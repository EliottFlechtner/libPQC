from __future__ import annotations

import hashlib
import json
import hmac
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List

from src.comms.channels import ChannelDeliveryError, TransportChannel
from src.comms.events import EventLogger
from src.comms.state import HandshakePhase, SessionState
from src.schemes.ml_kem import ml_kem_decaps, ml_kem_encaps, ml_kem_keygen


def _serialize_message(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _deserialize_message(payload: bytes) -> Dict[str, Any]:
    return json.loads(payload.decode("utf-8"))


def _send_over_channel(
    channel: TransportChannel,
    sender: str,
    receiver: str,
    stage: str,
    message: Dict[str, Any],
) -> Dict[str, Any]:
    wire = _serialize_message(message)
    delivered = channel.transmit(sender, receiver, wire, stage)
    return _deserialize_message(delivered)


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("xor input lengths must match")
    return bytes(a ^ b for a, b in zip(left, right))


def _derive_member_seed(
    seed_prefix: bytes | str | None, member_id: str
) -> bytes | str | None:
    if seed_prefix is None:
        return None
    if isinstance(seed_prefix, bytes):
        digest = hashlib.sha3_256(
            seed_prefix + b"|" + member_id.encode("utf-8")
        ).digest()
        return digest[:32]
    digest = hashlib.sha3_256(f"{seed_prefix}|{member_id}".encode("utf-8")).digest()
    return digest[:32]


def _derive_final_group_key(
    group_seed: bytes, session_id: str, member_ids: List[str]
) -> bytes:
    payload = (
        b"libpqc|group|"
        + session_id.encode("utf-8")
        + b"|"
        + "|".join(member_ids).encode("utf-8")
        + b"|"
        + group_seed
    )
    return hashlib.sha3_256(payload).digest()


@dataclass
class GroupHandshakeResult:
    success: bool
    session_id: str
    selected_params: str
    channel_name: str
    coordinator_id: str
    member_ids: List[str]
    coordinator_state: SessionState
    member_states: Dict[str, SessionState]
    coordinator_group_key: bytes | None
    member_group_keys: Dict[str, bytes]
    events: List[Dict[str, Any]]
    transcript: List[Dict[str, Any]]


@dataclass(frozen=True)
class BroadcastRecord:
    member_id: str
    message: str
    tag_hex: str


@dataclass(frozen=True)
class BroadcastResult:
    success: bool
    session_id: str
    coordinator_id: str
    label: str
    message: str
    records: List[BroadcastRecord]
    transcript_hash_hex: str


@dataclass(frozen=True)
class TranscriptReplayResult:
    valid: bool
    session_id: str
    transcript_hash_hex: str
    message_count: int


@dataclass(frozen=True)
class GroupRekeyResult:
    success: bool
    previous_session_id: str
    new_session_id: str
    member_ids: List[str]
    rekeyed_result: GroupHandshakeResult


def perform_group_key_agreement(
    channel: TransportChannel,
    member_ids: List[str],
    params: str = "ML-KEM-768",
    coordinator_id: str = "coordinator",
    group_seed: bytes | None = None,
    member_seed_prefix: bytes | str | None = None,
) -> GroupHandshakeResult:
    """Run a server-mediated ML-KEM group key agreement for 3+ parties."""

    if len(member_ids) < 2:
        raise ValueError("member_ids must include at least two members")

    normalized_members = []
    for member_id in member_ids:
        clean_id = str(member_id).strip()
        if not clean_id:
            raise ValueError("member_ids must not contain empty identifiers")
        normalized_members.append(clean_id)

    if len(set(normalized_members)) != len(normalized_members):
        raise ValueError("member_ids must be unique")

    logger = EventLogger()
    session_id = str(uuid.uuid4())
    transcript: List[Dict[str, Any]] = []

    coordinator_state = SessionState(actor=coordinator_id, session_id=session_id)
    coordinator_state.selected_params = params

    member_states: Dict[str, SessionState] = {
        member_id: SessionState(actor=member_id, session_id=session_id)
        for member_id in normalized_members
    }
    for state in member_states.values():
        state.selected_params = params

    logger.record(
        "protocol_start",
        "system",
        coordinator_state.phase.value,
        "group key agreement started",
        {
            "session_id": session_id,
            "channel": channel.name,
            "coordinator_id": coordinator_id,
            "member_count": len(normalized_members),
            "params": params,
        },
    )

    try:
        group_seed_value = (
            group_seed
            or hashlib.sha3_256(b"group-seed|" + session_id.encode("utf-8")).digest()
        )
        if len(group_seed_value) != 32:
            raise ValueError("group_seed must be exactly 32 bytes")

        coordinator_state.transition(HandshakePhase.CLIENT_HELLO_SENT)

        pairwise: Dict[str, Dict[str, bytes]] = {}
        member_group_keys: Dict[str, bytes] = {}

        for member_id in normalized_members:
            member_state = member_states[member_id]
            member_state.transition(HandshakePhase.CLIENT_HELLO_SENT)

            join_ek, join_dk = ml_kem_keygen(
                params,
                aseed=_derive_member_seed(member_seed_prefix, member_id),
            )
            join_message = {
                "type": "member_join",
                "session_id": session_id,
                "member_id": member_id,
                "encapsulation_key": join_ek.hex(),
            }
            delivered_join = _send_over_channel(
                channel,
                member_id,
                coordinator_id,
                f"group_join_{member_id}",
                join_message,
            )
            transcript.append(
                {
                    "stage": f"group_join_{member_id}",
                    "sent": join_message,
                    "delivered": delivered_join,
                }
            )
            if delivered_join.get("type") != "member_join":
                raise ValueError(f"invalid join message for {member_id}")

            ek_hex = delivered_join.get("encapsulation_key", "")
            if not isinstance(ek_hex, str):
                raise ValueError(
                    f"join payload missing encapsulation key for {member_id}"
                )

            coordinator_pairwise_key, ciphertext = ml_kem_encaps(
                bytes.fromhex(ek_hex),
                params=params,
            )

            wrapped_group_seed = _xor_bytes(group_seed_value, coordinator_pairwise_key)
            distribute_message = {
                "type": "group_distribute",
                "session_id": session_id,
                "member_id": member_id,
                "ciphertext": ciphertext.hex(),
                "wrapped_group_seed": wrapped_group_seed.hex(),
            }
            delivered_distribution = _send_over_channel(
                channel,
                coordinator_id,
                member_id,
                f"group_distribute_{member_id}",
                distribute_message,
            )
            transcript.append(
                {
                    "stage": f"group_distribute_{member_id}",
                    "sent": distribute_message,
                    "delivered": delivered_distribution,
                }
            )
            if delivered_distribution.get("type") != "group_distribute":
                raise ValueError(f"invalid group distribution for {member_id}")

            ciphertext_hex = delivered_distribution.get("ciphertext", "")
            wrapped_hex = delivered_distribution.get("wrapped_group_seed", "")
            if not isinstance(ciphertext_hex, str) or not isinstance(wrapped_hex, str):
                raise ValueError(f"distribution payload malformed for {member_id}")

            member_pairwise_key = ml_kem_decaps(
                bytes.fromhex(ciphertext_hex),
                join_dk,
                params=params,
            )
            recovered_group_seed = _xor_bytes(
                bytes.fromhex(wrapped_hex),
                member_pairwise_key,
            )
            if recovered_group_seed != group_seed_value:
                raise ValueError(f"group key recovery failed for {member_id}")

            member_state.shared_key = member_pairwise_key
            member_state.transition(HandshakePhase.CLIENT_KEYSHARE_SENT)

            pairwise[member_id] = {
                "coordinator_pairwise_key": coordinator_pairwise_key,
                "member_pairwise_key": member_pairwise_key,
            }

            logger.record(
                "member_joined",
                member_id,
                member_state.phase.value,
                "member pairwise channel established",
                {"member_id": member_id},
            )

        coordinator_state.transition(HandshakePhase.AUTHENTICATED)
        for member_state in member_states.values():
            member_state.transition(HandshakePhase.AUTHENTICATED)

        final_group_key = _derive_final_group_key(
            group_seed_value,
            session_id=session_id,
            member_ids=normalized_members,
        )

        coordinator_state.application_key = final_group_key
        coordinator_state.transition(HandshakePhase.ESTABLISHED)

        for member_id, member_state in member_states.items():
            member_state.application_key = final_group_key
            member_state.transition(HandshakePhase.ESTABLISHED)
            member_group_keys[member_id] = final_group_key

        logger.record(
            "state_transition",
            coordinator_id,
            coordinator_state.phase.value,
            "group session active",
            {"member_count": len(normalized_members)},
        )

        return GroupHandshakeResult(
            success=True,
            session_id=session_id,
            selected_params=params,
            channel_name=channel.name,
            coordinator_id=coordinator_id,
            member_ids=normalized_members,
            coordinator_state=coordinator_state,
            member_states=member_states,
            coordinator_group_key=final_group_key,
            member_group_keys=member_group_keys,
            events=logger.to_dicts(),
            transcript=transcript,
        )

    except (ValueError, KeyError, json.JSONDecodeError, ChannelDeliveryError) as exc:
        error_message = str(exc)
        coordinator_state.fail(error_message)
        for member_state in member_states.values():
            member_state.fail(error_message)
        logger.record(
            "protocol_error",
            "system",
            HandshakePhase.FAILED.value,
            "group handshake failed",
            {"error": error_message},
        )
        return GroupHandshakeResult(
            success=False,
            session_id=session_id,
            selected_params=params,
            channel_name=channel.name,
            coordinator_id=coordinator_id,
            member_ids=normalized_members,
            coordinator_state=coordinator_state,
            member_states=member_states,
            coordinator_group_key=None,
            member_group_keys={},
            events=logger.to_dicts(),
            transcript=transcript,
        )


def export_group_transcript(result: GroupHandshakeResult) -> Dict[str, Any]:
    if result.coordinator_group_key is None:
        raise ValueError(
            "group transcript can only be exported for successful sessions"
        )

    return {
        "session_id": result.session_id,
        "params": result.selected_params,
        "channel": result.channel_name,
        "coordinator_id": result.coordinator_id,
        "member_ids": result.member_ids,
        "transcript": result.transcript,
        "events": result.events,
        "group_key_hex": result.coordinator_group_key.hex(),
    }


def replay_group_transcript(document: Dict[str, Any]) -> TranscriptReplayResult:
    session_id = document.get("session_id")
    transcript = document.get("transcript")
    if not isinstance(session_id, str):
        raise ValueError("transcript document missing session_id")
    if not isinstance(transcript, list):
        raise ValueError("transcript document missing transcript")

    serialized = json.dumps(transcript, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    transcript_hash = hashlib.sha3_256(serialized).hexdigest()
    return TranscriptReplayResult(
        valid=True,
        session_id=session_id,
        transcript_hash_hex=transcript_hash,
        message_count=len(transcript),
    )


def broadcast_group_message(
    result: GroupHandshakeResult,
    message: bytes | str,
    label: str = "broadcast",
) -> BroadcastResult:
    if result.coordinator_group_key is None:
        raise ValueError("broadcast requires an established group session")
    if isinstance(message, bytes):
        message_text = message.decode("utf-8", errors="replace")
        message_bytes = message
    elif isinstance(message, str):
        message_text = message
        message_bytes = message.encode("utf-8")
    else:
        raise TypeError("message must be bytes-like or a string")

    transcript_hash = hashlib.sha3_256(
        json.dumps(result.transcript, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).digest()
    records: List[BroadcastRecord] = []
    for member_id in result.member_ids:
        tag = hmac.new(
            result.coordinator_group_key,
            b"broadcast|"
            + label.encode("utf-8")
            + b"|"
            + member_id.encode("utf-8")
            + b"|"
            + transcript_hash
            + b"|"
            + message_bytes,
            hashlib.sha3_256,
        ).hexdigest()
        records.append(
            BroadcastRecord(member_id=member_id, message=message_text, tag_hex=tag)
        )

    return BroadcastResult(
        success=True,
        session_id=result.session_id,
        coordinator_id=result.coordinator_id,
        label=label,
        message=message_text,
        records=records,
        transcript_hash_hex=transcript_hash.hex(),
    )


def rekey_group_membership(
    result: GroupHandshakeResult,
    channel: TransportChannel | None = None,
    add_members: List[str] | None = None,
    remove_members: List[str] | None = None,
    member_seed_prefix: bytes | str | None = None,
) -> GroupRekeyResult:
    if result.coordinator_group_key is None:
        raise ValueError("rekey requires an established group session")

    active_channel: TransportChannel
    if channel is None:
        from src.comms.channels import PerfectChannel

        active_channel = PerfectChannel()
    else:
        active_channel = channel

    next_members = [member_id for member_id in result.member_ids if True]
    if remove_members:
        remove_set = {str(member_id).strip() for member_id in remove_members}
        next_members = [
            member_id for member_id in next_members if member_id not in remove_set
        ]
    if add_members:
        for member_id in add_members:
            clean_id = str(member_id).strip()
            if not clean_id:
                raise ValueError("added members must not be empty")
            if clean_id not in next_members:
                next_members.append(clean_id)

    if len(next_members) < 2:
        raise ValueError("rekey must leave at least two members")

    rekey_seed = hashlib.sha3_256(
        b"rekey|"
        + result.coordinator_group_key
        + b"|"
        + "|".join(next_members).encode("utf-8")
    ).digest()
    rekeyed_result = perform_group_key_agreement(
        channel=active_channel,
        member_ids=next_members,
        params=result.selected_params,
        coordinator_id=result.coordinator_id,
        group_seed=rekey_seed,
        member_seed_prefix=member_seed_prefix,
    )
    return GroupRekeyResult(
        success=rekeyed_result.success,
        previous_session_id=result.session_id,
        new_session_id=rekeyed_result.session_id,
        member_ids=next_members,
        rekeyed_result=rekeyed_result,
    )


def replay_group_broadcast(
    result: GroupHandshakeResult, broadcast: BroadcastResult
) -> bool:
    if result.coordinator_group_key is None:
        return False
    if broadcast.session_id != result.session_id:
        return False

    transcript_hash = hashlib.sha3_256(
        json.dumps(result.transcript, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).digest()
    for record in broadcast.records:
        expected_tag = hmac.new(
            result.coordinator_group_key,
            b"broadcast|"
            + broadcast.label.encode("utf-8")
            + b"|"
            + record.member_id.encode("utf-8")
            + b"|"
            + transcript_hash
            + b"|"
            + record.message.encode("utf-8"),
            hashlib.sha3_256,
        ).hexdigest()
        if record.tag_hex != expected_tag:
            return False
    return True


__all__ = [
    "BroadcastRecord",
    "BroadcastResult",
    "GroupHandshakeResult",
    "GroupRekeyResult",
    "TranscriptReplayResult",
    "broadcast_group_message",
    "export_group_transcript",
    "perform_group_key_agreement",
    "rekey_group_membership",
    "replay_group_broadcast",
    "replay_group_transcript",
]
