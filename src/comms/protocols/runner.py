from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from src.comms.channels import AdversarialChannel, NoisyChannel, PerfectChannel
from src.comms.protocols.group_key_agreement import (
    GroupHandshakeResult,
    perform_group_key_agreement,
)
from src.comms.protocols.secure_key_agreement import (
    HandshakeResult,
    perform_secure_key_agreement,
)


def _default_tamper(payload: bytes, sender: str, receiver: str, stage: str) -> bytes:
    if stage != "client_keyshare" or not payload:
        return payload
    modified = bytearray(payload)
    modified[-1] ^= 0x01
    return bytes(modified)


def build_channel(
    channel_name: str,
    noisy_bit_error_rate: float = 0.01,
    seed: int | None = None,
):
    """Construct a channel model by name."""
    if channel_name == "perfect":
        return PerfectChannel()
    if channel_name == "noisy":
        return NoisyChannel(bit_error_rate=noisy_bit_error_rate, seed=seed)
    if channel_name == "adversarial":
        return AdversarialChannel(tamper_function=_default_tamper)
    raise ValueError(f"unsupported channel: {channel_name}")


@dataclass(frozen=True)
class ProtocolRunSummary:
    run_index: int
    success: bool
    session_id: str
    channel: str
    kem_params: str
    authenticate_server: bool
    client_phase: str
    server_phase: str
    client_protocol_state: str
    server_protocol_state: str
    application_keys_match: bool
    error: str | None
    events: List[Dict[str, Any]]


@dataclass(frozen=True)
class GroupProtocolRunSummary:
    run_index: int
    success: bool
    session_id: str
    channel: str
    kem_params: str
    member_count: int
    coordinator_protocol_state: str
    member_protocol_states: Dict[str, str]
    group_key_consensus: bool
    error: str | None
    events: List[Dict[str, Any]]


def run_key_agreement_batch(
    runs: int,
    channel_name: str,
    kem_params: str = "ML-KEM-768",
    authenticate_server: bool = False,
    dsa_params: str = "ML-DSA-87",
    noisy_bit_error_rate: float = 0.01,
    seed: int | None = None,
    server_aseed: bytes | str | None = None,
    server_zseed: bytes | str | None = None,
    server_dsa_aseed: bytes | str | None = None,
    server_signing_rnd: bytes | str | None = None,
    encaps_message: bytes | None = None,
    include_events: bool = False,
) -> Dict[str, Any]:
    """Run repeated secure key agreement simulations and summarize outcomes."""
    if runs <= 0:
        raise ValueError("runs must be positive")

    summaries: List[ProtocolRunSummary] = []

    for run_index in range(1, runs + 1):
        run_seed = None if seed is None else seed + run_index - 1
        channel = build_channel(
            channel_name,
            noisy_bit_error_rate=noisy_bit_error_rate,
            seed=run_seed,
        )

        result: HandshakeResult = perform_secure_key_agreement(
            channel=channel,
            params=kem_params,
            server_aseed=server_aseed,
            server_zseed=server_zseed,
            encaps_message=encaps_message,
            authenticate_server=authenticate_server,
            dsa_params=dsa_params,
            server_dsa_aseed=server_dsa_aseed,
            server_signing_rnd=server_signing_rnd,
        )

        summaries.append(
            ProtocolRunSummary(
                run_index=run_index,
                success=result.success,
                session_id=result.session_id,
                channel=result.channel_name,
                kem_params=result.selected_params,
                authenticate_server=authenticate_server,
                client_phase=result.client_state.phase.value,
                server_phase=result.server_state.phase.value,
                client_protocol_state=result.client_state.protocol_state.value,
                server_protocol_state=result.server_state.protocol_state.value,
                application_keys_match=(
                    result.client_application_key is not None
                    and result.server_application_key is not None
                    and result.client_application_key == result.server_application_key
                ),
                error=result.client_state.error,
                events=result.events if include_events else [],
            )
        )

    successes = sum(1 for summary in summaries if summary.success)
    failures = runs - successes

    return {
        "runs": runs,
        "channel": channel_name,
        "kem_params": kem_params,
        "authenticate_server": authenticate_server,
        "dsa_params": dsa_params if authenticate_server else None,
        "successes": successes,
        "failures": failures,
        "results": [
            {
                "run_index": summary.run_index,
                "success": summary.success,
                "session_id": summary.session_id,
                "channel": summary.channel,
                "kem_params": summary.kem_params,
                "authenticate_server": summary.authenticate_server,
                "client_phase": summary.client_phase,
                "server_phase": summary.server_phase,
                "client_protocol_state": summary.client_protocol_state,
                "server_protocol_state": summary.server_protocol_state,
                "application_keys_match": summary.application_keys_match,
                "error": summary.error,
                "events": summary.events,
            }
            for summary in summaries
        ],
    }


def run_group_key_agreement_batch(
    runs: int,
    channel_name: str,
    member_ids: List[str],
    kem_params: str = "ML-KEM-768",
    noisy_bit_error_rate: float = 0.01,
    seed: int | None = None,
    group_seed: bytes | None = None,
    member_seed_prefix: bytes | str | None = None,
    include_events: bool = False,
) -> Dict[str, Any]:
    """Run repeated multi-entity group key agreement simulations."""
    if runs <= 0:
        raise ValueError("runs must be positive")

    summaries: List[GroupProtocolRunSummary] = []

    for run_index in range(1, runs + 1):
        run_seed = None if seed is None else seed + run_index - 1
        channel = build_channel(
            channel_name,
            noisy_bit_error_rate=noisy_bit_error_rate,
            seed=run_seed,
        )

        result: GroupHandshakeResult = perform_group_key_agreement(
            channel=channel,
            member_ids=member_ids,
            params=kem_params,
            group_seed=group_seed,
            member_seed_prefix=member_seed_prefix,
        )

        member_key_values = list(result.member_group_keys.values())
        group_key_consensus = (
            result.success
            and result.coordinator_group_key is not None
            and len(member_key_values) == len(member_ids)
            and all(member_key == result.coordinator_group_key for member_key in member_key_values)
        )

        summaries.append(
            GroupProtocolRunSummary(
                run_index=run_index,
                success=result.success,
                session_id=result.session_id,
                channel=result.channel_name,
                kem_params=result.selected_params,
                member_count=len(result.member_ids),
                coordinator_protocol_state=result.coordinator_state.protocol_state.value,
                member_protocol_states={
                    member_id: state.protocol_state.value
                    for member_id, state in result.member_states.items()
                },
                group_key_consensus=group_key_consensus,
                error=result.coordinator_state.error,
                events=result.events if include_events else [],
            )
        )

    successes = sum(1 for summary in summaries if summary.success)
    failures = runs - successes

    return {
        "runs": runs,
        "channel": channel_name,
        "kem_params": kem_params,
        "member_count": len(member_ids),
        "successes": successes,
        "failures": failures,
        "results": [
            {
                "run_index": summary.run_index,
                "success": summary.success,
                "session_id": summary.session_id,
                "channel": summary.channel,
                "kem_params": summary.kem_params,
                "member_count": summary.member_count,
                "coordinator_protocol_state": summary.coordinator_protocol_state,
                "member_protocol_states": summary.member_protocol_states,
                "group_key_consensus": summary.group_key_consensus,
                "error": summary.error,
                "events": summary.events,
            }
            for summary in summaries
        ],
    }
