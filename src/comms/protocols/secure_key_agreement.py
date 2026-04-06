from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List

from src.comms.channels.transports import ChannelDeliveryError, TransportChannel
from src.comms.entities.participant import Participant
from src.comms.events.logger import EventLogger
from src.comms.state.session import HandshakePhase, SessionState
from src.schemes.ml_kem import ml_kem_decaps, ml_kem_encaps, ml_kem_keygen


@dataclass
class HandshakeResult:
    """Result of a two-party secure key agreement handshake."""

    success: bool
    session_id: str
    selected_params: str
    channel_name: str
    client_state: SessionState
    server_state: SessionState
    client_application_key: bytes | None
    server_application_key: bytes | None
    events: List[Dict[str, Any]]


def _serialize_message(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _deserialize_message(payload: bytes) -> Dict[str, Any]:
    return json.loads(payload.decode("utf-8"))


def _transcript_hash(transcript: List[bytes]) -> bytes:
    h = hashlib.sha3_256()
    for frame in transcript:
        h.update(len(frame).to_bytes(4, byteorder="big", signed=False))
        h.update(frame)
    return h.digest()


def _derive_handshake_secret(shared_key: bytes, transcript_hash: bytes) -> bytes:
    return hashlib.sha3_256(b"libpqc|handshake|" + shared_key + transcript_hash).digest()


def _derive_application_key(handshake_secret: bytes) -> bytes:
    return hashlib.sha3_256(b"libpqc|application|" + handshake_secret).digest()


def _finished_mac(handshake_secret: bytes, role: str, transcript_hash: bytes) -> str:
    return hmac.new(
        handshake_secret,
        b"finished|" + role.encode("utf-8") + b"|" + transcript_hash,
        hashlib.sha3_256,
    ).hexdigest()


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


def perform_secure_key_agreement(
    channel: TransportChannel,
    params: str = "ML-KEM-768",
    client_id: str = "client",
    server_id: str = "server",
    client_nonce: bytes | None = None,
    server_nonce: bytes | None = None,
    server_aseed: bytes | str | None = None,
    server_zseed: bytes | str | None = None,
    encaps_message: bytes | None = None,
) -> HandshakeResult:
    """Run a TLS-like post-quantum two-party key agreement with ML-KEM."""

    logger = EventLogger()
    client = Participant(participant_id=client_id, role="client")
    server = Participant(participant_id=server_id, role="server")

    session_id = str(uuid.uuid4())
    client_state = SessionState(actor=client.participant_id, session_id=session_id)
    server_state = SessionState(actor=server.participant_id, session_id=session_id)
    client_state.selected_params = params
    server_state.selected_params = params

    transcript: List[bytes] = []

    logger.record("protocol_start", "system", client_state.phase.value, "handshake started", {"session_id": session_id, "channel": channel.name, "params": params})

    try:
        client_hello = {
            "type": "client_hello",
            "session_id": session_id,
            "supported_params": [params],
            "client_nonce": (client_nonce or b"client-nonce").hex(),
        }
        delivered_client_hello = _send_over_channel(
            channel,
            client.participant_id,
            server.participant_id,
            "client_hello",
            client_hello,
        )
        if delivered_client_hello.get("type") != "client_hello":
            raise ValueError("invalid client hello")
        transcript.append(_serialize_message(delivered_client_hello))
        client_state.transition(HandshakePhase.CLIENT_HELLO_SENT)
        server_state.transition(HandshakePhase.CLIENT_HELLO_SENT)
        logger.record("state_transition", client.participant_id, client_state.phase.value, "client hello sent")

        ek, dk = ml_kem_keygen(params, aseed=server_aseed, zseed=server_zseed)
        server_hello = {
            "type": "server_hello",
            "session_id": session_id,
            "selected_params": params,
            "server_nonce": (server_nonce or b"server-nonce").hex(),
            "encapsulation_key": ek.hex(),
        }
        delivered_server_hello = _send_over_channel(
            channel,
            server.participant_id,
            client.participant_id,
            "server_hello",
            server_hello,
        )
        if delivered_server_hello.get("type") != "server_hello":
            raise ValueError("invalid server hello")
        if delivered_server_hello.get("selected_params") != params:
            raise ValueError("server selected unexpected parameter set")

        transcript.append(_serialize_message(delivered_server_hello))
        client_state.transition(HandshakePhase.SERVER_HELLO_SENT)
        server_state.transition(HandshakePhase.SERVER_HELLO_SENT)
        logger.record("state_transition", server.participant_id, server_state.phase.value, "server hello sent")

        received_ek_hex = delivered_server_hello.get("encapsulation_key", "")
        if not isinstance(received_ek_hex, str):
            raise ValueError("server encapsulation key is malformed")

        client_shared_key, ciphertext = ml_kem_encaps(
            bytes.fromhex(received_ek_hex),
            params=params,
            message=encaps_message,
        )
        client_keyshare = {
            "type": "client_keyshare",
            "session_id": session_id,
            "ciphertext": ciphertext.hex(),
        }
        delivered_client_keyshare = _send_over_channel(
            channel,
            client.participant_id,
            server.participant_id,
            "client_keyshare",
            client_keyshare,
        )
        if delivered_client_keyshare.get("type") != "client_keyshare":
            raise ValueError("invalid client keyshare")

        transcript.append(_serialize_message(delivered_client_keyshare))
        client_state.transition(HandshakePhase.CLIENT_KEYSHARE_SENT)
        server_state.transition(HandshakePhase.CLIENT_KEYSHARE_SENT)
        logger.record("state_transition", client.participant_id, client_state.phase.value, "client keyshare sent")

        delivered_ciphertext_hex = delivered_client_keyshare.get("ciphertext", "")
        if not isinstance(delivered_ciphertext_hex, str):
            raise ValueError("ciphertext is malformed")
        server_shared_key = ml_kem_decaps(
            bytes.fromhex(delivered_ciphertext_hex),
            dk,
            params=params,
        )
        client_state.shared_key = client_shared_key
        server_state.shared_key = server_shared_key

        server_transcript_hash = _transcript_hash(transcript)
        server_handshake_secret = _derive_handshake_secret(
            server_shared_key, server_transcript_hash
        )
        server_finished = {
            "type": "server_finished",
            "session_id": session_id,
            "verify_data": _finished_mac(
                server_handshake_secret,
                role="server",
                transcript_hash=server_transcript_hash,
            ),
        }
        delivered_server_finished = _send_over_channel(
            channel,
            server.participant_id,
            client.participant_id,
            "server_finished",
            server_finished,
        )
        transcript.append(_serialize_message(delivered_server_finished))
        server_state.transition(HandshakePhase.SERVER_FINISHED_SENT)
        logger.record("state_transition", server.participant_id, server_state.phase.value, "server finished sent")

        client_transcript_hash = _transcript_hash(transcript[:-1])
        client_handshake_secret = _derive_handshake_secret(
            client_shared_key, client_transcript_hash
        )
        expected_server_verify = _finished_mac(
            client_handshake_secret,
            role="server",
            transcript_hash=client_transcript_hash,
        )
        if delivered_server_finished.get("verify_data") != expected_server_verify:
            raise ValueError("server finished verification failed")

        client_finished = {
            "type": "client_finished",
            "session_id": session_id,
            "verify_data": _finished_mac(
                client_handshake_secret,
                role="client",
                transcript_hash=_transcript_hash(transcript),
            ),
        }
        delivered_client_finished = _send_over_channel(
            channel,
            client.participant_id,
            server.participant_id,
            "client_finished",
            client_finished,
        )

        server_expected_client_verify = _finished_mac(
            server_handshake_secret,
            role="client",
            transcript_hash=_transcript_hash(transcript),
        )
        if delivered_client_finished.get("verify_data") != server_expected_client_verify:
            raise ValueError("client finished verification failed")

        transcript.append(_serialize_message(delivered_client_finished))
        client_state.transition(HandshakePhase.CLIENT_FINISHED_SENT)
        server_state.transition(HandshakePhase.CLIENT_FINISHED_SENT)

        client_state.application_key = _derive_application_key(client_handshake_secret)
        server_state.application_key = _derive_application_key(server_handshake_secret)

        client_state.transition(HandshakePhase.ESTABLISHED)
        server_state.transition(HandshakePhase.ESTABLISHED)
        logger.record("state_transition", "system", HandshakePhase.ESTABLISHED.value, "secure session established")

        return HandshakeResult(
            success=True,
            session_id=session_id,
            selected_params=params,
            channel_name=channel.name,
            client_state=client_state,
            server_state=server_state,
            client_application_key=client_state.application_key,
            server_application_key=server_state.application_key,
            events=logger.to_dicts(),
        )

    except (ValueError, KeyError, json.JSONDecodeError, ChannelDeliveryError) as exc:
        error_message = str(exc)
        client_state.fail(error_message)
        server_state.fail(error_message)
        logger.record(
            "protocol_error",
            "system",
            HandshakePhase.FAILED.value,
            "handshake failed",
            {"error": error_message},
        )
        return HandshakeResult(
            success=False,
            session_id=session_id,
            selected_params=params,
            channel_name=channel.name,
            client_state=client_state,
            server_state=server_state,
            client_application_key=None,
            server_application_key=None,
            events=logger.to_dicts(),
        )
