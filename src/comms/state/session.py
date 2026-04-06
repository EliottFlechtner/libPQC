from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class ProtocolState(Enum):
    INIT = "init"
    KEY_EXCHANGE = "key_exchange"
    AUTHENTICATED = "authenticated"
    ACTIVE = "active"
    FAILED = "failed"


class HandshakePhase(Enum):
    INIT = "init"
    CLIENT_HELLO_SENT = "client_hello_sent"
    SERVER_HELLO_SENT = "server_hello_sent"
    CLIENT_KEYSHARE_SENT = "client_keyshare_sent"
    AUTHENTICATED = "authenticated"
    SERVER_FINISHED_SENT = "server_finished_sent"
    CLIENT_FINISHED_SENT = "client_finished_sent"
    ESTABLISHED = "established"
    FAILED = "failed"


@dataclass
class SessionState:
    """Tracks the local protocol state for one participant."""

    actor: str
    phase: HandshakePhase = HandshakePhase.INIT
    protocol_state: ProtocolState = ProtocolState.INIT
    session_id: str = ""
    selected_params: str = ""
    shared_key: Optional[bytes] = None
    application_key: Optional[bytes] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def transition(self, next_phase: HandshakePhase) -> None:
        self.phase = next_phase
        self.protocol_state = _protocol_state_from_phase(next_phase)

    def fail(self, error_message: str) -> None:
        self.phase = HandshakePhase.FAILED
        self.protocol_state = ProtocolState.FAILED
        self.error = error_message


def _protocol_state_from_phase(phase: HandshakePhase) -> ProtocolState:
    if phase == HandshakePhase.INIT:
        return ProtocolState.INIT
    if phase in {
        HandshakePhase.CLIENT_HELLO_SENT,
        HandshakePhase.SERVER_HELLO_SENT,
        HandshakePhase.CLIENT_KEYSHARE_SENT,
        HandshakePhase.SERVER_FINISHED_SENT,
        HandshakePhase.CLIENT_FINISHED_SENT,
    }:
        return ProtocolState.KEY_EXCHANGE
    if phase == HandshakePhase.AUTHENTICATED:
        return ProtocolState.AUTHENTICATED
    if phase == HandshakePhase.ESTABLISHED:
        return ProtocolState.ACTIVE
    return ProtocolState.FAILED
