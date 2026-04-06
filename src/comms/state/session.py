from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


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
    session_id: str = ""
    selected_params: str = ""
    shared_key: Optional[bytes] = None
    application_key: Optional[bytes] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def transition(self, next_phase: HandshakePhase) -> None:
        self.phase = next_phase

    def fail(self, error_message: str) -> None:
        self.phase = HandshakePhase.FAILED
        self.error = error_message
