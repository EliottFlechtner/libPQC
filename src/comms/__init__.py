"""Communication protocol simulation package."""

from .channels import (
    AdversarialChannel,
    ChannelDeliveryError,
    NoisyChannel,
    PerfectChannel,
    TransportChannel,
)
from .events import EventLogger, ProtocolEvent
from .protocols import (
    HandshakeResult,
    ProtocolRunSummary,
    perform_secure_key_agreement,
    run_key_agreement_batch,
)
from .state import HandshakePhase, ProtocolState, SessionState

__all__ = [
    "AdversarialChannel",
    "ChannelDeliveryError",
    "EventLogger",
    "HandshakePhase",
    "HandshakeResult",
    "ProtocolState",
    "ProtocolRunSummary",
    "NoisyChannel",
    "PerfectChannel",
    "ProtocolEvent",
    "SessionState",
    "TransportChannel",
    "perform_secure_key_agreement",
    "run_key_agreement_batch",
]
