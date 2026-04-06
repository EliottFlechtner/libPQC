"""Communication protocol simulation package."""

from .channels import (
    AdversarialChannel,
    ChannelDeliveryError,
    NoisyChannel,
    PerfectChannel,
    TransportChannel,
)
from .events import EventLogger, ProtocolEvent
from .protocols import HandshakeResult, perform_secure_key_agreement
from .state import HandshakePhase, SessionState

__all__ = [
    "AdversarialChannel",
    "ChannelDeliveryError",
    "EventLogger",
    "HandshakePhase",
    "HandshakeResult",
    "NoisyChannel",
    "PerfectChannel",
    "ProtocolEvent",
    "SessionState",
    "TransportChannel",
    "perform_secure_key_agreement",
]
