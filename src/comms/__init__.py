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
    GroupHandshakeResult,
    GroupProtocolRunSummary,
    HandshakeResult,
    ProtocolRunSummary,
    perform_group_key_agreement,
    run_group_key_agreement_batch,
    perform_secure_key_agreement,
    run_key_agreement_batch,
)
from .state import HandshakePhase, ProtocolState, SessionState

__all__ = [
    "AdversarialChannel",
    "ChannelDeliveryError",
    "EventLogger",
    "GroupHandshakeResult",
    "GroupProtocolRunSummary",
    "HandshakePhase",
    "HandshakeResult",
    "ProtocolState",
    "ProtocolRunSummary",
    "NoisyChannel",
    "PerfectChannel",
    "ProtocolEvent",
    "SessionState",
    "TransportChannel",
    "perform_group_key_agreement",
    "perform_secure_key_agreement",
    "run_group_key_agreement_batch",
    "run_key_agreement_batch",
]
