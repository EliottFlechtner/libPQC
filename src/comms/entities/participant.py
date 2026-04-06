from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Participant:
    """Represents a protocol participant in simulations."""

    participant_id: str
    role: str
