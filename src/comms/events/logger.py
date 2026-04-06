from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


@dataclass(frozen=True)
class ProtocolEvent:
    """Structured event emitted by the communication protocol."""

    event_type: str
    actor: str
    state: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class EventLogger:
    """Collects protocol events in execution order."""

    def __init__(self) -> None:
        self._events: List[ProtocolEvent] = []

    def record(
        self,
        event_type: str,
        actor: str,
        state: str,
        message: str,
        details: Dict[str, Any] | None = None,
    ) -> ProtocolEvent:
        event = ProtocolEvent(
            event_type=event_type,
            actor=actor,
            state=state,
            message=message,
            details=details or {},
        )
        self._events.append(event)
        return event

    @property
    def events(self) -> List[ProtocolEvent]:
        return list(self._events)

    def to_dicts(self) -> List[Dict[str, Any]]:
        return [
            {
                "event_type": event.event_type,
                "actor": event.actor,
                "state": event.state,
                "message": event.message,
                "details": event.details,
                "timestamp": event.timestamp,
            }
            for event in self._events
        ]
