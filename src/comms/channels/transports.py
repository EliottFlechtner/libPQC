from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable


class ChannelDeliveryError(RuntimeError):
    """Raised when a channel drops or blocks a message."""


class TransportChannel:
    """Base transport contract for protocol simulation channels."""

    name = "transport"

    def transmit(self, sender: str, receiver: str, payload: bytes, stage: str) -> bytes:
        raise NotImplementedError


class PerfectChannel(TransportChannel):
    """Ideal channel: no message loss or tampering."""

    name = "perfect"

    def transmit(self, sender: str, receiver: str, payload: bytes, stage: str) -> bytes:
        return payload


class NoisyChannel(TransportChannel):
    """Channel that introduces random bit flips."""

    name = "noisy"

    def __init__(self, bit_error_rate: float = 0.01, seed: int | None = None) -> None:
        if bit_error_rate < 0.0 or bit_error_rate > 1.0:
            raise ValueError("bit_error_rate must be between 0 and 1")
        self.bit_error_rate = bit_error_rate
        self._rng = random.Random(seed)

    def transmit(self, sender: str, receiver: str, payload: bytes, stage: str) -> bytes:
        corrupted = bytearray(payload)
        for i, byte in enumerate(corrupted):
            if self._rng.random() < self.bit_error_rate:
                bit_index = self._rng.randrange(0, 8)
                corrupted[i] = byte ^ (1 << bit_index)
        return bytes(corrupted)


TamperFunction = Callable[[bytes, str, str, str], bytes]


@dataclass
class AdversarialChannel(TransportChannel):
    """Channel model that can drop, tamper with, and replay messages."""

    tamper_function: TamperFunction | None = None
    drop_stages: tuple[str, ...] = ()
    replay_last_on_stage: str | None = None

    name = "adversarial"

    def __post_init__(self) -> None:
        self._last_payload: bytes | None = None

    def transmit(self, sender: str, receiver: str, payload: bytes, stage: str) -> bytes:
        if stage in self.drop_stages:
            raise ChannelDeliveryError(f"message dropped at stage={stage}")

        outgoing = payload
        if self.tamper_function is not None:
            outgoing = self.tamper_function(payload, sender, receiver, stage)

        if self.replay_last_on_stage is not None and stage == self.replay_last_on_stage:
            if self._last_payload is not None:
                return self._last_payload

        self._last_payload = outgoing
        return outgoing


@dataclass
class ReorderingChannel(TransportChannel):
    """Channel that returns prior payloads out of order for selected stages."""

    reorder_on_stages: tuple[str, ...] = ()

    name = "reordering"

    def __post_init__(self) -> None:
        self._buffered_payload: bytes | None = None

    def transmit(self, sender: str, receiver: str, payload: bytes, stage: str) -> bytes:
        if stage not in self.reorder_on_stages:
            return payload

        if self._buffered_payload is None:
            self._buffered_payload = payload
            return payload

        outgoing = self._buffered_payload
        self._buffered_payload = payload
        return outgoing
