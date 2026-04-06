from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from src.comms.channels import AdversarialChannel, NoisyChannel, PerfectChannel
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
    application_keys_match: bool
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
                "application_keys_match": summary.application_keys_match,
                "error": summary.error,
                "events": summary.events,
            }
            for summary in summaries
        ],
    }
