"""Post-quantum TLS handshake experiment helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha3_256
from time import perf_counter
from typing import Literal

from src.schemes.ml_dsa.keygen import ml_dsa_keygen
from src.schemes.ml_dsa.sign import ml_dsa_sign
from src.schemes.ml_dsa.verify import ml_dsa_verify
from src.schemes.ml_kem.decaps import ml_kem_decaps
from src.schemes.ml_kem.encaps import ml_kem_encaps
from src.schemes.ml_kem.keygen import ml_kem_keygen


TlsMode = Literal["pq-only", "hybrid"]
DEFAULT_TLS_MODES: tuple[TlsMode, ...] = ("pq-only", "hybrid")


@dataclass(frozen=True)
class TlsHandshakeRecord:
    mode: TlsMode
    kem_params: str
    dsa_params: str
    authenticate_server: bool
    runs: int
    handshake_successes: int
    handshake_failures: int
    shared_secret_match_rate: float
    mean_seconds: float
    min_seconds: float
    max_seconds: float
    client_hello_bytes: int
    server_hello_bytes: int
    certificate_verify_bytes: int
    finished_bytes: int
    estimated_total_bytes: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _derive_classical_shared_secret(seed_label: bytes) -> bytes:
    # Deterministic placeholder for a classical KEX output in the hybrid path.
    return sha3_256(b"classical-kex:" + seed_label).digest()


def _derive_hybrid_secret(pq_secret: bytes, classical_secret: bytes) -> bytes:
    return sha3_256(b"hybrid-tls:" + pq_secret + classical_secret).digest()


def _seed32(label: str, index: int) -> bytes:
    return sha3_256(f"{label}:{index}".encode("utf-8")).digest()


def simulate_post_quantum_tls_handshake(
    mode: TlsMode = "pq-only",
    kem_params: str = "ML-KEM-768",
    dsa_params: str = "ML-DSA-87",
    runs: int = 1,
    authenticate_server: bool = True,
) -> dict[str, object]:
    """Simulate a TLS-style handshake using PQ-only or hybrid key schedule."""

    if runs <= 0:
        raise ValueError("runs must be a positive integer")
    if mode not in DEFAULT_TLS_MODES:
        raise ValueError(f"unsupported TLS mode: {mode}")

    durations: list[float] = []
    successes = 0
    failures = 0
    shared_matches = 0

    for index in range(runs):
        start = perf_counter()

        ek, dk = ml_kem_keygen(
            kem_params,
            aseed=_seed32("tls-aseed", index),
            zseed=_seed32("tls-zseed", index),
        )
        message = _seed32("tls-client-hello", index)
        client_pq_secret, ciphertext = ml_kem_encaps(
            ek,
            params=kem_params,
            message=message,
        )
        server_pq_secret = ml_kem_decaps(ciphertext, dk, params=kem_params)

        if mode == "hybrid":
            classical_shared = _derive_classical_shared_secret(
                f"tls-hybrid-{index}".encode("utf-8")
            )
            client_secret = _derive_hybrid_secret(client_pq_secret, classical_shared)
            server_secret = _derive_hybrid_secret(server_pq_secret, classical_shared)
        else:
            client_secret = client_pq_secret
            server_secret = server_pq_secret

        authenticated = True
        certificate_verify_bytes = 0
        if authenticate_server:
            vk, sk = ml_dsa_keygen(
                dsa_params,
                aseed=_seed32("tls-dsa-aseed", index),
            )
            transcript = sha3_256(ciphertext + client_secret).digest()
            signature = ml_dsa_sign(
                transcript,
                sk,
                params=dsa_params,
                rnd=_seed32("tls-dsa-rnd", index),
            )
            authenticated = ml_dsa_verify(transcript, signature, vk, params=dsa_params)
            certificate_verify_bytes = len(vk) + len(signature)

        match = client_secret == server_secret
        shared_matches += 1 if match else 0
        if match and authenticated:
            successes += 1
        else:
            failures += 1
        durations.append(perf_counter() - start)

    record = TlsHandshakeRecord(
        mode=mode,
        kem_params=kem_params,
        dsa_params=dsa_params,
        authenticate_server=authenticate_server,
        runs=runs,
        handshake_successes=successes,
        handshake_failures=failures,
        shared_secret_match_rate=shared_matches / runs,
        mean_seconds=sum(durations) / runs,
        min_seconds=min(durations),
        max_seconds=max(durations),
        client_hello_bytes=1184,
        server_hello_bytes=1088 + len(ciphertext),
        certificate_verify_bytes=certificate_verify_bytes,
        finished_bytes=64,
        estimated_total_bytes=(
            1184 + 1088 + len(ciphertext) + certificate_verify_bytes + 64
        ),
    )
    return record.to_dict()
