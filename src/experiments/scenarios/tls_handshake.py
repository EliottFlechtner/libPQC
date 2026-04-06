"""Post-quantum TLS handshake experiment helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha3_256
from time import perf_counter
from typing import Literal, Sequence, cast

from src.schemes.ml_dsa.keygen import ml_dsa_keygen
from src.schemes.ml_dsa.sign import ml_dsa_sign
from src.schemes.ml_dsa.verify import ml_dsa_verify
from src.schemes.ml_kem.decaps import ml_kem_decaps
from src.schemes.ml_kem.encaps import ml_kem_encaps
from src.schemes.ml_kem.keygen import ml_kem_keygen


TlsMode = Literal["pq-only", "hybrid"]
DEFAULT_TLS_MODES: tuple[TlsMode, ...] = ("pq-only", "hybrid")
DEFAULT_TLS_DRAFT = "ietf-pqtls-00"
DEFAULT_TLS_CIPHERSUITE = "TLS13-IETF-PQT-MLKEM768-MLDSA87-SHA384"


TLS_DRAFT_POLICIES: dict[str, dict[str, object]] = {
    "ietf-pqtls-00": {
        "status": "deprecated",
        "replaced_by": "ietf-pqtls-01",
        "summary": "Legacy interop draft retained for compatibility checks.",
    },
    "ietf-pqtls-01": {
        "status": "current",
        "replaced_by": "ietf-pqtls-01",
        "summary": "Current draft profile with the recommended TLS policy.",
    },
}


TLS_CIPHERSUITE_PROFILES: dict[str, dict[str, object]] = {
    "TLS13-IETF-PQT-MLKEM512-MLDSA44-SHA256": {
        "kem_params": "ML-KEM-512",
        "dsa_params": "ML-DSA-44",
        "hash": "SHA256",
        "modes": ("pq-only", "hybrid"),
        "drafts": ("ietf-pqtls-00", "ietf-pqtls-01"),
        "draft_history": {
            "ietf-pqtls-00": "Initial PQ TLS draft 00 profile for ML-KEM-512 and ML-DSA-44.",
            "ietf-pqtls-01": "Current PQ TLS draft 01 profile retaining the same parameter binding.",
        },
    },
    "TLS13-IETF-PQT-MLKEM768-MLDSA87-SHA384": {
        "kem_params": "ML-KEM-768",
        "dsa_params": "ML-DSA-87",
        "hash": "SHA384",
        "modes": ("pq-only", "hybrid"),
        "drafts": ("ietf-pqtls-00", "ietf-pqtls-01"),
        "draft_history": {
            "ietf-pqtls-00": "Initial PQ TLS draft 00 profile for ML-KEM-768 and ML-DSA-87.",
            "ietf-pqtls-01": "Current PQ TLS draft 01 profile retaining the same parameter binding.",
        },
    },
    "TLS13-IETF-PQT-MLKEM1024-MLDSA87-SHA384": {
        "kem_params": "ML-KEM-1024",
        "dsa_params": "ML-DSA-87",
        "hash": "SHA384",
        "modes": ("pq-only",),
        "drafts": ("ietf-pqtls-01",),
        "draft_history": {
            "ietf-pqtls-01": "Draft 01-only profile for ML-KEM-1024 and ML-DSA-87.",
        },
    },
}


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
    flight_count: int
    transcript_hash_hex: str
    flight_trace: list[dict[str, object]]
    semantic_bindings: list[str]
    ciphersuite: str
    draft: str
    compatibility: dict[str, object]
    draft_policy: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _derive_classical_shared_secret(seed_label: bytes) -> bytes:
    # Deterministic placeholder for a classical KEX output in the hybrid path.
    return sha3_256(b"classical-kex:" + seed_label).digest()


def _derive_hybrid_secret(pq_secret: bytes, classical_secret: bytes) -> bytes:
    return sha3_256(b"hybrid-tls:" + pq_secret + classical_secret).digest()


def _seed32(label: str, index: int) -> bytes:
    return sha3_256(f"{label}:{index}".encode("utf-8")).digest()


def _check_ciphersuite_compatibility(
    ciphersuite: str,
    draft: str,
    mode: TlsMode,
    kem_params: str,
    dsa_params: str,
) -> dict[str, object]:
    profile = cast(dict[str, object] | None, TLS_CIPHERSUITE_PROFILES.get(ciphersuite))
    issues: list[str] = []
    warnings: list[str] = []
    if profile is None:
        warnings.append("unknown ciphersuite profile")
        return {
            "known_ciphersuite": False,
            "compatible": False,
            "issues": ["unsupported ciphersuite"],
            "warnings": warnings,
            "profile": None,
        }

    if str(profile["kem_params"]) != kem_params:
        issues.append(
            f"kem mismatch: expected {profile['kem_params']}, got {kem_params}"
        )
    if str(profile["dsa_params"]) != dsa_params:
        issues.append(
            f"dsa mismatch: expected {profile['dsa_params']}, got {dsa_params}"
        )
    modes = cast(tuple[TlsMode, ...], profile["modes"])
    drafts = cast(tuple[str, ...], profile["drafts"])
    draft_history = cast(dict[str, str], profile["draft_history"])
    if mode not in modes:
        issues.append(f"mode {mode} is not allowed for ciphersuite {ciphersuite}")
    if draft not in drafts:
        issues.append(f"draft {draft} not listed for ciphersuite {ciphersuite}")

    return {
        "known_ciphersuite": True,
        "compatible": len(issues) == 0,
        "issues": issues,
        "warnings": warnings,
        "profile": {
            "kem_params": profile["kem_params"],
            "dsa_params": profile["dsa_params"],
            "hash": profile["hash"],
            "modes": list(modes),
            "drafts": list(drafts),
            "draft_history": dict(draft_history),
        },
    }


def _check_draft_policy(draft: str, enforce_draft_policy: bool) -> dict[str, object]:
    policy = TLS_DRAFT_POLICIES.get(draft)
    if policy is None:
        return {
            "known_draft": False,
            "status": "unknown",
            "recommended_draft": DEFAULT_TLS_DRAFT,
            "enforced": enforce_draft_policy,
            "issues": [f"unsupported TLS draft: {draft}"],
            "warnings": ["unknown draft policy"],
            "summary": "Draft policy metadata unavailable.",
        }

    issues: list[str] = []
    warnings: list[str] = [str(policy["summary"])]
    status = str(policy["status"])
    recommended_draft = str(policy["replaced_by"])
    if status == "deprecated":
        warnings.append(f"draft {draft} is deprecated; prefer {recommended_draft}")
        if enforce_draft_policy:
            issues.append(
                f"draft {draft} is deprecated by policy; prefer {recommended_draft}"
            )

    return {
        "known_draft": True,
        "status": status,
        "recommended_draft": recommended_draft,
        "enforced": enforce_draft_policy,
        "issues": issues,
        "warnings": warnings,
        "summary": str(policy["summary"]),
    }


def _select_ciphersuite_for_context(
    mode: TlsMode,
    kem_params: str,
    dsa_params: str,
    draft: str,
) -> str:
    for ciphersuite, profile in TLS_CIPHERSUITE_PROFILES.items():
        if (
            str(profile["kem_params"]) == kem_params
            and str(profile["dsa_params"]) == dsa_params
            and mode in cast(tuple[TlsMode, ...], profile["modes"])
            and draft in cast(tuple[str, ...], profile["drafts"])
        ):
            return ciphersuite
    return DEFAULT_TLS_CIPHERSUITE


def _append_flight(
    trace: list[dict[str, object]],
    transcript_hash: bytes,
    *,
    flight_number: int,
    sender: str,
    message_type: str,
    payload: bytes,
    semantics: Sequence[str],
) -> bytes:
    payload_hash = sha3_256(payload).digest()
    semantics_blob = "|".join(semantics).encode("utf-8")
    next_hash = sha3_256(
        transcript_hash
        + f"{flight_number}:{sender}:{message_type}".encode("utf-8")
        + semantics_blob
        + payload_hash
    ).digest()
    trace.append(
        {
            "flight_number": flight_number,
            "sender": sender,
            "message_type": message_type,
            "payload_bytes": len(payload),
            "payload_hash_hex": payload_hash.hex(),
            "transcript_hash_hex": next_hash.hex(),
            "semantics": list(semantics),
        }
    )
    return next_hash


def simulate_post_quantum_tls_handshake(
    mode: TlsMode = "pq-only",
    kem_params: str = "ML-KEM-768",
    dsa_params: str = "ML-DSA-87",
    runs: int = 1,
    authenticate_server: bool = True,
    ciphersuite: str | None = None,
    draft: str = DEFAULT_TLS_DRAFT,
    enforce_compatibility: bool = True,
    enforce_draft_policy: bool = False,
) -> dict[str, object]:
    """Simulate a TLS-style handshake using PQ-only or hybrid key schedule."""

    if runs <= 0:
        raise ValueError("runs must be a positive integer")
    if mode not in DEFAULT_TLS_MODES:
        raise ValueError(f"unsupported TLS mode: {mode}")
    selected_ciphersuite = (
        ciphersuite
        if ciphersuite is not None
        else _select_ciphersuite_for_context(mode, kem_params, dsa_params, draft)
    )
    compatibility = _check_ciphersuite_compatibility(
        selected_ciphersuite,
        draft,
        mode,
        kem_params,
        dsa_params,
    )
    draft_policy = _check_draft_policy(draft, enforce_draft_policy)
    if enforce_compatibility and not bool(compatibility["compatible"]):
        raise ValueError(
            "incompatible TLS configuration: "
            + "; ".join(
                str(issue) for issue in cast(list[object], compatibility["issues"])
            )
        )
    if enforce_draft_policy and draft_policy["issues"]:
        raise ValueError(
            "incompatible TLS draft policy: "
            + "; ".join(
                str(issue) for issue in cast(list[object], draft_policy["issues"])
            )
        )

    durations: list[float] = []
    successes = 0
    failures = 0
    shared_matches = 0
    first_run_trace: list[dict[str, object]] = []
    first_run_transcript_hash_hex = ""
    first_run_flight_count = 0
    first_run_semantics: list[str] = []

    for index in range(runs):
        start = perf_counter()
        transcript_hash = b""
        run_trace: list[dict[str, object]] = []

        client_hello = (
            f"tls13-clienthello|kem={kem_params}|mode={mode}|run={index}".encode(
                "utf-8"
            )
        )
        transcript_hash = _append_flight(
            run_trace,
            transcript_hash,
            flight_number=1,
            sender="client",
            message_type="ClientHello",
            payload=client_hello,
            semantics=("supported_groups:kyber", "signature_algorithms:dilithium"),
        )

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

        server_hello = (
            f"tls13-serverhello|kem={kem_params}|ciphertext-len={len(ciphertext)}".encode(
                "utf-8"
            )
            + ciphertext
        )
        transcript_hash = _append_flight(
            run_trace,
            transcript_hash,
            flight_number=2,
            sender="server",
            message_type="ServerHello",
            payload=server_hello,
            semantics=("key_share:pq",),
        )

        encrypted_extensions = f"tls13-encrypted-extensions|alpn=h2|mode={mode}".encode(
            "utf-8"
        )
        transcript_hash = _append_flight(
            run_trace,
            transcript_hash,
            flight_number=3,
            sender="server",
            message_type="EncryptedExtensions",
            payload=encrypted_extensions,
            semantics=("application_protocol:h2",),
        )

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
            certificate_payload = vk + dsa_params.encode("utf-8")
            transcript_hash = _append_flight(
                run_trace,
                transcript_hash,
                flight_number=4,
                sender="server",
                message_type="Certificate",
                payload=certificate_payload,
                semantics=("certificate_type:ml-dsa", f"dsa_params:{dsa_params}"),
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
            transcript_hash = _append_flight(
                run_trace,
                transcript_hash,
                flight_number=5,
                sender="server",
                message_type="CertificateVerify",
                payload=signature,
                semantics=("signature_context:tls13", "transcript_binding:enabled"),
            )

        server_finished = sha3_256(
            b"tls13-server-finished" + transcript_hash + server_secret
        ).digest()
        transcript_hash = _append_flight(
            run_trace,
            transcript_hash,
            flight_number=6,
            sender="server",
            message_type="Finished",
            payload=server_finished,
            semantics=("finished_mac:server",),
        )

        client_finished = sha3_256(
            b"tls13-client-finished" + transcript_hash + client_secret
        ).digest()
        transcript_hash = _append_flight(
            run_trace,
            transcript_hash,
            flight_number=7,
            sender="client",
            message_type="Finished",
            payload=client_finished,
            semantics=("finished_mac:client", "key_schedule_bound_to_transcript"),
        )

        match = client_secret == server_secret
        shared_matches += 1 if match else 0
        if match and authenticated:
            successes += 1
        else:
            failures += 1
        durations.append(perf_counter() - start)

        if index == 0:
            first_run_trace = run_trace
            first_run_transcript_hash_hex = transcript_hash.hex()
            first_run_flight_count = len(run_trace)
            first_run_semantics = [
                "algorithm_binding:client_hello",
                "key_share_binding:server_hello",
                "certificate_binding:ml_dsa",
                "transcript_binding:finished",
            ]

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
        flight_count=first_run_flight_count,
        transcript_hash_hex=first_run_transcript_hash_hex,
        flight_trace=first_run_trace,
        semantic_bindings=first_run_semantics,
        ciphersuite=selected_ciphersuite,
        draft=draft,
        compatibility=compatibility,
        draft_policy=draft_policy,
    )
    return record.to_dict()
