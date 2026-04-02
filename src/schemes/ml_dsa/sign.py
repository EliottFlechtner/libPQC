"""ML-DSA signing with iterative rejection sampling.

Flow (spec-style):
1. Reconstruct A from rho in SK.
2. Compute mu = H(tr || M, 512) and rho'' = H(K || rnd || mu, 512).
3. Iteratively sample y via ExpandMask(rho'', kappa).
4. Build c_tilde = H(mu || HighBits(Ay), 2*lambda), then c = SampleInBall(c_tilde).
5. Accept when z, LowBits(w-c*s2), ct0 and hint weight satisfy bounds.
"""

from src.core import integers, module, polynomials, serialization
from src.schemes.utils import to_seed_bytes

from .sign_verify_utils import (
    MlDsaParams,
    challenge_digest,
    expand_a,
    expand_mask,
    high_bits_module,
    hint_ones_count,
    low_bits_module,
    low_bits_sufficiently_small,
    make_hint_payload,
    mat_vec_add_ahat,
    module_inf_norm,
    resolve_ml_dsa_sign_params,
    sample_in_ball,
    hash_shake_bits,
)


def ml_dsa_sign(
    message: bytes | str,
    signing_key: bytes,
    params: MlDsaParams | None = None,
    rnd: bytes | str | None = None,
    max_iterations: int = 64,
) -> bytes:
    """Generate an ML-DSA signature.

    The signing loop follows the expected pattern for ML-DSA:
    sample mask y, derive challenge c from HighBits(Ay), and reject until
    z/low-bits/hint constraints are satisfied.
    """
    # Normalize message to bytes
    if isinstance(message, str):
        message_bytes = message.encode("utf-8")
    elif isinstance(message, (bytes, bytearray)):
        message_bytes = bytes(message)
    else:
        raise TypeError("message must be bytes-like or a string")

    # Validate input parameters
    if not isinstance(signing_key, (bytes, bytearray)):
        raise TypeError("signing_key must be bytes-like")
    if not isinstance(max_iterations, int) or max_iterations <= 0:
        raise ValueError("max_iterations must be a positive integer")

    # Deserialize and validate signing key structure
    sk_payload = serialization.from_bytes(bytes(signing_key))
    if sk_payload.get("type") != "ml_dsa_signing_key":
        raise ValueError("invalid signing key payload type")

    # Resolve parameters: use embedded params from key if not explicitly overridden
    if params is None:
        key_params = sk_payload.get("params")
        if not isinstance(key_params, (str, dict)):
            raise ValueError("signing key payload missing params")
        resolved = resolve_ml_dsa_sign_params(key_params)
    else:
        resolved = resolve_ml_dsa_sign_params(params)

    # Extract cryptographic parameters
    q = resolved["q"]
    n = resolved["n"]
    k = resolved["k"]
    l = resolved["l"]
    gamma1 = resolved["gamma1"]  # Bound for mask y in signing
    gamma2 = resolved["gamma2"]  # Bound for high/low bits
    tau = resolved["tau"]  # Number of ±1 coefficients in challenge
    beta = resolved["beta"]  # Norm bound for rejection
    omega = resolved["omega"]  # Maximum hint weight (ones in h)
    lambda_bits = resolved["lambda"]
    alpha = 2 * gamma2  # Decomposition modulus for hint logic
    param_name = resolved.get("name", "custom")

    # Set up polynomial arithmetic (same as in keygen/verify)
    z_q = integers.IntegersRing(q)
    r_q = polynomials.QuotientPolynomialRing(z_q, degree=n)

    # Extract seed material from signing key
    rho_hex = sk_payload.get("rho")
    k_hex = sk_payload.get("K")
    tr_hex = sk_payload.get("tr")
    if not isinstance(rho_hex, str):
        raise ValueError("signing key payload missing rho")
    if not isinstance(k_hex, str):
        raise ValueError("signing key payload missing K")
    if not isinstance(tr_hex, str):
        raise ValueError("signing key payload missing tr")

    rho = bytes.fromhex(rho_hex)
    k_seed = bytes.fromhex(k_hex)  # Seed for randomness (used with rnd and mu)
    tr = bytes.fromhex(tr_hex)  # Transcript for message hashing

    # Reconstruct matrix A from rho (same deterministic expansion as keygen)
    a_matrix = expand_a(rho, r_q, k=k, l=l)
    if len(a_matrix) != k:
        raise ValueError("A row count mismatch")
    if any(len(row) != l for row in a_matrix):
        raise ValueError("A column count mismatch")

    # Extract and validate secret components from signing key
    s1_payload = sk_payload.get("s1")
    s2_payload = sk_payload.get("s2")
    t0_payload = sk_payload.get("t0")
    if not isinstance(s1_payload, dict):
        raise ValueError("signing key payload missing s1")
    if not isinstance(s2_payload, dict):
        raise ValueError("signing key payload missing s2")
    if not isinstance(t0_payload, dict):
        raise ValueError("signing key payload missing t0")
    s1 = serialization.module_element_from_dict(s1_payload)
    s2 = serialization.module_element_from_dict(s2_payload)
    t0 = serialization.module_element_from_dict(t0_payload)
    if s1.module.rank != l:
        raise ValueError("s1 rank mismatch")
    if s2.module.rank != k:
        raise ValueError("s2 rank mismatch")
    if t0.module.rank != k:
        raise ValueError("t0 rank mismatch")

    # Rehydrate module elements into local module instances for arithmetic
    # This is crucial: ModuleElement arithmetic is identity-sensitive on the ring
    rql_module = module.Module(r_q, rank=l)
    rk_module = module.Module(r_q, rank=k)
    s1 = rql_module.element([entry.to_coefficients(n) for entry in s1.entries])
    s2 = rk_module.element([entry.to_coefficients(n) for entry in s2.entries])
    t0 = rk_module.element([entry.to_coefficients(n) for entry in t0.entries])

    # Prepare randomness for signing
    if rnd is None:
        rnd_bytes = b"\x00" * 32  # Default: no additional randomness
    else:
        rnd_bytes = to_seed_bytes(rnd, field_name="rnd")
        if len(rnd_bytes) != 32:
            rnd_bytes = hash_shake_bits(rnd_bytes, 256)  # Normalize to 32 bytes

    # Derive deterministic values for this signing instance
    # mu uniquely identifies the message being signed (reproducible from tr and message)
    # rho'' derives the rejection sampling randomness from mu, message, and signing key seed K
    mu = hash_shake_bits(tr + message_bytes, 512)
    rho_2prime = hash_shake_bits(k_seed + rnd_bytes + mu, 512)

    # Initialize rejection sampling variables
    zeros_k = [r_q.zero() for _ in range(k)]

    c_tilde = None
    z = None
    hint = None
    kappa = 0  # Mask counter for rejection sampling

    # Rejection sampling loop: try different masks until all constraints satisfied
    for _ in range(max_iterations):
        # Step 1: Sample random mask y in R_q^l with coefficients in [-gamma1+1, gamma1]
        y = expand_mask(rho_2prime, rql_module, gamma1=gamma1, kappa=kappa)

        # Step 2: Compute w = A * y (matrix-vector product)
        w_entries = mat_vec_add_ahat(
            matrix=a_matrix,
            vector_entries=y.entries,
            add_entries=zeros_k,
            q=q,
            n=n,
        )
        w = rk_module.element(w_entries)

        # Step 3: Extract high bits w1 = HighBits(w)
        # Used in challenge digest to protect against large commitments
        w1 = high_bits_module(w, rk_module, alpha=alpha)

        # Step 4: Derive challenge from message and w1
        # c_tilde = H(mu || w1, 2*lambda) produces a challenge seed
        w1_payload = serialization.module_element_to_dict(w1)
        c_tilde_try = challenge_digest(
            mu,
            w1_payload,
            lambda_bits=lambda_bits,
            gamma2=gamma2,
        )

        # Step 5: Expand challenge seed to c in B_tau (exactly tau coefficients in {+/-1})
        c_try = sample_in_ball(c_tilde_try, r_q, tau=tau)

        # Step 6: Compute response z = y + c * s1 (addition in R_q^l)
        z_try = y + s1.scalar_mul(c_try)

        # Step 7: Compute intermediate values for four acceptance conditions
        cs2 = s2.scalar_mul(c_try)
        low = low_bits_module(w - cs2, rk_module, alpha=alpha)  # LowBits(w - c*s2)
        ct0 = t0.scalar_mul(c_try)  # Scaled low bits of public key
        # Create hint from ct0 (indicates where high bits change due to rounding)
        hint_try = make_hint_payload(
            z_value=ct0.scalar_mul(-1),
            r_value=(w - cs2) + ct0,
            alpha=alpha,
            q=q,
            n=n,
        )

        # Step 8: Check four acceptance conditions (all must pass for valid signature)
        # Condition 1: ||z||_inf < gamma1 - beta (ensures z not too large)
        z_ok = module_inf_norm(z_try) < (gamma1 - beta)
        # Condition 2: ||LowBits(w - c*s2)||_inf <= gamma2 - beta (norms stay bounded)
        low_ok = low_bits_sufficiently_small(low, gamma2=gamma2, beta=beta)
        # Condition 3: ||c*t0||_inf < gamma2 (scaled low bits don't blow up)
        ct0_ok = module_inf_norm(ct0) < gamma2
        # Condition 4: weight(h) <= omega (hint doesn't exceed capacity)
        hint_ok = hint_ones_count(hint_try) <= omega

        # If all conditions satisfied, accept this signature
        if z_ok and low_ok and ct0_ok and hint_ok:
            c_tilde = c_tilde_try
            z = z_try
            hint = hint_try
            break

        # Otherwise, advance mask counter and try next mask
        kappa += l

    # Check if we found a valid signature within iteration limit
    if c_tilde is None or z is None or hint is None:
        raise RuntimeError(
            "failed to sample acceptable signature within max_iterations"
        )

    # Build signature payload containing challenge seed, response, and hints
    signature_payload = {
        "version": 1,
        "type": "ml_dsa_signature",
        "params": param_name,
        "c_tilde": c_tilde.hex(),  # Challenge seed (256 bits)
        "z": serialization.module_element_to_dict(z),  # Response vector (l entries)
        "h": hint,  # Hint bits (k*n bits total)
    }
    return serialization.to_bytes(signature_payload)


__all__ = ["MlDsaParams", "ml_dsa_sign"]
