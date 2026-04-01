"""Utility functions for Kyber-PKE encoding, parameter handling, rounding, and compression.

This module contains reusable helpers for message encoding/decoding, parameter
resolution and validation, and cyclic distance calculations used in
encryption/decryption and key generation.
"""

from src.core import polynomials, module
from src.schemes.utils import resolve_named_params
from .params import ML_KEM_PARAM_SETS
from typing import Dict, Any


REQUIRED_PARAMS = ("q", "n", "k", "eta1", "eta2", "du", "dv")
PKE_MESSAGE_BYTES = 32


def pack_bits_le(values: list[int], bits: int) -> bytes:
    """Pack fixed-width integers into a little-endian bitstream."""
    if bits <= 0:
        raise ValueError("bits must be positive")
    mask = (1 << bits) - 1

    out = bytearray()
    acc = 0
    acc_bits = 0
    for value in values:
        v = int(value)
        if v < 0 or v > mask:
            raise ValueError(f"value {v} does not fit in {bits} bits")
        acc |= v << acc_bits
        acc_bits += bits
        while acc_bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            acc_bits -= 8

    if acc_bits:
        out.append(acc & 0xFF)

    return bytes(out)


def encode_polyvec_12(entries: list[list[int]], degree: int) -> bytes:
    """Encode a vector of degree-`degree` polynomials with 12-bit coefficients."""
    packed = bytearray()
    for coeffs in entries:
        if len(coeffs) != degree:
            raise ValueError("polynomial degree mismatch in polyvec encoding")
        packed.extend(pack_bits_le([int(c) for c in coeffs], 12))
    return bytes(packed)


def encode_public_key_bytes(
    rho_hex: str, t_payload: dict, params: Dict[str, Any] | str
) -> bytes:
    """Encode ML-KEM public key bytes as `byte_encode_12(t_hat) || rho`.

    This is the canonical form used in KAT vectors for `pk` and for `H(pk)`.
    """
    if not isinstance(rho_hex, str):
        raise TypeError("rho_hex must be a hex string")
    if not isinstance(t_payload, dict):
        raise TypeError("t_payload must be a dictionary")

    resolved = resolve_params(params)
    k = resolved["k"]
    n = resolved["n"]

    if t_payload.get("type") != "module_element":
        raise ValueError("t payload must be a module_element")
    if t_payload.get("rank") != k:
        raise ValueError("t payload rank mismatch")
    if t_payload.get("degree") != n:
        raise ValueError("t payload degree mismatch")

    entries = t_payload.get("entries")
    if not isinstance(entries, list) or len(entries) != k:
        raise ValueError("t payload entries mismatch")

    parsed_entries: list[list[int]] = []
    for coeffs in entries:
        if not isinstance(coeffs, list):
            raise ValueError("t payload polynomial entry must be a list")
        parsed_entries.append([int(c) for c in coeffs])

    return encode_polyvec_12(parsed_entries, degree=n) + bytes.fromhex(rho_hex)


def compress_coefficient(value: int, q: int, bits: int) -> int:
    """Compress one coefficient from Z_q to an integer in [0, 2^bits).

    Uses the Kyber quantization rule with nearest-integer rounding.
    """
    if bits <= 0:
        raise ValueError("bits must be positive")
    scale = 1 << bits
    return ((int(value) % q) * scale + (q // 2)) // q % scale


def decompress_coefficient(value: int, q: int, bits: int) -> int:
    """Decompress one quantized coefficient back into Z_q."""
    if bits <= 0:
        raise ValueError("bits must be positive")
    scale = 1 << bits
    return ((int(value) % scale) * q + (scale // 2)) // scale % q


def compress_polynomial(poly: polynomials.QuotientPolynomial, bits: int) -> dict:
    """Compress a quotient polynomial coefficient-wise to a JSON-friendly payload."""
    q = poly.ring.modulus
    degree = poly.degree
    coeffs = poly.to_coefficients(degree)
    return {
        "version": 1,
        "type": "ml_kem_compressed_polynomial",
        "modulus": q,
        "degree": degree,
        "bits": bits,
        "coefficients": [compress_coefficient(c, q, bits) for c in coeffs],
    }


def decompress_polynomial(
    payload: dict,
    ring: polynomials.QuotientPolynomialRing,
    expected_bits: int | None = None,
):
    """Decompress a polynomial payload into a QuotientPolynomial in ``ring``."""
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dictionary")
    if payload.get("type") != "ml_kem_compressed_polynomial":
        raise ValueError("invalid compressed polynomial payload type")

    bits = payload.get("bits")
    if not isinstance(bits, int):
        raise ValueError("compressed polynomial payload missing bits")
    if expected_bits is not None and bits != expected_bits:
        raise ValueError("compressed polynomial bits do not match parameter set")

    if payload.get("modulus") != ring.coefficient_ring.modulus:
        raise ValueError("compressed polynomial modulus mismatch")
    if payload.get("degree") != ring.degree:
        raise ValueError("compressed polynomial degree mismatch")

    coeffs = payload.get("coefficients")
    if not isinstance(coeffs, list):
        raise TypeError("compressed polynomial coefficients must be a list")
    if len(coeffs) != ring.degree:
        raise ValueError("compressed polynomial coefficient length mismatch")

    return ring.polynomial(
        [decompress_coefficient(c, ring.coefficient_ring.modulus, bits) for c in coeffs]
    )


def compress_module_element(element: module.ModuleElement, bits: int) -> dict:
    """Compress a module element coefficient-wise to a JSON-friendly payload."""
    qring = element.module.quotient_ring
    q = qring.coefficient_ring.modulus
    degree = qring.degree

    compressed_entries = []
    for entry in element.entries:
        coeffs = entry.to_coefficients(degree)
        compressed_entries.append([compress_coefficient(c, q, bits) for c in coeffs])

    return {
        "version": 1,
        "type": "ml_kem_compressed_module_element",
        "modulus": q,
        "degree": degree,
        "rank": element.module.rank,
        "bits": bits,
        "entries": compressed_entries,
    }


def decompress_module_element(
    payload: dict,
    target_module: module.Module,
    expected_bits: int | None = None,
):
    """Decompress a module-element payload into a ModuleElement in ``target_module``."""
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dictionary")
    if payload.get("type") != "ml_kem_compressed_module_element":
        raise ValueError("invalid compressed module element payload type")

    bits = payload.get("bits")
    if not isinstance(bits, int):
        raise ValueError("compressed module element payload missing bits")
    if expected_bits is not None and bits != expected_bits:
        raise ValueError("compressed module element bits do not match parameter set")

    qring = target_module.quotient_ring
    if payload.get("modulus") != qring.coefficient_ring.modulus:
        raise ValueError("compressed module element modulus mismatch")
    if payload.get("degree") != qring.degree:
        raise ValueError("compressed module element degree mismatch")
    if payload.get("rank") != target_module.rank:
        raise ValueError("compressed module element rank mismatch")

    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise TypeError("compressed module element entries must be a list")
    if len(entries) != target_module.rank:
        raise ValueError("compressed module element entry count mismatch")

    decompressed_entries = []
    for coeffs in entries:
        if not isinstance(coeffs, list):
            raise TypeError(
                "compressed module element entry must be a coefficient list"
            )
        if len(coeffs) != qring.degree:
            raise ValueError("compressed module element coefficient length mismatch")
        decompressed_entries.append(
            [
                decompress_coefficient(c, qring.coefficient_ring.modulus, bits)
                for c in coeffs
            ]
        )

    return target_module.element(decompressed_entries)


def resolve_params(params: Dict[str, Any] | str) -> Dict[str, Any]:
    """Resolve a parameter preset name or explicit parameter dictionary.

    Flexible parameter input resolution supporting multiple call conventions:
      1. Preset name: resolve_params("ML-KEM-768") or resolve_params("768")
      2. Explicit dict: resolve_params({"q": 3329, "n": 256, ...})
      3. Dict with preset name: resolve_params({"name": "ML-KEM-768", "q": 3330})
         (merges preset values with overrides)

    Args:
        params: Either a preset name string ("ML-KEM-512", "512", etc.) or
                a parameter dictionary with keys q, n, k, eta1, eta2, du, dv.

    Returns:
        dict: Resolved parameter dictionary with all required keys and their values.
              Preserves any extra keys for forward compatibility.

    Raises:
        ValueError: If string preset is not recognized (not in ML_KEM_PARAM_SETS).
        TypeError: If params is neither string nor dict.

    Examples:
        >>> params = resolve_params("ML-KEM-768")
        >>> params["k"]
        3
        >>> params = resolve_params({"name": "ML-KEM-512"})
        >>> params["k"]
        2
    """
    return resolve_named_params(
        params=params,
        preset_map=ML_KEM_PARAM_SETS,
        required=REQUIRED_PARAMS,
        unknown_message=(
            "unknown ML-KEM parameter set; expected one of: "
            "ML-KEM-512, ML-KEM-768, ML-KEM-1024, 512, 768, 1024"
        ),
        type_message="params must be a dict or preset name string",
        missing_message_prefix="missing required ML-KEM parameters",
    )


def validate_params(resolved: Dict[str, Any]) -> None:
    """Validate that a parameter dictionary contains all required ML-KEM parameters.

    Checks that all parameters in REQUIRED_PARAMS tuple are present in the resolved dict.
    Required parameters: q, n, k, eta1, eta2, du, dv

    Args:
        resolved: Parameter dictionary to validate (typically from resolve_params).

    Raises:
        ValueError: If any required parameter is missing (lists the missing keys).

    Examples:
        >>> validate_params({"q": 3329, "n": 256, "k": 3, "eta1": 2, "eta2": 2, "du": 10, "dv": 4})
        # No error
        >>> validate_params({"q": 3329})
        ValueError: missing required ML-KEM parameters: n, k, eta1, eta2, du, dv
    """
    # Keep public API for callers while resolution now guarantees required keys.
    missing = [name for name in REQUIRED_PARAMS if name not in resolved]
    if missing:
        missing_csv = ", ".join(missing)
        raise ValueError(f"missing required ML-KEM parameters: {missing_csv}")


def message_to_poly(message: bytes, ring: polynomials.QuotientPolynomialRing):
    """Encode a 32-byte message into a polynomial in R_q using bit embedding.

    MESSAGE ENCODING SCHEME:
    Each of the 256 bits (32 bytes * 8 bits/byte) is embedded into polynomial coefficients:
      bit b_i (0 or 1) -> coefficient c_i = b_i * (q+1)/2 in Z_q
      Example with q=3329:
        bit 0 -> coefficient 0
        bit 1 -> coefficient 1664 = (3329+1)/2 in Z_q

    This embedding is resilient to small errors: if a coefficient is perturbed by
    an error smaller than (q-1)/4 ≈ 832, nearest-neighbor rounding recovers the original bit.

    Args:
        message: 32-byte message to encode (required exact length for Kyber-PKE standard).
        ring: Target quotient ring R_q = Z_q[X]/(X^n+1) where n >= 256.
              Typically n=256 for Kyber-PKE, allowing coefficients 0..255.

    Returns:
        QuotientPolynomial: Encoded message as polynomial in ring.
                           Coefficients 0..255 contain embedded bits.
                           Remaining coefficients (if n > 256) are zero.

    Raises:
        TypeError: If message is not bytes-like (bytes or bytearray).
        ValueError: If message length is not exactly 32 bytes.

    Examples:
        >>> from src.core.polynomials import QuotientPolynomialRing
        >>> from src.core.integers import IntegersRing
        >>> ring = QuotientPolynomialRing(IntegersRing(3329), 256)
        >>> msg = b"\\x00" * 32  # all zero bits
        >>> poly = message_to_poly(msg, ring)
        >>> all(c == 0 for c in poly.coefficients[:256])  # all bits encoded as 0
        True
        >>> msg = b"\\xff" * 32  # all one bits
        >>> poly = message_to_poly(msg, ring)
        >>> all(c == 1664 for c in poly.coefficients[:256])  # all bits encoded as 1664
        True
    """
    # Validate input type and length
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes-like")
    if len(message) != PKE_MESSAGE_BYTES:
        raise ValueError("message must be exactly 32 bytes")

    q = ring.coefficient_ring.modulus
    one = (q + 1) // 2
    coeffs = [0] * ring.degree

    # Extract bits from bytes in little-endian order (LSB first)
    bits = []
    for byte in bytes(message):
        for bit_idx in range(8):
            bits.append((byte >> bit_idx) & 1)

    # Map bits to polynomial coefficients
    for idx, bit in enumerate(bits):
        coeffs[idx] = one if bit else 0

    return ring.polynomial(coeffs)


def cyclic_distance(a: int, b: int, q: int) -> int:
    """Compute the cyclic (modular) distance between two elements in Z_q.

    In modular arithmetic on Z_q, there are two distances from a to b:
      - forward: (b - a) mod q
      - backward: (a - b) mod q

    The cyclic distance is the minimum of these two, representing the "shortest path"
    on the cyclic group Z_q.

    ROUNDING APPLICATION:
    During message decoding, we use cyclic distance to perform nearest-neighbor rounding:
      - distance[coeff to 0] vs distance[coeff to (q+1)/2]
      - If distance to (q+1)/2 is smaller, round to 1; else round to 0
    This works because valid ciphertexts have small errors, keeping coefficients close
    to either 0 or (q+1)/2 in the cyclic metric.

    Args:
        a: First element in Z_q (typically a ciphertext coefficient).
        b: Second element (typically a rounding target: 0 or (q+1)/2).
        q: Modulus defining Z_q (typically q=3329 for Kyber).

    Returns:
        int: Minimum cyclic distance between a and b, always in range [0, floor(q/2)].

    Examples:
        >>> cyclic_distance(1, 0, 3329)  # distance from 1 to 0
        1
        >>> cyclic_distance(3328, 0, 3329)  # 3328 equiv -1 mod 3329, distance 1
        1
        >>> cyclic_distance(1665, 1664, 3329)  # distance from 1665 to 1664
        1
    """
    # Calculate difference modulo q
    diff = abs(a - b) % q
    # Return minimum of forward and backward distances
    return min(diff, q - diff)


def poly_to_message(poly: polynomials.QuotientPolynomial) -> bytes:
    """Decode a polynomial from R_q back into a 32-byte message using nearest-neighbor rounding.

    DECODING ALGORITHM:
    1. Extract first 256 coefficients from polynomial (one per bit).
    2. For each coefficient c in Z_q:
       a. Compute cyclic distances: d0 = distance(c, 0) and d1 = distance(c, (q+1)/2)
       b. Bit b_i = 1 if d1 < d0, else b_i = 0
    3. Pack 256 bits back into 32 bytes (little-endian bit ordering).

    CORRECTNESS:
    Decryption produces m_poly = v - s^T*u, which approximately equals e2 - e1^T*r + m_poly_original.
    The error term is bounded by small infinity norm (controlled by eta1, eta2 parameters).
    This ensures each coefficient stays close enough to either 0 or (q+1)/2 that
    nearest-neighbor rounding recovers the correct bit.

    Args:
        poly: QuotientPolynomial from decryption to decode back to message.
              Typically degree 256 with 256 bits packed in coefficients.

    Returns:
        bytes: 32-byte decoded message.
               Bits are extracted and packed in little-endian byte order.

    Examples:
        >>> from src.core.polynomials import QuotientPolynomialRing
        >>> from src.core.integers import IntegersRing
        >>> ring = QuotientPolynomialRing(IntegersRing(3329), 256)
        >>> msg = b"hello world!!!!!!!!!!!!!!!!!!!!!!"  # 32 bytes
        >>> poly = message_to_poly(msg, ring)
        >>> recovered = poly_to_message(poly)
        >>> recovered == msg
        True
    """
    q = poly.ring.modulus
    one = (q + 1) // 2
    # Extract first 256 coefficients (one per bit)
    coeffs = poly.to_coefficients(PKE_MESSAGE_BYTES * 8)

    # Perform nearest-neighbor rounding to recover bits
    bits = []
    for coeff in coeffs:
        c = coeff % q
        # Calculate cyclic distance to both rounding targets
        d0 = cyclic_distance(c, 0, q)
        d1 = cyclic_distance(c, one, q)
        # Recover bit based on which target is closer
        bits.append(1 if d1 < d0 else 0)

    # Pack bits back into bytes (little-endian)
    out = bytearray(PKE_MESSAGE_BYTES)
    for i, bit in enumerate(bits):
        out[i // 8] |= (bit & 1) << (i % 8)
    return bytes(out)


__all__ = [
    "pack_bits_le",
    "encode_polyvec_12",
    "encode_public_key_bytes",
    "resolve_params",
    "validate_params",
    "message_to_poly",
    "cyclic_distance",
    "poly_to_message",
    "compress_coefficient",
    "decompress_coefficient",
    "compress_polynomial",
    "decompress_polynomial",
    "compress_module_element",
    "decompress_module_element",
    "REQUIRED_PARAMS",
    "PKE_MESSAGE_BYTES",
]
