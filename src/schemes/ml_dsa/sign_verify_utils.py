"""Shared helpers for ML-DSA signing and verification."""

from hashlib import shake_128, shake_256
from typing import Any, Dict

from src.core import module, polynomials, sampling, serialization
from src.schemes.utils import resolve_named_params

from .params import ML_DSA_PARAM_SETS, MlDsaParams


_ML_DSA_Q = 8380417
_ML_DSA_QINV = 58728449
_ML_DSA_N = 256
_ML_DSA_ZETAS = [
    0,
    25847,
    -2608894,
    -518909,
    237124,
    -777960,
    -876248,
    466468,
    1826347,
    2353451,
    -359251,
    -2091905,
    3119733,
    -2884855,
    3111497,
    2680103,
    2725464,
    1024112,
    -1079900,
    3585928,
    -549488,
    -1119584,
    2619752,
    -2108549,
    -2118186,
    -3859737,
    -1399561,
    -3277672,
    1757237,
    -19422,
    4010497,
    280005,
    2706023,
    95776,
    3077325,
    3530437,
    -1661693,
    -3592148,
    -2537516,
    3915439,
    -3861115,
    -3043716,
    3574422,
    -2867647,
    3539968,
    -300467,
    2348700,
    -539299,
    -1699267,
    -1643818,
    3505694,
    -3821735,
    3507263,
    -2140649,
    -1600420,
    3699596,
    811944,
    531354,
    954230,
    3881043,
    3900724,
    -2556880,
    2071892,
    -2797779,
    -3930395,
    -1528703,
    -3677745,
    -3041255,
    -1452451,
    3475950,
    2176455,
    -1585221,
    -1257611,
    1939314,
    -4083598,
    -1000202,
    -3190144,
    -3157330,
    -3632928,
    126922,
    3412210,
    -983419,
    2147896,
    2715295,
    -2967645,
    -3693493,
    -411027,
    -2477047,
    -671102,
    -1228525,
    -22981,
    -1308169,
    -381987,
    1349076,
    1852771,
    -1430430,
    -3343383,
    264944,
    508951,
    3097992,
    44288,
    -1100098,
    904516,
    3958618,
    -3724342,
    -8578,
    1653064,
    -3249728,
    2389356,
    -210977,
    759969,
    -1316856,
    189548,
    -3553272,
    3159746,
    -1851402,
    -2409325,
    -177440,
    1315589,
    1341330,
    1285669,
    -1584928,
    -812732,
    -1439742,
    -3019102,
    -3881060,
    -3628969,
    3839961,
    2091667,
    3407706,
    2316500,
    3817976,
    -3342478,
    2244091,
    -2446433,
    -3562462,
    266997,
    2434439,
    -1235728,
    3513181,
    -3520352,
    -3759364,
    -1197226,
    -3193378,
    900702,
    1859098,
    909542,
    819034,
    495491,
    -1613174,
    -43260,
    -522500,
    -655327,
    -3122442,
    2031748,
    3207046,
    -3556995,
    -525098,
    -768622,
    -3595838,
    342297,
    286988,
    -2437823,
    4108315,
    3437287,
    -3342277,
    1735879,
    203044,
    2842341,
    2691481,
    -2590150,
    1265009,
    4055324,
    1247620,
    2486353,
    1595974,
    -3767016,
    1250494,
    2635921,
    -3548272,
    -2994039,
    1869119,
    1903435,
    -1050970,
    -1333058,
    1237275,
    -3318210,
    -1430225,
    -451100,
    1312455,
    3306115,
    -1962642,
    -1279661,
    1917081,
    -2546312,
    -1374803,
    1500165,
    777191,
    2235880,
    3406031,
    -542412,
    -2831860,
    -1671176,
    -1846953,
    -2584293,
    -3724270,
    594136,
    -3776993,
    -2013608,
    2432395,
    2454455,
    -164721,
    1957272,
    3369112,
    185531,
    -1207385,
    -3183426,
    162844,
    1616392,
    3014001,
    810149,
    1652634,
    -3694233,
    -1799107,
    -3038916,
    3523897,
    3866901,
    269760,
    2213111,
    -975884,
    1717735,
    472078,
    -426683,
    1723600,
    -1803090,
    1910376,
    -1667432,
    -1104333,
    -260646,
    -3833893,
    -2939036,
    -2235985,
    -420899,
    -2286327,
    183443,
    -976891,
    1612842,
    -3545687,
    -554416,
    3919660,
    -48306,
    -1362209,
    3937738,
    1400424,
    -846154,
    1976782,
]


def hash_shake_bits(data: bytes, bits: int) -> bytes:
    """Hash arbitrary bytes with SHAKE256 to an exact bit-length output."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    if not isinstance(bits, int) or bits <= 0:
        raise ValueError("bits must be a positive integer")
    if bits % 8 != 0:
        raise ValueError("bits must be a multiple of 8")
    return shake_256(bytes(data)).digest(bits // 8)


def _pack_bits_le(values: list[int], bits: int) -> bytes:
    if bits <= 0:
        raise ValueError("bits must be positive")

    out = bytearray()
    acc = 0
    acc_bits = 0
    mask = (1 << bits) - 1

    for value in values:
        v = int(value)
        if v < 0 or v > mask:
            raise ValueError("value out of range for bit width")
        acc |= v << acc_bits
        acc_bits += bits
        while acc_bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            acc_bits -= 8

    if acc_bits:
        out.append(acc & 0xFF)
    return bytes(out)


def _montgomery_reduce(value: int) -> int:
    t = (int(value) & 0xFFFFFFFF) * _ML_DSA_QINV
    t &= 0xFFFFFFFF
    if t & 0x80000000:
        t -= 0x100000000
    return (int(value) - t * _ML_DSA_Q) >> 32


def _caddq(value: int) -> int:
    return int(value) + ((int(value) >> 31) & _ML_DSA_Q)


def _ml_dsa_ntt(coeffs: list[int]) -> list[int]:
    if len(coeffs) != _ML_DSA_N:
        raise ValueError("NTT input must have length 256")
    out = [int(c) for c in coeffs]
    k = 0
    length = 128
    while length > 0:
        for start in range(0, _ML_DSA_N, 2 * length):
            k += 1
            zeta = _ML_DSA_ZETAS[k]
            for j in range(start, start + length):
                t = _montgomery_reduce(zeta * out[j + length])
                out[j + length] = out[j] - t
                out[j] = out[j] + t
        length >>= 1
    return out


def _ml_dsa_invntt_tomont(coeffs: list[int]) -> list[int]:
    if len(coeffs) != _ML_DSA_N:
        raise ValueError("invNTT input must have length 256")
    out = [int(c) for c in coeffs]
    k = 256
    length = 1
    f = 41978  # mont^2 / 256 from reference implementation.
    while length < _ML_DSA_N:
        for start in range(0, _ML_DSA_N, 2 * length):
            k -= 1
            zeta = -_ML_DSA_ZETAS[k]
            for j in range(start, start + length):
                t = out[j]
                out[j] = t + out[j + length]
                out[j + length] = t - out[j + length]
                out[j + length] = _montgomery_reduce(zeta * out[j + length])
        length <<= 1
    for j in range(_ML_DSA_N):
        out[j] = _montgomery_reduce(f * out[j])
    return out


def _poly_pointwise_montgomery(a_hat: list[int], b_hat: list[int]) -> list[int]:
    return [_montgomery_reduce(int(a_hat[i]) * int(b_hat[i])) for i in range(_ML_DSA_N)]


def _shake_reader(seed: bytes, *, variant: int):
    offset = 0

    def read(n: int) -> bytes:
        nonlocal offset
        if n <= 0:
            return b""
        total = offset + n
        if variant == 128:
            data = shake_128(seed).digest(total)
        elif variant == 256:
            data = shake_256(seed).digest(total)
        else:
            raise ValueError("unsupported SHAKE variant")
        chunk = data[offset:total]
        offset = total
        return chunk

    return read


def _rej_uniform_q(seed: bytes, n: int, q: int) -> list[int]:
    coeffs: list[int] = []
    read = _shake_reader(seed, variant=128)
    while len(coeffs) < n:
        buf = read(168)
        for i in range(0, len(buf) - 2, 3):
            t = buf[i] | (buf[i + 1] << 8) | (buf[i + 2] << 16)
            t &= 0x7FFFFF
            if t < q:
                coeffs.append(t)
                if len(coeffs) == n:
                    break
    return coeffs


def _rej_eta(seed: bytes, n: int, eta: int) -> list[int]:
    coeffs: list[int] = []
    read = _shake_reader(seed, variant=256)
    while len(coeffs) < n:
        buf = read(136)
        for b in buf:
            lo = b & 0x0F
            hi = b >> 4
            for t in (lo, hi):
                if eta == 2:
                    if t >= 15:
                        continue
                    t = t - ((205 * t) >> 10) * 5
                    coeffs.append(2 - t)
                elif eta == 4:
                    if t >= 9:
                        continue
                    coeffs.append(4 - t)
                else:
                    raise ValueError("unsupported eta")
                if len(coeffs) == n:
                    break
            if len(coeffs) == n:
                break
    return coeffs


def _expand_mask_poly(seed: bytes, n: int, gamma1: int) -> list[int]:
    bits = 18 if gamma1 == (1 << 17) else 20
    mask = (1 << bits) - 1
    need_bits = n * bits
    need_bytes = (need_bits + 7) // 8
    stream = shake_256(seed).digest(need_bytes)

    out: list[int] = []
    acc = 0
    acc_bits = 0
    idx = 0
    while len(out) < n:
        while acc_bits < bits:
            acc |= stream[idx] << acc_bits
            idx += 1
            acc_bits += 8
        t = acc & mask
        acc >>= bits
        acc_bits -= bits
        out.append(gamma1 - t)
    return out


def pack_w1(module_element: module.ModuleElement, gamma2: int) -> bytes:
    """Pack w1 coefficients to the byte layout used in challenge hashing."""
    n = module_element.module.quotient_ring.degree
    packed = bytearray()
    if gamma2 == 95232:
        # Values are in [0, 43], packed on 6 bits.
        for entry in module_element.entries:
            coeffs = [int(c) & 0x3F for c in entry.to_coefficients(n)]
            packed.extend(_pack_bits_le(coeffs, 6))
        return bytes(packed)

    if gamma2 == 261888:
        # Values are in [0, 15], packed on 4 bits.
        for entry in module_element.entries:
            coeffs = [int(c) & 0x0F for c in entry.to_coefficients(n)]
            packed.extend(_pack_bits_le(coeffs, 4))
        return bytes(packed)

    raise ValueError("unsupported gamma2 for w1 packing")


def pack_t1(module_element: module.ModuleElement) -> bytes:
    """Pack t1 coefficients on 10 bits per coefficient."""
    n = module_element.module.quotient_ring.degree
    packed = bytearray()
    for entry in module_element.entries:
        coeffs = [int(c) & 0x3FF for c in entry.to_coefficients(n)]
        packed.extend(_pack_bits_le(coeffs, 10))
    return bytes(packed)


def resolve_ml_dsa_sign_params(params: MlDsaParams) -> Dict[str, Any]:
    """Resolve preset/custom ML-DSA parameters and validate required keys."""
    return resolve_named_params(
        params=params,
        preset_map=ML_DSA_PARAM_SETS,
        required=(
            "q",
            "n",
            "d",
            "k",
            "l",
            "eta",
            "gamma1",
            "gamma2",
            "tau",
            "beta",
            "lambda",
        ),
        unknown_message=f"Unknown ML-DSA parameter set: {params}",
        type_message="params must be a string preset or dictionary",
        missing_message_prefix="params missing required keys",
    )


def centered_mod(value: int, modulus: int) -> int:
    """Centered representative in (-modulus/2, modulus/2]."""
    v = int(value) % modulus
    half = modulus // 2
    if v > half:
        v -= modulus
    return v


def centered_mod_power_of_two(value: int, d: int) -> int:
    """Centered remainder mods 2^d in (-2^(d-1), 2^(d-1)]."""
    if not isinstance(d, int) or d <= 0:
        raise ValueError("d must be a positive integer")
    m = 1 << d
    r0 = int(value) % m
    half = m >> 1
    if r0 > half:
        r0 -= m
    return r0


def power2round_coeff(value: int, d: int, q: int) -> tuple[int, int]:
    """Split a mod-q coefficient into (high, low) with r = high*2^d + low."""
    a = int(value) % q
    two_d = 1 << d
    low = centered_mod(a, two_d)
    high = (a - low) >> d
    return high, low


def power2round_module(
    value: module.ModuleElement,
    target_module: module.Module,
    d: int,
) -> tuple[module.ModuleElement, module.ModuleElement]:
    """Apply `power2round_coeff` to every coefficient of a module element."""
    highs = []
    lows = []
    n = target_module.quotient_ring.degree
    q = target_module.quotient_ring.coefficient_ring.modulus
    for entry in value.entries:
        hi = []
        lo = []
        for coeff in entry.to_coefficients(n):
            c_hi, c_lo = power2round_coeff(coeff, d, q)
            hi.append(c_hi)
            lo.append(c_lo)
        highs.append(target_module.quotient_ring.polynomial(hi))
        lows.append(target_module.quotient_ring.polynomial(lo))
    return target_module.element(highs), target_module.element(lows)


def expand_a(
    rho: bytes,
    quotient_ring: polynomials.QuotientPolynomialRing,
    k: int,
    l: int,
) -> list[list[polynomials.QuotientPolynomial]]:
    """Deterministically expand matrix A from rho."""
    if not isinstance(rho, (bytes, bytearray)):
        raise TypeError("rho must be bytes-like")
    if len(rho) != 32:
        raise ValueError("rho must be 32 bytes")

    q = quotient_ring.coefficient_ring.modulus
    n = quotient_ring.degree
    matrix: list[list[polynomials.QuotientPolynomial]] = []
    for i in range(k):
        row: list[polynomials.QuotientPolynomial] = []
        for j in range(l):
            seed = bytes(rho) + bytes([j, i])
            coeffs = _rej_uniform_q(seed=seed, n=n, q=q)
            row.append(quotient_ring.polynomial(coeffs))
        matrix.append(row)
    return matrix


def expand_s(
    rho_prime: bytes,
    module_l: module.Module,
    module_k: module.Module,
    eta: int,
) -> tuple[module.ModuleElement, module.ModuleElement]:
    """Deterministically expand s1 and s2 from rho'."""
    if not isinstance(rho_prime, (bytes, bytearray)):
        raise TypeError("rho_prime must be bytes-like")
    if len(rho_prime) != 64:
        raise ValueError("rho_prime must be 64 bytes")

    n = module_l.quotient_ring.degree
    nonce = 0
    s1_entries = []
    for _ in range(module_l.rank):
        seed = bytes(rho_prime) + nonce.to_bytes(2, "little")
        coeffs = _rej_eta(seed=seed, n=n, eta=eta)
        s1_entries.append(module_l.quotient_ring.polynomial(coeffs))
        nonce += 1

    s2_entries = []
    for _ in range(module_k.rank):
        seed = bytes(rho_prime) + nonce.to_bytes(2, "little")
        coeffs = _rej_eta(seed=seed, n=n, eta=eta)
        s2_entries.append(module_k.quotient_ring.polynomial(coeffs))
        nonce += 1

    return module_l.element(s1_entries), module_k.element(s2_entries)


def expand_mask(
    rho_2prime: bytes,
    module_l: module.Module,
    gamma1: int,
    kappa: int,
) -> module.ModuleElement:
    """Deterministically sample y in S~_{gamma1}^l from rho'' and kappa."""
    if not isinstance(rho_2prime, (bytes, bytearray)):
        raise TypeError("rho_2prime must be bytes-like")
    if len(rho_2prime) != 64:
        raise ValueError("rho_2prime must be 64 bytes")
    if not isinstance(kappa, int) or kappa < 0:
        raise ValueError("kappa must be a non-negative integer")
    if gamma1 <= 0:
        raise ValueError("gamma1 must be positive")

    kappa_bytes = kappa.to_bytes(2, byteorder="little", signed=False)
    n = module_l.quotient_ring.degree
    entries = []
    for r in range(module_l.rank):
        nonce = int.from_bytes(kappa_bytes, "little") + r
        seed = bytes(rho_2prime) + nonce.to_bytes(2, "little")
        coeffs = _expand_mask_poly(seed=seed, n=n, gamma1=gamma1)
        entries.append(module_l.quotient_ring.polynomial(coeffs))
    return module_l.element(entries)


def mat_vec_add_ahat(
    matrix: list[list[polynomials.QuotientPolynomial]],
    vector_entries: list[polynomials.QuotientPolynomial],
    add_entries: list[polynomials.QuotientPolynomial],
    q: int,
    n: int,
) -> list[polynomials.QuotientPolynomial]:
    """Compute A_hat * vector + add_entries using ML-DSA NTT-domain arithmetic."""
    if q != _ML_DSA_Q or n != _ML_DSA_N:
        raise ValueError("mat_vec_add_ahat currently supports ML-DSA q=8380417, n=256")

    rows = len(matrix)
    if rows != len(add_entries):
        raise ValueError("matrix row count must equal add_entries length")
    if rows == 0:
        return []

    cols = len(vector_entries)
    s_hat = [
        _ml_dsa_ntt([centered_mod(c, q) for c in entry.to_coefficients(n)])
        for entry in vector_entries
    ]

    ring = matrix[0][0].ring
    out: list[polynomials.QuotientPolynomial] = []
    for i, row in enumerate(matrix):
        if len(row) != cols:
            raise ValueError("matrix row width must equal vector length")

        acc = [0] * n
        for j in range(cols):
            a_hat = row[j].to_coefficients(n)
            prod = _poly_pointwise_montgomery(a_hat, s_hat[j])
            acc = [acc[z] + prod[z] for z in range(n)]

        coeffs = _ml_dsa_invntt_tomont(acc)
        add_coeffs = [centered_mod(c, q) for c in add_entries[i].to_coefficients(n)]
        coeffs = [(_caddq(coeffs[z] + add_coeffs[z])) % q for z in range(n)]
        out.append(polynomials.QuotientPolynomial(coeffs, ring, n))

    return out


def sample_in_ball(
    c_tilde: bytes,
    ring: polynomials.QuotientPolynomialRing,
    tau: int,
) -> polynomials.QuotientPolynomial:
    """Map challenge bytes to c in B_tau (exactly tau coefficients in {+/-1})."""
    if not isinstance(c_tilde, (bytes, bytearray)):
        raise TypeError("c_tilde must be bytes-like")
    if tau <= 0:
        raise ValueError("tau must be positive")

    n = ring.degree
    if tau > n:
        raise ValueError("tau cannot exceed polynomial degree")

    read = _shake_reader(bytes(c_tilde), variant=256)
    signs = int.from_bytes(read(8), byteorder="little", signed=False)
    coeffs = [0] * n

    for i in range(n - tau, n):
        while True:
            b = read(1)[0]
            if b <= i:
                break
        coeffs[i] = coeffs[b]
        coeffs[b] = 1 if (signs & 1) == 0 else -1
        signs >>= 1
    return ring.polynomial(coeffs)


def matrix_payload(
    matrix: list[list[polynomials.QuotientPolynomial]], q: int, n: int
) -> dict:
    """Serialize a polynomial matrix into a JSON-friendly payload."""
    rows = len(matrix)
    cols = len(matrix[0]) if rows > 0 else 0
    return {
        "version": 1,
        "type": "ml_dsa_matrix",
        "modulus": q,
        "degree": n,
        "rows": rows,
        "cols": cols,
        "entries": [[poly.to_coefficients(n) for poly in row] for row in matrix],
    }


def matrix_from_payload(
    payload: dict,
    ring: Any,
    degree: int,
) -> list[list[polynomials.QuotientPolynomial]]:
    """Deserialize a matrix payload back into quotient polynomials."""
    if not isinstance(payload, dict):
        raise TypeError("A payload must be a dictionary")
    if payload.get("type") != "ml_dsa_matrix":
        raise ValueError("invalid A payload type")
    if payload.get("modulus") != ring.modulus:
        raise ValueError("A payload modulus mismatch")
    if payload.get("degree") != degree:
        raise ValueError("A payload degree mismatch")

    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise TypeError("A payload entries must be a list")

    matrix: list[list[polynomials.QuotientPolynomial]] = []
    for row in entries:
        if not isinstance(row, list):
            raise TypeError("A payload rows must be lists")
        matrix.append([polynomials.QuotientPolynomial(c, ring, degree) for c in row])
    return matrix


def challenge_digest(
    mu: bytes,
    w1_payload: dict,
    lambda_bits: int,
    gamma2: int,
) -> bytes:
    """Compute c_tilde = H(mu || w1, 2*lambda)."""
    if not isinstance(mu, (bytes, bytearray)):
        raise TypeError("mu must be bytes-like")
    module_element = serialization.module_element_from_dict(w1_payload)
    w1_bytes = pack_w1(module_element, gamma2=gamma2)
    return hash_shake_bits(bytes(mu) + w1_bytes, 2 * lambda_bits)


def decompose_coeff(value: int, q: int, alpha: int) -> tuple[int, int]:
    """Modified Decompose used by Dilithium hint logic."""
    if alpha <= 0:
        raise ValueError("alpha must be positive")
    r = int(value) % q
    r0 = centered_mod(r, alpha)
    if (r - r0) == (q - 1):
        r1 = 0
        r0 = r0 - 1
    else:
        r1 = (r - r0) // alpha
    return r1, r0


def _poly_high_low(
    poly: polynomials.QuotientPolynomial,
    ring: polynomials.QuotientPolynomialRing,
    alpha: int,
) -> tuple[polynomials.QuotientPolynomial, polynomials.QuotientPolynomial]:
    q = ring.coefficient_ring.modulus
    n = ring.degree
    highs = []
    lows = []
    for coeff in poly.to_coefficients(n):
        high, low = decompose_coeff(coeff, q, alpha)
        highs.append(high)
        lows.append(low)
    return ring.polynomial(highs), ring.polynomial(lows)


def high_bits_module(
    value: module.ModuleElement,
    target_module: module.Module,
    alpha: int,
) -> module.ModuleElement:
    """Return component-wise HighBits under the modified decompose rule."""
    highs = []
    for entry in value.entries:
        high, _ = _poly_high_low(entry, target_module.quotient_ring, alpha)
        highs.append(high)
    return target_module.element(highs)


def low_bits_module(
    value: module.ModuleElement,
    target_module: module.Module,
    alpha: int,
) -> module.ModuleElement:
    """Return component-wise LowBits under the modified decompose rule."""
    lows = []
    for entry in value.entries:
        _, low = _poly_high_low(entry, target_module.quotient_ring, alpha)
        lows.append(low)
    return target_module.element(lows)


def hint_payload(hints: list[list[int]], q: int, n: int, k: int) -> dict:
    """Build the canonical signature hint payload object."""
    return {
        "version": 1,
        "type": "ml_dsa_hint",
        "modulus": q,
        "degree": n,
        "rank": k,
        "entries": hints,
    }


def make_hint_payload(
    z_value: module.ModuleElement,
    r_value: module.ModuleElement,
    alpha: int,
    q: int,
    n: int,
) -> dict:
    """Compute hint bits where HighBits(r+z) differs from HighBits(r)."""
    hints = []
    for z_entry, r_entry in zip(z_value.entries, r_value.entries):
        row = []
        z_coeffs = z_entry.to_coefficients(n)
        r_coeffs = r_entry.to_coefficients(n)
        for zc, rc in zip(z_coeffs, r_coeffs):
            high_rz, _ = decompose_coeff((rc + zc) % q, q, alpha)
            high_r, _ = decompose_coeff(rc % q, q, alpha)
            row.append(1 if high_rz != high_r else 0)
        hints.append(row)
    return hint_payload(hints, q=q, n=n, k=len(hints))


def hint_ones_count(payload: dict) -> int:
    """Count set bits in a hint payload for omega-bound checks."""
    entries = payload.get("entries", [])
    return sum(int(bit) for row in entries for bit in row)


def use_hint_module(
    hint: dict,
    r_value: module.ModuleElement,
    target_module: module.Module,
    alpha: int,
) -> module.ModuleElement:
    """Recover high bits of (r+z) from hint and r only."""
    q = target_module.quotient_ring.coefficient_ring.modulus
    n = target_module.quotient_ring.degree
    m = (q - 1) // alpha

    if hint.get("type") != "ml_dsa_hint":
        raise ValueError("invalid hint payload type")
    entries = hint.get("entries")
    if not isinstance(entries, list) or len(entries) != target_module.rank:
        raise ValueError("hint entry layout mismatch")

    out = []
    for r_entry, h_row in zip(r_value.entries, entries):
        if not isinstance(h_row, list) or len(h_row) != n:
            raise ValueError("hint row size mismatch")
        row = []
        r_coeffs = r_entry.to_coefficients(n)
        for coeff, h_bit in zip(r_coeffs, h_row):
            r1, r0 = decompose_coeff(coeff % q, q, alpha)
            if int(h_bit) == 1:
                if r0 > 0:
                    r1 = (r1 + 1) % m
                else:
                    r1 = (r1 - 1) % m
            row.append(r1)
        out.append(target_module.quotient_ring.polynomial(row))
    return target_module.element(out)


def low_bits_sufficiently_small(
    value: module.ModuleElement,
    gamma2: int,
    beta: int,
) -> bool:
    """Check `||LowBits(.)||_inf < gamma2 - beta` over all coefficients."""
    bound = max(gamma2 - beta, 0)
    q = value.module.quotient_ring.coefficient_ring.modulus
    n = value.module.quotient_ring.degree
    for entry in value.entries:
        for coeff in entry.to_coefficients(n):
            if abs(centered_mod(coeff, q)) >= bound:
                return False
    return True


def module_inf_norm(value: module.ModuleElement) -> int:
    """Return infinity norm of a module element under centered coefficients."""
    q = value.module.quotient_ring.coefficient_ring.modulus
    n = value.module.quotient_ring.degree
    norm = 0
    for entry in value.entries:
        for coeff in entry.to_coefficients(n):
            norm = max(norm, abs(centered_mod(coeff, q)))
    return norm


__all__ = [
    "MlDsaParams",
    "hash_shake_bits",
    "resolve_ml_dsa_sign_params",
    "centered_mod",
    "power2round_coeff",
    "power2round_module",
    "decompose_coeff",
    "expand_a",
    "expand_s",
    "expand_mask",
    "sample_in_ball",
    "challenge_digest",
    "pack_t1",
    "pack_w1",
    "mat_vec_add_ahat",
    "matrix_payload",
    "matrix_from_payload",
    "high_bits_module",
    "low_bits_module",
    "make_hint_payload",
    "hint_ones_count",
    "use_hint_module",
    "low_bits_sufficiently_small",
    "module_inf_norm",
]
