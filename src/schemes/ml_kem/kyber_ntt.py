"""Kyber-specific NTT helpers for q=3329, n=256.

The generic core NTT requires 2n | (q-1), which does not hold for Kyber.
This module implements the Kyber reference-style transform and reductions.
"""

from __future__ import annotations

Q = 3329
QINV = 62209
N = 256

# PQClean ML-KEM zetas table (signed centered representatives).
ZETAS = [
    -1044,
    -758,
    -359,
    -1517,
    1493,
    1422,
    287,
    202,
    -171,
    622,
    1577,
    182,
    962,
    -1202,
    -1474,
    1468,
    573,
    -1325,
    264,
    383,
    -829,
    1458,
    -1602,
    -130,
    -681,
    1017,
    732,
    608,
    -1542,
    411,
    -205,
    -1571,
    1223,
    652,
    -552,
    1015,
    -1293,
    1491,
    -282,
    -1544,
    516,
    -8,
    -320,
    -666,
    -1618,
    -1162,
    126,
    1469,
    -853,
    -90,
    -271,
    830,
    107,
    -1421,
    -247,
    -951,
    -398,
    961,
    -1508,
    -725,
    448,
    -1065,
    677,
    -1275,
    -1103,
    430,
    555,
    843,
    -1251,
    871,
    1550,
    105,
    422,
    587,
    177,
    -235,
    -291,
    -460,
    1574,
    1653,
    -246,
    778,
    1159,
    -147,
    -777,
    1483,
    -602,
    1119,
    -1590,
    644,
    -872,
    349,
    418,
    329,
    -156,
    -75,
    817,
    1097,
    603,
    610,
    1322,
    -1285,
    -1465,
    384,
    -1215,
    -136,
    1218,
    -1335,
    -874,
    220,
    -1187,
    -1659,
    -1185,
    -1530,
    -1278,
    794,
    -1510,
    -854,
    -870,
    478,
    -108,
    -308,
    996,
    991,
    958,
    -1460,
    1522,
    1628,
]


def _to_centered(value: int) -> int:
    x = int(value) % Q
    if x > Q // 2:
        x -= Q
    return x


def to_standard(value: int) -> int:
    return int(value) % Q


def montgomery_reduce(a: int) -> int:
    t = (int(a) * QINV) & 0xFFFF
    u = (int(a) - t * Q) >> 16
    return _to_centered(u)


def barrett_reduce(a: int) -> int:
    v = ((1 << 26) + Q // 2) // Q
    t = ((v * int(a) + (1 << 25)) >> 26) * Q
    return _to_centered(int(a) - t)


def fqmul(a: int, b: int) -> int:
    return montgomery_reduce(int(a) * int(b))


def ntt(coeffs: list[int]) -> list[int]:
    if len(coeffs) != N:
        raise ValueError("Kyber NTT expects 256 coefficients")

    r = [_to_centered(c) for c in coeffs]
    k = 1
    length = 128
    while length >= 2:
        start = 0
        while start < N:
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = fqmul(zeta, r[j + length])
                r[j + length] = _to_centered(r[j] - t)
                r[j] = _to_centered(r[j] + t)
            start += 2 * length
        length >>= 1

    return [to_standard(barrett_reduce(c)) for c in r]


def invntt_tomont(coeffs: list[int]) -> list[int]:
    if len(coeffs) != N:
        raise ValueError("Kyber inverse NTT expects 256 coefficients")

    r = [_to_centered(c) for c in coeffs]
    k = 127
    length = 2
    while length <= 128:
        start = 0
        while start < N:
            zeta = ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = r[j]
                r[j] = barrett_reduce(t + r[j + length])
                r[j + length] = _to_centered(r[j + length] - t)
                r[j + length] = fqmul(zeta, r[j + length])
            start += 2 * length
        length <<= 1

    f = 1441
    return [to_standard(fqmul(c, f)) for c in r]


def poly_reduce(coeffs: list[int]) -> list[int]:
    if len(coeffs) != N:
        raise ValueError("Kyber polynomial reduction expects 256 coefficients")
    return [to_standard(barrett_reduce(c)) for c in coeffs]


def poly_add(a: list[int], b: list[int]) -> list[int]:
    if len(a) != N or len(b) != N:
        raise ValueError("Kyber polynomial add expects 256 coefficients")
    return [to_standard(int(x) + int(y)) for x, y in zip(a, b)]


def poly_tomont(coeffs: list[int]) -> list[int]:
    if len(coeffs) != N:
        raise ValueError(
            "Kyber polynomial Montgomery conversion expects 256 coefficients"
        )
    f = (1 << 32) % Q
    return [to_standard(montgomery_reduce(int(c) * f)) for c in coeffs]


def poly_basemul_montgomery(a: list[int], b: list[int]) -> list[int]:
    if len(a) != N or len(b) != N:
        raise ValueError("Kyber basemul expects 256-coefficient inputs")

    r = [0] * N
    for i in range(N // 4):
        zeta = ZETAS[64 + i]

        a0, a1 = _to_centered(a[4 * i]), _to_centered(a[4 * i + 1])
        b0, b1 = _to_centered(b[4 * i]), _to_centered(b[4 * i + 1])
        r0 = fqmul(a1, b1)
        r0 = fqmul(r0, zeta)
        r0 = _to_centered(r0 + fqmul(a0, b0))
        r1 = _to_centered(fqmul(a0, b1) + fqmul(a1, b0))
        r[4 * i] = to_standard(r0)
        r[4 * i + 1] = to_standard(r1)

        a2, a3 = _to_centered(a[4 * i + 2]), _to_centered(a[4 * i + 3])
        b2, b3 = _to_centered(b[4 * i + 2]), _to_centered(b[4 * i + 3])
        r2 = fqmul(a3, b3)
        r2 = fqmul(r2, -zeta)
        r2 = _to_centered(r2 + fqmul(a2, b2))
        r3 = _to_centered(fqmul(a2, b3) + fqmul(a3, b2))
        r[4 * i + 2] = to_standard(r2)
        r[4 * i + 3] = to_standard(r3)

    return r
