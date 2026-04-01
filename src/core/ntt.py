"""Number Theoretic Transform utilities for fast negacyclic polynomial multiplication.

The implementation is generic over moduli where:
- n is a power of two
- 2n divides (q - 1)

Under those conditions, negacyclic multiplication in Z_q[X]/(X^n + 1)
can be reduced to a cyclic NTT with a twiddle (psi) transform.
"""


def _is_power_of_two(value: int) -> bool:
    return value > 0 and (value & (value - 1)) == 0


def _pow_mod(base: int, exp: int, modulus: int) -> int:
    return pow(base, exp, modulus)


def _inv_mod(value: int, modulus: int) -> int:
    return pow(value, modulus - 2, modulus)


def _prime_factors(value: int) -> list[int]:
    factors = []
    n = value
    divisor = 2
    while divisor * divisor <= n:
        if n % divisor == 0:
            factors.append(divisor)
            while n % divisor == 0:
                n //= divisor
        divisor += 1
    if n > 1:
        factors.append(n)
    return factors


def _find_primitive_root(order: int, modulus: int) -> int:
    """Find an element of exact multiplicative order `order` in Z_modulus^*."""
    if (modulus - 1) % order != 0:
        raise ValueError("order must divide modulus - 1")

    factors = _prime_factors(order)
    for candidate in range(2, modulus):
        if _pow_mod(candidate, order, modulus) != 1:
            continue
        is_exact = True
        for prime_factor in factors:
            if _pow_mod(candidate, order // prime_factor, modulus) == 1:
                is_exact = False
                break
        if is_exact:
            return candidate

    raise ValueError("no primitive root found for requested order")


def supports_negacyclic_ntt(modulus: int, length: int) -> bool:
    """Return True when NTT-based negacyclic multiplication is supported."""
    if not isinstance(modulus, int) or not isinstance(length, int):
        return False
    if modulus <= 2 or length <= 0:
        return False
    if not _is_power_of_two(length):
        return False
    return (modulus - 1) % (2 * length) == 0


def _ntt(values: list[int], root: int, modulus: int) -> list[int]:
    n = len(values)
    if not _is_power_of_two(n):
        raise ValueError("NTT length must be a power of two")

    data = list(values)

    # Bit-reversed permutation.
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            data[i], data[j] = data[j], data[i]

    length = 2
    while length <= n:
        step = _pow_mod(root, n // length, modulus)
        half = length // 2
        for start in range(0, n, length):
            w = 1
            for offset in range(half):
                u = data[start + offset]
                v = (data[start + offset + half] * w) % modulus
                data[start + offset] = (u + v) % modulus
                data[start + offset + half] = (u - v) % modulus
                w = (w * step) % modulus
        length <<= 1

    return data


def _intt(values: list[int], root: int, modulus: int) -> list[int]:
    n = len(values)
    inv_root = _inv_mod(root, modulus)
    transformed = _ntt(values, inv_root, modulus)
    inv_n = _inv_mod(n, modulus)
    return [(value * inv_n) % modulus for value in transformed]


def negacyclic_convolution_ntt(a: list[int], b: list[int], modulus: int) -> list[int]:
    """Compute (a * b) mod (X^n + 1, modulus) via NTT.

    Inputs must have equal length n.
    """
    if len(a) != len(b):
        raise ValueError("input vectors must have equal length")
    n = len(a)
    if not supports_negacyclic_ntt(modulus, n):
        raise ValueError("NTT not supported for given modulus and length")

    psi = _find_primitive_root(2 * n, modulus)
    omega = _pow_mod(psi, 2, modulus)

    a_twisted = [
        (a[i] % modulus) * _pow_mod(psi, i, modulus) % modulus for i in range(n)
    ]
    b_twisted = [
        (b[i] % modulus) * _pow_mod(psi, i, modulus) % modulus for i in range(n)
    ]

    a_ntt = _ntt(a_twisted, omega, modulus)
    b_ntt = _ntt(b_twisted, omega, modulus)
    c_ntt = [(a_ntt[i] * b_ntt[i]) % modulus for i in range(n)]
    c_twisted = _intt(c_ntt, omega, modulus)

    inv_psi = _inv_mod(psi, modulus)
    return [c_twisted[i] * _pow_mod(inv_psi, i, modulus) % modulus for i in range(n)]
