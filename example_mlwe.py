"""
Module Learning With Errors (MLWE) Example

Demonstrates the MLWE problem with concrete parameters:
- Ring: R_q = Z_541[X]/(X^4 + 1) (quotient polynomial ring)
- Matrix A ∈ R_q^(3×2) (3 rows, 2 columns)
- Secret vector s ∈ S_{η1}^2 (2 entries, each with inf_norm ≤ 3)
- Error vector e ∈ S_{η2}^3 (3 entries, each with inf_norm ≤ 2)
- Public vector t = A*s + e ∈ R_q^3

The MLWE problem: Given (A, t), determine s.
This is the hardness assumption underlying lattice-based cryptosystems.
"""

from src.integers import IntegersRing
from src.polynomials import QuotientPolynomialRing
from src.module import Module

print("=" * 80)
print("MODULE LEARNING WITH ERRORS (MLWE) EXAMPLE")
print("=" * 80)

# Parameters
q = 541
n = 4
k = 3  # number of rows in A
ell = 2  # number of columns in A (also dimension of secret vector s)
eta1 = 3  # bound for secret vector s
eta2 = 2  # bound for error vector e

print(f"\nParameters:")
print(f"  q (modulus) = {q}")
print(f"  n (polynomial degree) = {n}")
print(f"  Ring R_q = Z_{q}[X]/(X^{n} + 1)")
print(f"  Matrix A dimensions: {k} × {ell}")
print(f"  η1 (secret bound) = {eta1}")
print(f"  η2 (error bound) = {eta2}")

# Create the ring R_q = Z_541[X]/(X^4 + 1)
Z_q = IntegersRing(q)
R_q = QuotientPolynomialRing(Z_q, degree=n)
print(f"\nRing created: R_q = Z_{q}[X]/(X^{n}+1)")

# Create modules
M_cols = Module(R_q, rank=ell)  # R_q^ell for the columns of A and secret s
M_rows = Module(R_q, rank=k)  # R_q^k for the rows of results (A*s and e, t)

print(f"Module for vector s: R_q^{ell} = (Z_{q}[X]/(X^{n}+1))^{ell}")
print(f"Module for vector e, t: R_q^{k} = (Z_{q}[X]/(X^{n}+1))^{k}")

# ============================================================================
# Define the matrix A ∈ R_q^(k×ℓ)
# ============================================================================
print("\n" + "=" * 80)
print("MATRIX A (k × ℓ = 3 × 2)")
print("=" * 80)

# Matrix A is represented as a list of row vectors
# Each row is a ModuleElement in R_q^2
A_rows = [
    M_cols.element(
        [
            R_q.polynomial([442, 502, 513, 15]),  # 442 + 502x + 513x^2 + 15x^3
            R_q.polynomial([368, 166, 37, 135]),  # 368 + 166x + 37x^2 + 135x^3
        ]
    ),
    M_cols.element(
        [
            R_q.polynomial([479, 532, 116, 41]),  # 479 + 532x + 116x^2 + 41x^3
            R_q.polynomial([12, 139, 385, 409]),  # 12 + 139x + 385x^2 + 409x^3
        ]
    ),
    M_cols.element(
        [
            R_q.polynomial([29, 394, 503, 389]),  # 29 + 394x + 503x^2 + 389x^3
            R_q.polynomial([9, 499, 92, 254]),  # 9 + 499x + 92x^2 + 254x^3
        ]
    ),
]

print("\nMatrix A (as row vectors):")
for i, row in enumerate(A_rows):
    print(f"\n  A[{i}]:")
    for j, entry in enumerate(row.entries):
        print(f"    A[{i},{j}] = {entry}")

# ============================================================================
# Define the secret vector s ∈ S_{η1}^2
# ============================================================================
print("\n" + "=" * 80)
print(f"SECRET VECTOR s ∈ S_{{{eta1}}}^{ell}")
print("=" * 80)

s = M_cols.element(
    [
        R_q.polynomial([2, -2, 0, 1]),  # 2 - 2x + x^3
        R_q.polynomial([3, -2, -2, -2]),  # 3 - 2x - 2x^2 - 2x^3
    ]
)

print(f"\nSecret vector s (dimension {ell}):")
for i, entry in enumerate(s.entries):
    print(f"  s[{i}] = {entry}")

# Verify s is small (belongs to S_{η1})
s_norm = s.inf_norm()
print(f"\n  ||s||_∞ = {s_norm}")
print(f"  s ∈ S_{{{eta1}}}? {s.is_small(eta1)} (norm {s_norm} ≤ {eta1})")

# ============================================================================
# Define the error vector e ∈ S_{η2}^3
# ============================================================================
print("\n" + "=" * 80)
print(f"ERROR VECTOR e ∈ S_{{{eta2}}}^{k}")
print("=" * 80)

e = M_rows.element(
    [
        R_q.polynomial([2, -2, -1, 0]),  # 2 - 2x - x^2
        R_q.polynomial([1, 2, 2, 1]),  # 1 + 2x + 2x^2 + x^3
        R_q.polynomial([-2, 0, -1, -2]),  # -2 - x^2 - 2x^3
    ]
)

print(f"\nError vector e (dimension {k}):")
for i, entry in enumerate(e.entries):
    print(f"  e[{i}] = {entry}")

# Verify e is small (belongs to S_{η2})
e_norm = e.inf_norm()
print(f"\n  ||e||_∞ = {e_norm}")
print(f"  e ∈ S_{{{eta2}}}? {e.is_small(eta2)} (norm {e_norm} ≤ {eta2})")

# ============================================================================
# Compute t = A*s + e
# ============================================================================
print("\n" + "=" * 80)
print("MATRIX-VECTOR MULTIPLICATION: t = A*s + e")
print("=" * 80)

# Compute t = A*s + e
# A*s is computed by taking the inner product of each row of A with s
A_times_s_entries = []
for i, A_row in enumerate(A_rows):
    # Inner product: A[i] · s
    As_i = A_row * s  # This uses the * operator which computes inner product
    A_times_s_entries.append(As_i)
    print(f"\nA[{i}] · s = {As_i}")

# Create the vector A*s
A_times_s = M_rows.element(A_times_s_entries)
print(f"\n||A*s||_∞ = {A_times_s.inf_norm()}")

# Compute t = A*s + e
t = A_times_s + e
print(f"\nComputing t = A*s + e:")
for i, t_i in enumerate(t.entries):
    print(f"  t[{i}] = {t_i}")

t_norm = t.inf_norm()
print(f"\n||t||_∞ = {t_norm}")

# ============================================================================
# Verify against expected result
# ============================================================================
print("\n" + "=" * 80)
print("VERIFICATION AGAINST EXPECTED VALUES")
print("=" * 80)

expected_t = [
    (30, 252, 401, 332),  # 30 + 252x + 401x^2 + 332x^3
    (247, 350, 259, 485),  # 247 + 350x + 259x^2 + 485x^3
    (534, 234, 137, 443),  # 534 + 234x + 137x^2 + 443x^3
]

print("\nExpected t:")
for i, (c0, c1, c2, c3) in enumerate(expected_t):
    print(f"  t[{i}] = {c0} + {c1}x + {c2}x^2 + {c3}x^3")

print("\nVerification:")
all_match = True
for i in range(k):
    computed = t.entries[i].coefficients
    expected = list(expected_t[i])

    # Pad to same length
    while len(computed) < len(expected):
        computed = computed + [0]
    while len(expected) < len(computed):
        expected = expected + [0]

    match = computed == expected
    all_match = all_match and match
    status = "✓" if match else "✗"
    print(f"  t[{i}]: {status}")
    if not match:
        print(f"    Computed: {list(t.entries[i].coefficients)}")
        print(f"    Expected: {expected}")

print(f"\nExpected ||t||_∞ = 259")
print(f"Computed ||t||_∞ = {t_norm}")
print(f"Norm match: {'✓' if t_norm == 259 else '✗'}")

# ============================================================================
# Summary and MLWE Problem
# ============================================================================
print("\n" + "=" * 80)
print("MLWE PROBLEM SUMMARY")
print("=" * 80)

print(f"\nGiven:")
print(f"  - Ring R_q = Z_{q}[X]/(X^{n}+1)")
print(f"  - Public matrix A ∈ R_q^({k}×{ell}) (shown above)")
print(f"  - Public vector t = A*s + e ∈ R_q^{k}")
for i, t_i in enumerate(t.entries):
    print(f"    t[{i}] = {t_i}")

print(f"\nChallenge:")
print(f"  Determine the secret vector s ∈ S_{eta1}^{ell} (if it exists)")

print(f"\nHardness Basis:")
print(f"  The MLWE problem is conjectured to be hard.")
print(
    f"  This hardness assumption underlies security of schemes like Kyber and Dilithium."
)

print(f"\nOur Knowledge (for verification only):")
print(f"  Secret: s ∈ S_{{{eta1}}}^{ell}")
for i, s_i in enumerate(s.entries):
    print(f"    s[{i}] = {s_i}")
print(f"  Error: e ∈ S_{{{eta2}}}^{k}")
for i, e_i in enumerate(e.entries):
    print(f"    e[{i}] = {e_i}")

print("\n" + "=" * 80)
print(
    "COMPUTATION VERIFICATION: ✓"
    if all_match and t_norm == 259
    else "COMPUTATION VERIFICATION: ✗"
)
print("=" * 80 + "\n")
