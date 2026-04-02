# ML-KEM & ML-DSA Architecture

**Document**: Technical architecture and implementation guide
**Purpose**: Crystal-clear scheme descriptions with mathematical notation
**Audience**: Implementers, researchers, code reviewers

---

## Table of Contents

1. [Ring Foreground](#ring-foreground)
2. [ML-KEM (Kyber) Architecture](#ml-kem-kyber-architecture)
3. [ML-DSA (Dilithium) Architecture](#ml-dsa-dilithium-architecture)
4. [Comparison](#comparison)
5. [Implementation Notes](#implementation-notes)

---

## Ring Foreground

### Polynomial Ring $\mathbb{Z}_q[X]/(X^n + 1)$

**Elements**: Polynomials of degree < $n$ with integer coefficients modulo $q$.

$$\mathbb{Z}_q[X]/(X^n + 1) = \left\{ \sum_{i=0}^{n-1} a_i X^i : a_i \in \mathbb{Z}_q \right\}$$

**Parameters**:
- $n = 256$ (polynomial degree)
- $q = 3329$ (ML-KEM) or $8380417$ (ML-DSA)
- $q \equiv 1 \pmod{2n}$ (enables NTT)

### NTT (Number Theoretic Transform)

**Purpose**: Fast polynomial multiplication via convolution theorem (similar to FFT).

**Representation**:
- **Coefficient domain**: standard polynomial representation
- **NTT domain**: evaluations at primitive $2n$-th roots of unity

**Operations**:
```
Coefficient domain:  a · b = c (slow, O(n²))
         ↓ NTT
NTT domain:          â · b̂ = ĉ (fast, O(n log n))
         ↓ INTT
Coefficient domain:  c = a · b (result)
```

**In libPQC**: Implemented via iterative NTT with bit-reversal.

### Centered Binomial Distribution

**Symbol**: $\chi_k$

**Definition**:
$$e \sim \chi_k : e = \sum_{i=1}^{k} (a_i - b_i) \text{ where } a_i, b_i \in \{0, 1\}$$

**Intuition**: Sum of $k$ independent bit differences (roughly Gaussian-like).

**Sampling**:
```python
def cbd(k, seed_bytes):
    stream = SHAKE256(seed, 136*k)  # Sample bytes
    for i in range(n):
        two_bits = extract_bits(stream, 2)  # Get 0-3
        a = two_bits & 1
        b = (two_bits >> 1) & 1
        e[i] = a - b  # -1, 0, or 1
    return e
```

---

## ML-KEM (Kyber) Architecture

### Overview

**Type**: Public-key encryption (KECapproach)
**Goal**: Establish shared secret between two parties
**Security**: IND-CCA2 via Fujisaki-Okamoto

### Parameter Sets

| Set | Module Dim | Poly Degree | Prime | Security |
|---|---|---|---|---|
| ML-KEM-512 | 2 | 256 | 3329 | 128-bit |
| ML-KEM-768 | 3 | 256 | 3329 | 192-bit |
| ML-KEM-1024 | 4 | 256 | 3329 | 256-bit |

### Key Generation

**Input**: Random seed (64 bytes)
**Output**: Public key $(d, \text{pk})$, Secret key (various)

```
Keygen(seed):
  1. (ρ, σ) := G(seed)           # Expand seed (256 + 256 bits)
  2. A ∈ R_q^(k×k) := SampleA(ρ) # Sample matrix from ρ
  3. For i = 1..k:
       s_i := CBD_η1(PRF(σ, i))   # Sample error vectors
       e_i := CBD_η1(PRF(σ, k+i))
  4. For i,j = 1..k:
       b_{i,j} := A_{i,j} * s_j + e_i  # Matrix-vector multiply in NTT
  5. t := NTT^{-1}(b)             # INTT to get t
  6. (t_1, t_d) := PowerRound(t)  # Decompose: t = 2^d * t_d + t_1
  7. return pk = (d || EncodeC(t_1)), sk = (sk_data)
```

**Key Size**:
- `pk`: 352 bytes (ML-KEM-512) to 1216 bytes (ML-KEM-1024)
- `sk`: 736 bytes to 2400 bytes

### Encapsulation

**Input**: Public key `pk`
**Output**: Ciphertext `ct` (352-1088 bytes), Shared secret `ss` (32 bytes)

```
Encaps(pk):
  1. Parse pk → (ρ, t_1)
  2. m := 32 random bytes
  3. (K̄, r) := G(H(m) || H(pk))  # Pseudorandom from message + PK
  4. A := SampleA(ρ)             # Public matrix
  5. For i = 1..k:
       y_i := CBD_η1(PRF(r, i))   # Sample y vector
  6. u := A^T * y + e_1           # u = A^T y + e_1 (NTT ops)
  7. v := t_1 * y + e_2 + Compress_q(m, 1)
  8. ct := Compress_u(u, du) || Compress_v(v, dv)  # Compress + encode
  9. ss := KDF(K̄, ct)            # Hash ciphertext for session key
  10. return (ct, ss)
```

### Decapsulation

**Input**: Ciphertext `ct`, Secret key `sk`
**Output**: Shared secret `ss` (32 bytes)

```
Decaps(ct, sk):
  1. Parse sk → (s₁, ..., s_k, ρ)
  2. Parse ct → (u', v')
  3. u := Decompress_u(u', du)
  4. v := Decompress_v(v', dv)
  5. m' := Decompress_1(v - u · s)  # m' = Decompress_1(v - <u, s>)
  6. (K̄', r') := G(H(m') || H(pk))
  7. ct' := Encaps_deterministic(pk, m', r')
  8. If ct == ct':                 # Verify ciphertext
       ss := KDF(K̄', ct)
   Else:
       ss := KDF(z, ct)  # z = random, appears random anyway
  9. return ss
```

**Decryption Failure**: Extremely rare (DF prob ≈ 2^-139).

### Compression/Decompression

**Purpose**: Reduce ciphertext size.

```
Compress_q(x, d):
  return ⌊ (2^d / q) · x ⌋

Decompress_d(y, d):
  return ⌊ (q / 2^d) · y ⌋
```

**Effect**: Quantizes values to d-bit precision, adds small error.

---

## ML-DSA (Dilithium) Architecture

### Overview

**Type**: Digital signature scheme
**Goal**: Sign messages with private key, verify with public key
**Security**: EUF-CMA via Fiat-Shamir

### Parameter Sets

| Set | Module Dim | Poly Degree | Prime | Security |
|---|---|---|---|---|
| ML-DSA-44 | 4 | 256 | 8380417 | 128-bit |
| ML-DSA-65 | 6 | 256 | 8380417 | 192-bit |
| ML-DSA-87 | 8 | 256 | 8380417 | 256-bit |

### Key Generation

```
Keygen(seed):
  1. (ρ, ρ', σ) := SplitSeed(seed)  # Expand 32→48 bytes
  2. A := SampleA(ρ)              # k×l matrix
  3. For i = 1..l:
       s_{1,i} := CBD_η1(PRF(σ, i))  # l vectors of error
     For i = 1..k:
       s_{2,i} := CBD_η2(PRF(σ, l+i)) # k vectors of error
  4. For i,j:
       t_{i,j} := A_{i,j} · s_{1,j} + s_{2,i}  # Matrix multiply
  5. (t_1, t_0) := PowerRound(t)           # Decompose
  6. tr := H(ρ || t_1)                     # Hash of public data
  7. return pk = ρ || t_1, sk = ρ || K || tr || s_1 || s_2 || t_0
```

**Key Sizes**:
- `pk`: 1312 bytes (ML-DSA-44) to 2560 bytes (ML-DSA-87)
- `sk`: 2544 bytes to 4864 bytes

### Signing

**Input**: Message `msg`, Secret key `sk`
**Output**: Signature `sig` (2420-4595 bytes)

```
Sign(msg, sk):
  1. Parse sk → (ρ, K, tr, s_1, s_2, t_0)
  2. A := SampleA(ρ)
  3. c̃ := H(dom2 || tr || msg)     # Challenge seed (deterministic)
  4. c := SampleInBall(c̃)          # Expand to binary polynomial (60 ones)
  5. nonce := 0
  6. Repeat:
       7. y := ExpandMask(K, nonce++)  # Random-like expansion
       8. w := A^T · y                  # NTT multiply
       9. w_1 := HighBits(w)            # Extract high bits
      10. c_hash := H(dom2 || w_1 || msg)  # Recompute commitment
      11. z := y + c · s_1             # Candidate signature
      12. If ‖z‖ > γ1 - β: continue   # Check bounds
      13. r_0 := LowBits(w - c · s_2)
      14. If ‖r_0‖ > γ2 - β: continue
      15. c_tz := c · t_0
      16. If ‖c_tz‖ > γ2: continue
  17. Until first valid z found
  18. return sig = z || c_z_tilde (compressed)
```

**Rejection Sampling**: Ensures signature leaks no information about secret.

### Verification

**Input**: Message `msg`, Signature `sig`, Public key `pk`
**Output**: Accept or Reject

```
Verify(msg, sig, pk):
  1. Parse pk → (ρ, t_1)
  2. Parse sig → (z, c̃)
  3. If ‖z‖ > γ1 - β: return ⊥   # Check norm
  4. A := SampleA(ρ)
  5. c := SampleInBall(c̃)
  6. w' := A^T · z - c · t_1      # Verify equation
  7. w'_1 := HighBits(w')
  8. If H(dom2 || w'_1 || msg) == c̃: return Accept
  9. Else: return ⊥
```

### High/Low Bit Decomposition

**Purpose**: Separate high bits (message-dependent) from low bits (noise).

```
w = 2^d · w_1 + w_0    where w_0 ∈ [-(2^(d-1)), 2^(d-1)]

HighBits(w) = w_1
LowBits(w) = w_0

UseHint(h, x):  # Apply hint from signer to verifier
  x' := HighBits(x)
  If h = 1:
    x' := (x' + 1) mod q
  return x'
```

---

## Comparison

| Feature | ML-KEM | ML-DSA |
|---|---|---|
| **Type** | Key Encapsulation | Digital Signature |
| **Assumption** | LWE (R-LWE) | LWE + SIS (R-LWE + R-SIS) |
| **Security Proof** | Fujisaki-Okamoto (CCA2) | Fiat-Shamir ROA (EUF-CMA) |
| **Message Encoding** | Compression (lossy) | Hash + SampleInBall (deterministic) |
| **Randomness** | Pseudorandom from message | Deterministic ExpandMask |
| **Typical Use** | Establish shared secret | Sign documents |
| **Ciphertext/Sig Size** | ~1000 bytes | ~2500 bytes |
| **Key Recovery** | Requires LWE solver | Requires LWE + SIS solver |

---

## Implementation Notes

### Memory Layout

**Polynomial Representation**:
```python
# Coefficient domain (libPQC internal)
poly = [a_0, a_1, ..., a_255]  # Coefficients, each < q

# NTT domain
poly_ntt = [â_0, â_1, ..., â_255]  # NTT evaluations
```

### NTT Considerations

1. **Dimension**: $n = 256 = 2^8$ (all operations are powers of 2)
2. **Root of unity**: $\zeta = 17$ is primitive 512-th root mod 3329 (for ML-KEM)
3. **Normalization**: INTT requires division by $n$ (implemented as multiplication by $n^{-1} \bmod q$)

### Module Representation

**ML-KEM k=3 (ML-KEM-768)**:
- Public matrix $A$: 3×3 matrix of polynomials (9 polys total)
- Secret vector $s$: 3 polynomials
- Key operations: 9 polynomial multiplications per operation

### Constant-Time Implementation

**Critical Functions**:
- `ntt()`, `intt()`: No branches on values
- `cbd()`: Fixed sampling from byte stream
- `mul()`: Polynomial multiplication (even if NTT-based, keep constant cycles)
- Comparisons: Use masks, not if/else

---

**Document Version**: 1.0
**Last Updated**: 2026