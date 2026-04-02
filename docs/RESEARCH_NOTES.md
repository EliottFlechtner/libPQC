# Research Notes & Design Decisions

**Document**: Design rationale, alternatives considered, and lessons learned
**Purpose**: Capture engineering decisions for future maintainers
**Audience**: Developers, researchers, future contributors

---

## Table of Contents

1. [Architecture Decisions](#architecture-decisions)
2. [Security-Critical Choices](#security-critical-choices)
3. [Implementation Tradeoffs](#implementation-tradeoffs)
4. [Lessons Learned](#lessons-learned)
5. [Open Questions](#open-questions)

---

## Architecture Decisions

### 1. Python for Reference Implementation

**Decision**: Use Python (with optional C extensions for performance-critical paths).

**Rationale**:
- ✅ Readability and maintainability for research/education
- ✅ Rapid prototyping and testing
- ✅ Easy to integrate academic libraries (scipy, numpy, sympy)
- ❌ Performance not competitive with C/Rust
- ❌ Deployment limited to Python environments

**Alternatives Considered**:
1. **C/C++ (Kyber reference)**: Faster, but steeper learning curve; chose Python for clarity
2. **Rust**: Good safety, but less mature PQC ecosystem; reconsidered post-MVP
3. **Go**: Reasonable middle ground; not chosen due to team preference

**Decision Impact**:
- ✅ Portfolio demonstrates deep understanding of algorithms (not just using library)
- ⚠️ Performance not a primary metric (acceptable for research)
- ✅ Easier to audit for side-channel-free properties (fewer implicit optimizations)

### 2. NTT as Primary Polynomial Multiplication

**Decision**: Use Number Theoretic Transform (NTT) for all polynomial products.

**Rationale**:
- ✅ $O(n \log n)$ complexity for $n=256$ (38,400 vs 65,536 multiplications)
- ✅ Aligns with NIST spec (official Kyber/Dilithium uses NTT)
- ✅ Enables generic polynomial ring abstraction
- ❌ Requires careful implementation of reduction modulo $q$

**Alternatives**:
1. **Karatsuba**: $O(n^{1.58})$ ≈ 15,000 ops for $n=256$
   - Faster than coefficient domain, but still slower than NTT
   - Used in some optimized implementations

2. **FFT-based (not applicable)**: Requires floating-point, unsuitable for exact arithmetic

**Decision Impact**:
- ✅ Implements state-of-the-art polynomial arithmetic
- ✅ Matches industry standard (liboqs, libpqc, etc.)
- ⚠️ Higher cognitive load for understanding implementation

### 3. Rijndael S-Box vs. Custom Pseudorandom Expansion

**Decision**: Use SHAKE256 for all randomness (no AES-based constructs).

**Rationale**:
- ✅ SHAKE256 is quantum-safe (no cryptanalytic weakness known)
- ✅ Matches NIST FIPS 203/204 specification exactly
- ✅ Single cryptographic primitive for all operations
- ❌ Slightly slower than AES-based PRFs on some platforms

**Alternatives**:
1. **AES-CTR**: Faster, but less aligned with post-quantum ethos
2. **ChaCha20**: Reasonable alternative, but SHAKE256 is NIST standard

**Decision Impact**:
- ✅ No risk of accidentally breaking specifications
- ✅ Easier to verify against NIST test vectors
- ⚠️ Slightly lower performance (acceptable for research)

---

## Security-Critical Choices

### 1. Constant-Time Implementation

**Decision**: Attempt constant-time operations for all secret-dependent code.

**Details**:
```python
# ❌ NOT CONSTANT TIME:
def bad_compare(secret, value):
    if secret == value:      # Branch depends on secret!
        return True
    return False

# ✅ CONSTANT TIME:
def good_compare(secret, value):
    diff = secret ^ value
    result = 0
    for byte in diff:
        result |= byte      # Bitwise ops, no branches
    return result == 0
```

**Trade-off**:
- ✅ Prevents timing side-channels (fundamental defense)
- ❌ Slower (eliminate branch optimization)
- ⚠️ Hard to verify (requires code inspection + testing)

**Verification Method**:
- Static analysis: No `if/elif/else` on secret data
- Timing simulation: Tools like `valgrind --tool=cachegrind`
- Real hardware: ChipWhisperer or oscilloscope (if available)

### 2. Deterministic Message Encoding (ML-DSA)

**Decision**: Use deterministic ExpandMask for signature randomness (no random nonce).

**Rationale**:
- ✅ Eliminates risk of nonce reuse (ECDSA disaster)
- ✅ Matches NIST Dilithium standard
- ✅ Deterministic makes implementation easier to test
- ❌ Slightly less randomness diversity (but cryptographically sufficient)

**Implication**:
- Same message + same private key → **same signature**
- This is actually desirable for reproducibility
- ✅ Enables deterministic signing in some contexts

### 3. Rejection Sampling Bounds

**Decision**: Carefully tune rejection bounds to ensure statistical uniformity.

**Parameters** (ML-DSA-65):
- $\gamma_1 = 2^{19}$: Mask range size
- $\gamma_2 = 261888$: High bits threshold
- $\omega = 55$: Maximum hint bits

**Design Goal**:
- Ensure $\text{Pr}[\text{abort}]$ is independent of message (< 1% typically)
- Prevent side-channel leakage from retry count

**Verification**:
- Statistical test: [Message setup] vs [Rejection statistics]
- Should be uncorrelated

---

## Implementation Tradeoffs

### 1. Modular Arithmetic: Fast vs. Correct

**Trade-off**: Speed vs clarity of reduction operations.

**Chosen Approach**: Explicit modular reduction after each operation.

```python
# Explicit (slower, clearer)
def mul_poly(a, b, q):
    product = [0] * 256
    for i in range(256):
        for j in range(256):
            idx = (i + j) % 256
            product[idx] = (product[idx] + a[i] * b[j]) % q
    return product

# Optimized (faster, less clear)
def mul_poly_ntt(a, b, q):
    a_ntt = ntt(a, q)
    b_ntt = ntt(b, q)
    c_ntt = [a_ntt[i] * b_ntt[i] % q for i in range(256)]
    return intt(c_ntt, q)
```

**Decision**: Use NTT (optimized) but keep coefficient operations explicit (readable).

### 2. Parameter Storage: Hardcoding vs. Dynamic

**Decision**: Hardcode NIST-defined parameters, don't allow runtime variation.

**Rationale**:
- ✅ Prevents accidental misuse (e.g., using wrong q)
- ✅ Simplifies testing (single code path per scheme)
- ❌ Less flexible for experimentation

**Code Structure**:
```python
ML_KEM_PARAMS = {
    512: {"k": 2, "eta1": 3, "q": 3329, ...},
    768: {"k": 3, "eta1": 2, "q": 3329, ...},
    1024: {"k": 4, "eta1": 2, "q": 3329, ...},
}

# Not parameterizable: prevents mistakes
```

### 3. Error Distribution: Sampling vs. Precomputation

**Decision**: Sample errors on-the-fly using SHAKE256, no precomputed tables.

**Rationale**:
- ✅ No precomputation tables to cache-attack
- ✅ Matches NIST spec exactly
- ❌ Slightly slower (but negligible compared to NTT)

---

## Lessons Learned

### 1. Specification Compliance is Non-Negotiable

**Lesson**: Even small deviations from the NIST spec break KAT validation.

**Examples** (from our earlier work):
- **ML-KEM**: Using `G(d)` instead of `G(d || k_byte)` for keygen seed
- **ML-DSA**: Using `rehash_with_counter` instead of continuous SHAKE stream
- Both caused mismatches on official vectors

**Take-away**:
- Read spec carefully (multiple times)
- Implement exactly what's written, not what seems "reasonable"
- Test against NIST vectors early

### 2. Module Arithmetic Locality

**Lesson**: Ensure ModuleElements are rehydrated into local Module instance before combining.

**Problem**:
```python
# ❌ Wrong: payload.coeff() returns element from different Module
result = secret_poly * payload.coeff()

# ✅ Correct: rehydrate into local module
local_coeff = poly.module.lift(payload.get_coefficient_bytes())
result = secret_poly * local_coeff
```

**Why**: Python module instances are singleton-like; cross-module arithmetic silently fails.

### 3. NTT Normalization Details

**Lesson**: INTT requires careful handling of the normalization factor.

**Implementation**:
$$\text{INTT}(c) = n^{-1} \cdot \text{NTT}^{-1}(c) \pmod{q}$$

**Critical**: $n^{-1}$ computed as inverse of $n$ modulo $q$, NOT floating-point division!

```python
# ❌ Wrong
n_inv = 1.0 / 256

# ✅ Correct
n_inv = pow(256, -1, q)  # Modular inverse
```

### 4. Rejection Sampling Loop Termination

**Lesson**: Ensure rejection loop eventually terminates (bound aborting).

**ML-DSA implementation**:
```python
for nonce in range(256):  # Bounded loop
    y = expand_mask(seed, nonce)
    if good_signature(y, message):
        return signature
    # Loop counter prevents infinite loop

# After 256 attempts: cryptographically shouldn't happen, flag as error
```

---

## Open Questions

### 1. Side-Channel Resistance Beyond Theory

**Question**: How can we provide stronger side-channel assurances?

**Current State**:
- ✅ Constant-time code structure (visual inspection)
- ❌ No hardware testing (ChipWhisperer experiments needed)
- ❌ Compiler verification (does `-O3` introduce branches?)

**Future Work**:
- Acquire ChipWhisperer for timing/power analysis
- Test on multiple CPU architectures (x86, ARM, RISC-V)
- Use formal verification tools (e.g., Jasmin)

### 2. Lattice Attack Simulation Accuracy

**Question**: Do our cost models match state-of-the-art attack implementations?

**Current Models**:
- ✅ Conservative (likely overestimate actual attack cost)
- ⚠️ Based on theoretical complexity, not empirical data
- ❌ No validation against actual BKZ implementations (fplll, etc.)

**Next Steps**:
- Run actual BKZ on lattice instances of our dimension
- Compare empirical vs. theoretical costs
- Adjust cost models based on data

### 3. Quantum Security Estimates

**Question**: How reliable are our quantum gate count estimates?

**Current**: Using standard Grover model (√2^λ gates).

**Concerns**:
- Assumes perfect quantum computer (no error correction overhead)
- Error correction multiplier (1000-10000×) is speculative
- Fault-tolerant Shor's algorithm for lattices not yet solved

**Open Research**:
- Does quantum algorithm for LWE exist?
- What would be the gate complexity?

### 4. Implementation Variants

**Question**: Should we develop side-channel resistant variants?

**Options**:
1. **Masked arithmetic**: Share secrets, randomize computations
2. **Constant-time Karatsuba**: Alternative to NTT (constant circuit depth)
3. **Crandall primes**: Alternative modulus (if q = 2^k ± 1)

**Assessment**: Beyond PhD portfolio scope; defer to production implementations.

---

## References for Design

- Lyubashevsky et al., "CRYSTALS–Dilithium: A Lattice-Based Digital Signature Scheme"
- Bos et al., "CRYSTALS–Kyber: A CCA2-Secure Module-Lattice-Based KEM"
- NIST FIPS 203, FIPS 204 specifications
- Alkim et al., "The Lattice-Based Digital Signature Scheme qTESLA"

---

**Document Version**: 1.0
**Last Updated**: 2026
**Next Review**: Quarterly or after major architectural changes
