# Performance Analysis & Benchmarks

**Document**: Performance characteristics and optimization analysis
**Purpose**: Establish baseline performance and identify optimization opportunities
**Audience**: Implementers, performance engineers, researchers

---

## Table of Contents

1. [Baseline Metrics](#baseline-metrics)
2. [Operation Costs](#operation-costs)
3. [Optimization Opportunities](#optimization-opportunities)
4. [Comparison with Reference Implementations](#comparison-with-reference-implementations)
5. [Bottleneck Analysis](#bottleneck-analysis)

---

## Baseline Metrics

### Status: No Profiling Data Collected

**Note**: Benchmarking has not yet been performed on this implementation. The following sections document the framework for profiling, with example metrics from reference implementations for comparison.

### Expected Performance (Based on Reference Implementations)

For reference, Kyber and Dilithium reference implementations typically achieve:

#### ML-KEM Operations (estimated)

| Operation | Cycles | Platform | Notes |
|---|---|---|---|
| KeyGen | ~40,000 | x86-64 | Based on Kyber reference; libPQC uses NTT (likely similar) |
| Encaps | ~25,000 | x86-64 | Dominated by NTT + sampling |
| Decaps | ~30,000 | x86-64 | Inverse operations + decompression |

#### ML-DSA Operations (estimated)

| Operation | Cycles | Platform | Notes |
|---|---|---|---|
| KeyGen | ~60,000 | x86-64 | Based on Dilithium reference |
| Sign | ~50,000 | x86-64 | Includes rejection sampling (~1-2 iterations) |
| Verify | ~30,000 | x86-64 | Single matrix multiply + hash |

**Important**: libPQC is a pure Python implementation with optional C extensions. Absolute cycle counts will be 10-100× slower than C implementations. Relative performance should be similar if NTT and sampling are optimized.

---

## Operation Costs

### Memory Footprint

#### ML-KEM-768

| Component | Size | Rationale |
|---|---|---|
| Public key `pk` | 1,184 bytes | ρ (32) + t_1 compressed (1,152) |
| Secret key `sk` | 2,400 bytes | Full expanded key materials |
| Ciphertext | 1,088 bytes | Compressed u + v |
| Ephemeral (KeyGen) | ~50 KB | Intermediate matrices, A matrix |
| Ephemeral (Encaps) | ~30 KB | y, u, v during encapsulation |
| **Stack/Heap** | Low | Suitable for embedded devices |

#### ML-DSA-65

| Component | Size | Rationale |
|---|---|---|
| Public key `pk` | 1,952 bytes | ρ + t_1 compressed |
| Secret key `sk` | 4,000 bytes | All coefficients + tr, K |
| Signature | 3,309 bytes | z + c̃ (redundancy intentional) |
| Ephemeral (KeyGen) | ~80 KB | Larger matrix + more vectors |
| Ephemeral (Sign) | ~40 KB | A, y, w, etc. |
| **Stack/Heap** | Low | Suitable for embedded devices |

### Cache Considerations

**L1 Cache (32KB)**:
- Polynomial: 256 × 4 bytes = 1 KB (fits easily)
- Matrix row (3 polynomials): ~3 KB (fits in L1)

**L3 Cache (8-20 MB)**:
- Full matrix (6×6 of polynomials): ~400 KB
- All supporting data: <1 MB

**Implication**: Cache misses are not a primary concern for small operations.

---

## Optimization Opportunities

### High-Priority

1. **NTT Butterfly Unrolling**
   - Current: Software loop
   - Optimization: Unroll 2-4 butterflies per iteration
   - Expected speedup: 15-20%
   - Complexity: Medium

2. **Vectorization (SIMD)**
   - Use AVX2/AVX-512 for point-wise operations
   - 256-bit registers → process 4 coefficients simultaneously (for 64-bit arithmetic)
   - Expected speedup: 3-4×
   - Complexity: High (requires portable abstractions)

3. **Precomputed NTT Weights**
   - Cache $\zeta^{2^k}$ values instead of computing on-the-fly
   - Memory trade-off: +256 × 8 bytes = 2 KB per variation
   - Expected speedup: 10-15%
   - Complexity: Low

### Medium-Priority

4. **Karatsuba Multiplication**
   - Replace naive $O(n^2)$ with $O(n^{1.58})$ in coefficient domain
   - Useful for 512-dimension vectors
   - Expected speedup: 30-40% if coefficient domain ever used
   - Complexity: Medium
   - **Note**: NTT already faster for n=256, so limited benefit

5. **Rejection Sampling Vectorization (ML-DSA)**
   - Batch multiple norm checks
   - Expected speedup: 20-30%
   - Complexity: Low

### Low-Priority (Research-Level)

6. **Specialized Hash Extension**
   - Custom SHAKE256 optimized for our fixed input lengths
   - Expected speedup: 5-10%
   - Complexity: High, diminishing returns

7. **GPU Acceleration**
   - For high-volume operations (e.g., batch verification)
   - Expected speedup: 10-100× (context dependent)
   - Complexity: Very high, platform specific

---

## Comparison with Reference Implementations

### Performance Comparison Methodology

When benchmarking libPQC, compare against:
- **Kyber reference implementation** (C, pure)
- **liboqs** (C, optimized)
- **libpqc** (C, optimized by PQCryptography)

**Expected pattern**:
- libPQC (Python) ≈ 10-100× slower than C implementations
- Overhead comes from bytecode interpretation, not algorithmic differences
- Relative time distribution should be similar (same algorithmic complexity)

---

## Bottleneck Analysis

### About This Section

The following describes expected bottlenecks **based on algorithm analysis**, not measured data. Until `py-spy` or `cProfile` runs are available, these are educated guesses. See [Profiling Methodology](#bottleneck-analysis) for how to gather real data.

#### KeyGen
1. **NTT**: ~40% (forward transforms)
2. **Sampling**: ~30% (ExpandA, CBD)
3. **Arithmetic**: ~20% (multiplication, modular reduction)
4. **Memory**: ~10% (cache misses, bandwidth)

#### Encaps
1. **Matrix multiply**: ~50% (A^T · y)
2. **NTT**: ~30%
3. **Hash/Compression**: ~15%
4. **Misc**: ~5%

#### Sign
1. **Matrix multiply**: ~35%
2. **Rejection sampling**: ~30% (loop & norms)
3. **Hash**: ~15%
4. **NTT**: ~15%
5. **Arithmetic**: ~5%

#### Verify
1. **Matrix multiply**: ~60%
2. **NTT**: ~25%
3. **Hash/Compare**: ~15%

---

## Recommendations for Profiling & Optimization

### Phase 1: Baseline Profiling (Before optimization)

To establish what the actual bottlenecks are:

```bash
 # Deterministic benchmarks for the main operations
 python3 scratch.py benchmark ml-kem keygen --iterations 25
 python3 scratch.py benchmark ml-kem encaps --iterations 25
 python3 scratch.py benchmark ml-kem decaps --iterations 25
 python3 scratch.py benchmark ml-dsa sign --iterations 25
 python3 scratch.py benchmark ml-dsa verify --iterations 25
 python3 scratch.py benchmark core poly-mul --iterations 25

 # Python profiling with cProfile
 python3 scratch.py profile ml-kem keygen --iterations 1 --limit 20
 python3 scratch.py profile ml-dsa sign --iterations 1 --limit 20
 python3 scratch.py profile core poly-mul --iterations 1 --limit 20

# Visualize with snakeviz
pip install snakeviz
snakeviz libpqc_profile.txt
```

**Goals for Phase 1**:
- [ ] Measure actual time for each demo operation (KeyGen, Encaps, Sign, Verify)
- [ ] Identify which operations consume most time (NTT? Sampling? Arithmetic?)
- [ ] Measure wall-clock time for all 6 demos in `scratch.py`
- [ ] Compare relative time spending (e.g., NTT vs sampling ratio)

### Phase 2: Optimization (If needed for portfolio)

Low-hanging fruit if profiling reveals them:
- [ ] Profile current NTT implementation to identify innermost loops
- [ ] Implement NTT weight precomputation (if not already done)
- [ ] Unroll NTT butterfly operations (minor speedup from loop overhead)
- [ ] Profile polynomial multiplication (check if NTT is actually fastest choice)

### Phase 3: Research Optimizations (Beyond MVP)

Higher-complexity optimizations (likely beyond PhD scope):
- [ ] SIMD vectorization (AVX2 for batch operations)
- [ ] Batch verification infrastructure
- [ ] Karatsuba variant (if coefficient domain ever used)

---

**Note**: Profiling is most valuable AFTER implementing correct algorithms. The current focus is on demonstrating security analysis and correct implementations; performance optimization comes later.

---

## Target Performance Goals

### Research Implementation (libPQC - Python)

**Current Focus**: Correctness & clarity, not performance optimization.

**Acceptable ranges** (for research portfolio):
- ML-KEM-768 KeyGen: < 5 seconds
- ML-KEM-768 Encaps: < 1 second
- ML-DSA-65 Sign: < 2 seconds
- ML-DSA-65 Verify: < 1 second

**Rationale**: Python overhead dominates; algorithmic efficiency is verified through NTT implementation & no unnecessary loops. Production C implementations will be 10-100× faster with same algorithms.

### Production Implementation (C/Rust target)

**Target performance** (if optimized to C):
- ML-KEM-768 KeyGen: < 50ms
- ML-KEM-768 Encaps: < 10ms
- ML-DSA-65 Sign: < 20ms
- ML-DSA-65 Verify: < 10ms

**Note**: These are based on libOQS reference implementations; libPQC does not currently target production-level performance.

---

**Document Version**: 1.0 (Draft)
**Last Updated**: 2026
**Data Status**: Benchmarks to be populated after profiling
