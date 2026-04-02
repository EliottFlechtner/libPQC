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

### Key Operations (Target Platform: x86-64 @ 1-3 GHz)

#### ML-KEM Operations

| Operation | Time (ms) | Notes |
|---|---|---|
| KeyGen | TBD | Includes matrix sampling, error generation, NTT |
| Encaps | TBD | Matrix-vector multiply, compression |
| Decaps | TBD | Inverse operations, decompression |

#### ML-DSA Operations

| Operation | Time (ms) | Notes |
|---|---|---|
| KeyGen | TBD | Similar to ML-KEM + PowerRound |
| Sign | TBD | Dominated by rejection sampling (1-2 iterations typical) |
| Verify | TBD | Single matrix multiply |

### Cycle Counts by Component

#### NTT (256 coefficients)

```
Forward NTT:  ~5,000 - 10,000 cycles
Inverse NTT:  ~5,000 - 10,000 cycles
Point multiply: ~100 - 200 cycles per point
```

#### Polynomial Multiplication

```
Coefficient domain: ~65,536 multiplies (256²) → impractical
NTT-based: 256 point mults + 2×NTT → ~20,000 - 30,000 cycles
Karatsuba variant: TBD (if implemented)
```

#### Sampling

```
CBD_η1: ~1,000 - 2,000 cycles (SHAKE256 + arithmetic)
SampleA: ~50,000+ cycles per matrix row (deterministic expansion)
```

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

### Benchmarks (Cycles, rounded)

**Reference**: libpqc vs Kyber official vs liboqs

| Operation | libPQC | Kyber Ref | liboqs | Notes |
|---|---|---|---|---|
| ML-KEM-768 KeyGen | TBD | ~40K | ~35K | Includes all setup |
| ML-KEM-768 Encaps | TBD | ~25K | ~24K | Per encapsulation |
| ML-KEM-768 Decaps | TBD | ~30K | ~28K | Per decapsulation |
| ML-DSA-65 KeyGen | TBD | ~60K | ~55K |  |
| ML-DSA-65 Sign | TBD | ~50K | ~45K | Includes rejection |
| ML-DSA-65 Verify | TBD | ~30K | ~28K | Rejection-free |

### Interpretation

- **Within ±20% of reference**: Acceptable (close to optimal)
- **20-50% slower**: Acceptable (minor optimizations available)
- **>50% slower**: Investigate (likely algorithmic issue)

---

## Bottleneck Analysis

### Profiling Methodology

```bash
# Run with CPU performance counter
perf stat -e cycles,instructions,L1-dcache-load-misses \
  python -m tests.integration.test_ml_kem

# For detailed flame graphs
py-spy record --rate 100 -d 5 -- python test_ml_kem.py
```

### Expected Bottlenecks (by operation)

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

## Recommendations for Optimization

### Phase 1 (Immediate, 15-20% speedup)
- [ ] Profile current implementation to identify actual bottlenecks
- [ ] Implement NTT weight precomputation
- [ ] Unroll NTT butterfly loops

### Phase 2 (Medium-term, 50-100% speedup)
- [ ] SIMD vectorization (AVX2)
- [ ] Optimize hash expansion (if separate bottleneck)
- [ ] Batch verification infrastructure

### Phase 3 (Long-term, 3-10× speedup)
- [ ] Consider specialized instruction sets (AVX-512, ARM NEON)
- [ ] GPU variants for bulk operations
- [ ] Hardware acceleration (ASIC/FPGA) for production

---

## Target Performance Goals

**Research Implementation**:
- ML-KEM-768 KeyGen: <200ms
- ML-KEM-768 Encaps: <50ms
- ML-DSA-65 Sign: <100ms
- ML-DSA-65 Verify: <50ms

**Production Implementation**:
- ML-KEM-768 KeyGen: <50ms
- ML-KEM-768 Encaps: <10ms
- ML-DSA-65 Sign: <20ms
- ML-DSA-65 Verify: <10ms

---

**Document Version**: 1.0 (Draft)
**Last Updated**: 2026
**Data Status**: Benchmarks to be populated after profiling
