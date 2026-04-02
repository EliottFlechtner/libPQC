# Conformance vectors

Place official NIST-style `.rsp` files here, grouped by scheme.

Expected layout:

- `tests/conformance/vectors/ml_kem/`
- `tests/conformance/vectors/ml_dsa/`

The KAT scaffolds in `tests/conformance/test_ml_kem_kat.py` and
`tests/conformance/test_ml_dsa_kat.py` will automatically skip until at least
one `.rsp` file exists in the corresponding scheme directory.
