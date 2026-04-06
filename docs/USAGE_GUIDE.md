# Usage Guide

This guide focuses on practical usage of libPQC from Python and the CLI.
If you want implementation details, see `docs/ARCHITECTURE.md`.

## Who This Is For

- Developers integrating ML-KEM key exchange
- Developers integrating ML-DSA signing and verification
- Engineers building conformance or interoperability tooling around JSON/RSP encodings

## Install and Run

Use a local virtual environment and run from the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -U pip
```

Run demo flows:

```bash
python3 scratch.py
python3 scratch.py demo ml-kem
python3 scratch.py demo ml-dsa
```

## Python: ML-KEM

### Key Generation

```python
from src.schemes.ml_kem.keygen import ml_kem_keygen

ek, dk = ml_kem_keygen("ML-KEM-768")
```

- `ek`: encapsulation key payload bytes
- `dk`: decapsulation key payload bytes

Deterministic mode for reproducible tests:

```python
ek, dk = ml_kem_keygen("ML-KEM-768", aseed=b"seed-material", zseed=b"z" * 32)
```

### Encapsulate and Decapsulate

```python
from src.schemes.ml_kem.encaps import ml_kem_encaps
from src.schemes.ml_kem.decaps import ml_kem_decaps

shared_bob, ciphertext = ml_kem_encaps(ek, params="ML-KEM-768")
shared_alice = ml_kem_decaps(ciphertext, dk, params="ML-KEM-768")
assert shared_bob == shared_alice
```

Notes:
- If you pass `message`, it must be exactly 32 bytes.
- Use matching parameter sets end-to-end.

## Python: ML-DSA

### Key Generation

```python
from src.schemes.ml_dsa.keygen import ml_dsa_keygen

vk, sk = ml_dsa_keygen("ML-DSA-87")
```

Deterministic mode:

```python
vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"seed-material")
```

### Sign and Verify

```python
from src.schemes.ml_dsa.sign import ml_dsa_sign
from src.schemes.ml_dsa.verify import ml_dsa_verify

message = b"hello"
signature = ml_dsa_sign(message, sk, params="ML-DSA-87", rnd=b"r" * 32)
assert ml_dsa_verify(message, signature, vk, params="ML-DSA-87")
```

Notes:
- `message` can be `bytes` or `str`.
- For deterministic signatures in tests, provide `rnd`.
- Keep parameter set consistency between keygen, sign, and verify.

## CLI Workflows

## ML-KEM CLI

```bash
python3 scratch.py ml-kem keygen --params ML-KEM-768
python3 scratch.py ml-kem encaps --params ML-KEM-768 --ek-hex <ek_hex>
python3 scratch.py ml-kem decaps --params ML-KEM-768 --dk-hex <dk_hex> --ciphertext-hex <ct_hex>
```

## ML-DSA CLI

```bash
python3 scratch.py ml-dsa keygen --params ML-DSA-87
python3 scratch.py ml-dsa sign --params ML-DSA-87 --sk-hex <sk_hex> --message "hello"
python3 scratch.py ml-dsa verify --params ML-DSA-87 --vk-hex <vk_hex> --sig-hex <sig_hex> --message "hello"
```

## Interoperability CLI

Export keypairs/artifacts/test-vectors as JSON bundles:

```bash
python3 scratch.py interop export ml-kem keypair --params ML-KEM-768 --output ml_kem_keypair.json
python3 scratch.py interop export ml-kem test-vector --params ML-KEM-768 --output ml_kem_vector.json
python3 scratch.py interop export ml-dsa test-vector --params ML-DSA-87 --output ml_dsa_vector.json
```

Import bundles and print normalized summaries:

```bash
python3 scratch.py interop import ml-kem keypair --input ml_kem_keypair.json
python3 scratch.py interop import ml-kem test-vector --input ml_kem_vector.json
python3 scratch.py interop import ml-dsa test-vector --input ml_dsa_vector.json
```

## Performance Commands

```bash
python3 scratch.py benchmark ml-kem keygen --iterations 25
python3 scratch.py benchmark core poly-mul --iterations 25
python3 scratch.py profile ml-dsa sign --iterations 1 --limit 20
```

See `docs/PERFORMANCE.md` for interpretation guidance.

## Failure Modes and Validation

libPQC deliberately validates payload structure and rejects malformed input.
Recommended integration checks:

- Reject unexpected payload `type` values.
- Reject malformed hex fields in key/signature payloads.
- Reject or treat as invalid cross-parameter flows (e.g., ML-DSA-44 artifacts used as ML-DSA-87).
- Keep deterministic seed material and signing randomness separated by context.

## Testing While Integrating

Run high-signal scheme tests (including negative cases):

```bash
python3 -m unittest discover -s tests/schemes -p 'test_*.py'
```

Run conformance vectors:

```bash
python3 -m unittest tests/conformance/test_ml_kem_kat.py tests/conformance/test_ml_dsa_kat.py
```
