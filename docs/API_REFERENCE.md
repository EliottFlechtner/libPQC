# API Reference

This reference describes the primary public surfaces in libPQC.

## Parameter Presets

## ML-KEM

- `ML-KEM-512`
- `ML-KEM-768`
- `ML-KEM-1024`

Short aliases are accepted in some helpers (`"512"`, `"768"`, `"1024"`).

## ML-DSA

- `ML-DSA-44`
- `ML-DSA-65`
- `ML-DSA-87`

Short aliases are accepted in some helpers (`"44"`, `"65"`, `"87"`).

## ML-KEM API

Module: `src.schemes.ml_kem`

### `ml_kem_keygen(params, aseed=None, zseed=None) -> tuple[bytes, bytes]`

Generates KEM keys.

- Input:
  - `params`: preset name or explicit parameter dictionary
  - `aseed`: optional deterministic seed material
  - `zseed`: optional deterministic fallback seed (`32` bytes when provided)
- Output:
  - `ek`: encapsulation key payload bytes
  - `dk`: decapsulation key payload bytes

Raises:
- `ValueError` for unsupported presets or invalid deterministic seed shapes
- `TypeError` for invalid seed types

### `ml_kem_encaps(encapsulation_key, params, message=None) -> tuple[bytes, bytes]`

Encapsulates a shared key under an encapsulation key.

- Input:
  - `encapsulation_key`: bytes payload from `ml_kem_keygen`
  - `params`: preset name or explicit parameter dictionary
  - `message`: optional deterministic 32-byte message
- Output:
  - `shared_key`: 32-byte shared secret
  - `ciphertext`: serialized ciphertext payload bytes

Raises:
- `ValueError` for malformed payloads, missing fields, or invalid message length
- `TypeError` for invalid input types

### `ml_kem_decaps(ciphertext, decapsulation_key, params) -> bytes`

Decapsulates and returns the recovered shared key.

- Input:
  - `ciphertext`: bytes payload from `ml_kem_encaps`
  - `decapsulation_key`: bytes payload from `ml_kem_keygen`
  - `params`: preset name or explicit parameter dictionary
- Output:
  - `shared_key`: recovered 32-byte key (verified or fallback depending on path)

Raises:
- `ValueError` for malformed decapsulation key payloads
- `TypeError` for invalid input types

## ML-DSA API

Module: `src.schemes.ml_dsa`

### `ml_dsa_keygen(params="ML-DSA-87", aseed=None) -> tuple[bytes, bytes]`

Generates signature keys.

- Input:
  - `params`: preset name or explicit parameter dictionary
  - `aseed`: optional deterministic seed material
- Output:
  - `vk`: verification key payload bytes
  - `sk`: signing key payload bytes

Raises:
- `ValueError` for unsupported or incomplete parameter sets
- `TypeError` for invalid seed type

### `ml_dsa_sign(message, signing_key, params=None, rnd=None, max_iterations=64) -> bytes`

Signs a message.

- Input:
  - `message`: `bytes`, `bytearray`, or `str`
  - `signing_key`: key payload bytes from `ml_dsa_keygen`
  - `params`: optional override (defaults to key payload params)
  - `rnd`: optional signing randomness
  - `max_iterations`: rejection-sampling cap
- Output:
  - `signature`: serialized signature payload bytes

Raises:
- `ValueError` for malformed payloads, mismatched ranks/degrees, or invalid params
- `TypeError` for invalid message/key types
- `RuntimeError` if an acceptable signature is not found within `max_iterations`

### `ml_dsa_verify(message, signature, verification_key, params=None) -> bool`

Verifies a signature.

- Input:
  - `message`: `bytes`, `bytearray`, or `str`
  - `signature`: payload bytes from `ml_dsa_sign`
  - `verification_key`: payload bytes from `ml_dsa_keygen`
  - `params`: optional override (defaults to key payload params)
- Output:
  - `True` if valid, `False` for invalid-but-well-formed signatures

Raises:
- `ValueError` for malformed payload structures and unrecoverable parameter mismatches
- `TypeError` for invalid input types

## CLI Reference

Entry point:

```bash
python3 scratch.py
```

Top-level commands:

- `demo`
- `ml-kem`
- `ml-dsa`
- `benchmark`
- `profile`
- `interop`

## `interop` Command Family

### Export

- `interop export ml-kem keypair`
- `interop export ml-kem ciphertext`
- `interop export ml-kem test-vector`
- `interop export ml-dsa keypair`
- `interop export ml-dsa signature`
- `interop export ml-dsa test-vector`

Each export command supports `--output` to write JSON bundles.

### Import

- `interop import ml-kem keypair --input <path>`
- `interop import ml-kem ciphertext --input <path>`
- `interop import ml-kem test-vector --input <path>`
- `interop import ml-dsa keypair --input <path>`
- `interop import ml-dsa signature --input <path>`
- `interop import ml-dsa test-vector --input <path>`

Imports validate bundle schema and print normalized summaries.

## Interoperability Helper Module

Module: `src.app.interoperability`

Primary exports include:

- Document IO:
  - `dump_document(document, output=None)`
  - `load_document(source)`
- Artifact export:
  - `export_ml_kem_keypair(...)`
  - `export_ml_kem_ciphertext(...)`
  - `export_ml_dsa_keypair(...)`
  - `export_ml_dsa_signature(...)`
- Test-vector export/import:
  - `export_ml_kem_test_vector(...)`
  - `import_ml_kem_test_vector(...)`
  - `export_ml_dsa_test_vector(...)`
  - `import_ml_dsa_test_vector(...)`
- Packed encodings for standards-focused workflows:
  - `ml_kem_rsp_public_key_bytes(...)`
  - `ml_kem_rsp_secret_key_bytes(...)`
  - `ml_kem_rsp_ciphertext_bytes(...)`
  - `ml_dsa_rsp_verification_key_bytes(...)`
  - `ml_dsa_rsp_signing_key_bytes(...)`
  - `ml_dsa_rsp_signature_bytes(...)`

These helpers emit both libPQC JSON payloads and packed RSP hex in exported bundles.
