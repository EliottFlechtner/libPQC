"""Quick Kyber-PKE encrypt/decrypt demo."""

from src.schemes.ml_kem.kyber_pke import (
    kyber_pke_decryption,
    kyber_pke_encryption,
    kyber_pke_keygen,
)


def main() -> None:
    params = "ML-KEM-768"

    # 1) Generate PKE keys
    public_key, secret_key = kyber_pke_keygen(params)

    # 2) Encrypt a 32-byte message (Kyber-PKE message size)
    message = b"0123456789abcdef0123456789abcdef"
    if len(message) != 32:
        raise ValueError("demo message must be exactly 32 bytes")

    ciphertext = kyber_pke_encryption(
        public_key,
        message,
        params=params,
        coins=b"abcdefghijklmnopqrstuvwx12345678",
    )

    # 3) Decrypt and verify
    recovered = kyber_pke_decryption(ciphertext, secret_key, params=params)

    print("Original:", message.hex())
    print("Recovered:", recovered.hex())
    print("Match:", recovered == message)
    print("Public key bytes:", len(public_key))
    print("Ciphertext bytes:", len(ciphertext))


if __name__ == "__main__":
    main()
