"""ML-KEM end-to-end demo (keygen/encaps/decaps)."""

from src.schemes.ml_kem.decaps import ml_kem_decaps
from src.schemes.ml_kem.encaps import ml_kem_encaps
from src.schemes.ml_kem.keygen import ml_kem_keygen


def main() -> None:
    params = "ML-KEM-768"

    # 1) Generate encapsulation and decapsulation keys.
    ek, dk = ml_kem_keygen(params, aseed=b"demo-ml-kem-aseed")

    # 2) Encapsulate a shared key to produce ciphertext.
    shared_encaps, ciphertext = ml_kem_encaps(
        ek,
        params=params,
        message=b"0123456789abcdef0123456789abcdef",
    )

    # 3) Decapsulate and verify key agreement.
    shared_decaps = ml_kem_decaps(ciphertext, dk, params=params)

    print("Params:", params)
    print("Encapsulation key bytes:", len(ek))
    print("Decapsulation key bytes:", len(dk))
    print("Ciphertext bytes:", len(ciphertext))
    print("Shared key length:", len(shared_encaps))
    print("Key agreement:", shared_encaps == shared_decaps)


if __name__ == "__main__":
    main()
