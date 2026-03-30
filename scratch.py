"""Quick ML-KEM keygen/encaps/decaps demo."""

from src.schemes.ml_kem.decaps import ml_kem_decaps
from src.schemes.ml_kem.encaps import ml_kem_encaps
from src.schemes.ml_kem.keygen import ml_kem_keygen


def main() -> None:
    params = "ML-KEM-768"

    # 1) Alice generates ML-KEM keys.
    ek, dk = ml_kem_keygen(params, aseed=b"demo-aseed-for-ml-kem")

    # 2) Bob encapsulates to Alice using ek.
    shared_key_bob, ciphertext = ml_kem_encaps(ek, params)

    # 3) Alice decapsulates using dk.
    shared_key_alice = ml_kem_decaps(ciphertext, dk, params)

    print("Shared key (Bob):   ", shared_key_bob.hex())
    print("Shared key (Alice): ", shared_key_alice.hex())
    print("Match:", shared_key_bob == shared_key_alice)
    print("Encapsulation key bytes:", len(ek))
    print("Ciphertext bytes:", len(ciphertext))


if __name__ == "__main__":
    main()
