"""Top-level demo runner for libPQC first-release flows."""

from demos.ml_dsa_demo import main as ml_dsa_demo
from demos.ml_kem_demo import main as ml_kem_demo


def main() -> None:
    print("=== libPQC Demo Runner ===")
    print()

    print("--- ML-KEM Demo ---")
    ml_kem_demo()
    print()

    print("--- ML-DSA Demo ---")
    ml_dsa_demo()


if __name__ == "__main__":
    main()
