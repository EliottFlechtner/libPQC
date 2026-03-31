"""Quick ML-DSA keygen/sign/verify demo."""

from src.schemes.ml_dsa.keygen import ml_dsa_keygen
from src.schemes.ml_dsa.sign import ml_dsa_sign
from src.schemes.ml_dsa.verify import ml_dsa_verify
from src.core import serialization


def main() -> None:
    params = "ML-DSA-87"
    message = b"libPQC ML-DSA demo"

    # 1) Generate verification/signing keys.
    vk, sk = ml_dsa_keygen(params, aseed=b"demo-aseed-for-ml-dsa")

    # 2) Sign a message (rnd makes this deterministic for repeatable demo output).
    sig = ml_dsa_sign(message, sk, params=params, rnd=b"demo-rnd-seed-for-ml-dsa")

    # 3) Verify valid and tampered cases.
    ok_valid = ml_dsa_verify(message, sig, vk, params=params)
    ok_tampered_msg = ml_dsa_verify(message + b"!", sig, vk, params=params)

    # Tamper signature while keeping JSON structure valid.
    sig_obj = serialization.from_bytes(sig)
    sig_obj["c_tilde"] = "00" + sig_obj["c_tilde"][2:]
    tampered_sig = serialization.to_bytes(sig_obj)
    ok_tampered_sig = ml_dsa_verify(message, tampered_sig, vk, params=params)

    print("Params:", params)
    print("Message:", message)
    print("Verification key bytes:", len(vk))
    print("Signing key bytes:", len(sk))
    print("Signature bytes:", len(sig))
    print("Verify(valid):", ok_valid)
    print("Verify(tampered message):", ok_tampered_msg)
    print("Verify(tampered signature):", ok_tampered_sig)


if __name__ == "__main__":
    main()
