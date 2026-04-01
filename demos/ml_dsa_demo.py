"""ML-DSA end-to-end demo (keygen/sign/verify)."""

from src.core import serialization
from src.schemes.ml_dsa.keygen import ml_dsa_keygen
from src.schemes.ml_dsa.sign import ml_dsa_sign
from src.schemes.ml_dsa.verify import ml_dsa_verify


def main() -> None:
    params = "ML-DSA-87"
    message = b"libPQC ML-DSA demo"

    # 1) Generate verification/signing keys.
    vk, sk = ml_dsa_keygen(params, aseed=b"demo-ml-dsa-aseed")

    # 2) Sign message with deterministic random seed for reproducibility.
    sig = ml_dsa_sign(message, sk, params=params, rnd=b"demo-ml-dsa-rnd-seed")

    # 3) Verify valid and tampered cases.
    ok_valid = ml_dsa_verify(message, sig, vk, params=params)
    ok_tampered_msg = ml_dsa_verify(message + b"!", sig, vk, params=params)

    sig_obj = serialization.from_bytes(sig)
    sig_obj["c_tilde"] = "00" + sig_obj["c_tilde"][2:]
    tampered_sig = serialization.to_bytes(sig_obj)
    ok_tampered_sig = ml_dsa_verify(message, tampered_sig, vk, params=params)

    print("Params:", params)
    print("Verification key bytes:", len(vk))
    print("Signing key bytes:", len(sk))
    print("Signature bytes:", len(sig))
    print("Verify(valid):", ok_valid)
    print("Verify(tampered message):", ok_tampered_msg)
    print("Verify(tampered signature):", ok_tampered_sig)


if __name__ == "__main__":
    main()
