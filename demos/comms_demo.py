"""Communication protocol demos for ML-KEM/ML-DSA workflows."""

from src.comms.protocols import run_key_agreement_batch


def _print_result(title: str, payload: dict[str, object]) -> None:
    print(f"\n{title}")
    print("-" * len(title))
    print("Channel:", payload["channel"])
    print("Runs:", payload["runs"])
    print("Server authenticated:", payload["authenticate_server"])
    print("Successes:", payload["successes"])
    print("Failures:", payload["failures"])

    first = payload["results"][0]
    print("Client phase:", first["client_phase"])
    print("Server phase:", first["server_phase"])
    print("Application keys match:", first["application_keys_match"])
    if first["error"]:
        print("Error:", first["error"])


def main() -> None:
    """Run deterministic comms demos for success and failure paths."""

    success_case = run_key_agreement_batch(
        runs=1,
        channel_name="perfect",
        kem_params="ML-KEM-768",
        authenticate_server=True,
        dsa_params="ML-DSA-65",
        server_aseed=b"server-seed-32-bytes-material!!!!"[:32],
        server_zseed=b"z" * 32,
        server_dsa_aseed=b"server-dsa-seed-material-32-bytes"[:32],
        server_signing_rnd=b"r" * 32,
        encaps_message=b"m" * 32,
    )
    _print_result("Comms Demo: Authenticated Success", success_case)

    adversarial_case = run_key_agreement_batch(
        runs=1,
        channel_name="adversarial",
        kem_params="ML-KEM-768",
        authenticate_server=False,
        server_aseed=b"server-seed-32-bytes-material!!!!"[:32],
        server_zseed=b"z" * 32,
        encaps_message=b"m" * 32,
    )
    _print_result("Comms Demo: Adversarial Failure", adversarial_case)


if __name__ == "__main__":
    main()
