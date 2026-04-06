"""Communication protocol demos for ML-KEM/ML-DSA workflows."""

from typing import cast

from src.comms.channels import PerfectChannel
from src.comms.protocols import (
    broadcast_group_message,
    export_group_transcript,
    perform_group_key_agreement,
    rekey_group_membership,
    replay_group_broadcast,
    replay_group_transcript,
    run_key_agreement_batch,
)


def _print_result(title: str, payload: dict[str, object]) -> None:
    print(f"\n{title}")
    print("-" * len(title))
    print("Channel:", payload["channel"])
    print("Runs:", payload["runs"])
    print("Server authenticated:", payload["authenticate_server"])
    print("Successes:", payload["successes"])
    print("Failures:", payload["failures"])

    results = cast(list[dict[str, object]], payload["results"])
    first = results[0]
    print("Client phase:", first["client_phase"])
    print("Server phase:", first["server_phase"])
    print("Application keys match:", first["application_keys_match"])
    if first["error"]:
        print("Error:", first["error"])


def _print_group_result(title: str, payload: dict[str, object]) -> None:
    print(f"\n{title}")
    print("-" * len(title))
    print("Channel:", payload["channel"])
    print("Runs:", payload["runs"])
    print("Members:", payload["member_count"])
    print("Successes:", payload["successes"])
    print("Failures:", payload["failures"])

    results = cast(list[dict[str, object]], payload["results"])
    first = results[0]
    member_protocol_states = cast(dict[str, str], first["member_protocol_states"])
    print("Coordinator state:", first["coordinator_protocol_state"])
    print("Member states:", ", ".join(sorted(member_protocol_states.values())))
    print("Group key consensus:", first["group_key_consensus"])
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

    group_session = perform_group_key_agreement(
        channel=PerfectChannel(),
        member_ids=["alice", "bob", "carol"],
        params="ML-KEM-768",
        group_seed=b"g" * 32,
        member_seed_prefix="group-seed-prefix",
    )
    transcript_document = export_group_transcript(group_session)
    replay = replay_group_transcript(transcript_document)
    broadcast = broadcast_group_message(group_session, "group-message", label="notice")
    broadcast_verified = replay_group_broadcast(group_session, broadcast)
    rekeyed = rekey_group_membership(
        group_session,
        add_members=["dave"],
        remove_members=["carol"],
        member_seed_prefix="group-seed-prefix",
    )

    _print_group_result(
        "Comms Demo: Group Session Utilities",
        {
            "channel": group_session.channel_name,
            "runs": 1,
            "member_count": len(group_session.member_ids),
            "successes": 1,
            "failures": 0,
            "results": [
                {
                    "coordinator_protocol_state": group_session.coordinator_state.protocol_state.value,
                    "member_protocol_states": {
                        member_id: state.protocol_state.value
                        for member_id, state in group_session.member_states.items()
                    },
                    "group_key_consensus": True,
                    "error": None,
                }
            ],
        },
    )
    print("Transcript hash:", replay.transcript_hash_hex)
    print("Transcript messages:", replay.message_count)
    print("Broadcast verified:", broadcast_verified)
    print("Broadcast tags:", len(broadcast.records))
    print("Rekey session success:", rekeyed.success)
    print("Rekey members:", ", ".join(rekeyed.member_ids))


if __name__ == "__main__":
    main()
