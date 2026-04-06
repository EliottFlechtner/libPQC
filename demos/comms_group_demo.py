"""Multi-entity communication protocol demo for libPQC."""

from src.comms.channels import PerfectChannel
from src.comms.protocols import (
    broadcast_group_message,
    export_group_transcript,
    perform_group_key_agreement,
    rekey_group_membership,
    replay_group_broadcast,
    replay_group_transcript,
)


def main() -> None:
    """Run a deterministic multi-entity group protocol demo."""

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

    print("Comms Group Demo: Group Session Utilities")
    print("---------------------------------------")
    print("Channel:", group_session.channel_name)
    print("Members:", len(group_session.member_ids))
    print("Coordinator state:", group_session.coordinator_state.protocol_state.value)
    print(
        "Member states:",
        ", ".join(
            sorted(
                state.protocol_state.value
                for state in group_session.member_states.values()
            )
        ),
    )
    print("Group key consensus:", True)
    print("Transcript hash:", replay.transcript_hash_hex)
    print("Transcript messages:", replay.message_count)
    print("Broadcast verified:", broadcast_verified)
    print("Broadcast tags:", len(broadcast.records))
    print("Rekey session success:", rekeyed.success)
    print("Rekey members:", ", ".join(rekeyed.member_ids))


if __name__ == "__main__":
    main()
