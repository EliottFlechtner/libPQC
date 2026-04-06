import unittest

from src.comms.channels import NoisyChannel, PerfectChannel, ReorderingChannel
from src.comms.protocols.group_key_agreement import (
    broadcast_group_message,
    export_group_transcript,
    perform_group_key_agreement,
    rekey_group_membership,
    replay_group_broadcast,
    replay_group_transcript,
)
from src.comms.state import ProtocolState


class TestGroupKeyAgreement(unittest.TestCase):
    def test_group_key_agreement_succeeds_for_three_members(self):
        result = perform_group_key_agreement(
            channel=PerfectChannel(),
            member_ids=["alice", "bob", "carol"],
            params="ML-KEM-768",
            group_seed=b"g" * 32,
            member_seed_prefix="group-seed-prefix",
        )

        self.assertTrue(result.success)
        self.assertIsNotNone(result.coordinator_group_key)
        self.assertEqual(len(result.member_group_keys), 3)

        for state in result.member_states.values():
            self.assertEqual(state.protocol_state, ProtocolState.ACTIVE)
        self.assertEqual(result.coordinator_state.protocol_state, ProtocolState.ACTIVE)

        for recovered in result.member_group_keys.values():
            self.assertEqual(recovered, result.coordinator_group_key)

    def test_group_key_agreement_fails_on_noisy_channel(self):
        result = perform_group_key_agreement(
            channel=NoisyChannel(bit_error_rate=1.0, seed=7),
            member_ids=["alice", "bob", "carol"],
            params="ML-KEM-768",
            group_seed=b"g" * 32,
            member_seed_prefix="group-seed-prefix",
        )

        self.assertFalse(result.success)
        self.assertEqual(result.coordinator_state.protocol_state, ProtocolState.FAILED)
        for state in result.member_states.values():
            self.assertEqual(state.protocol_state, ProtocolState.FAILED)

    def test_group_key_agreement_rejects_small_member_set(self):
        with self.assertRaises(ValueError):
            _ = perform_group_key_agreement(
                channel=PerfectChannel(),
                member_ids=["alice"],
            )

    def test_group_transcript_export_and_replay(self):
        result = perform_group_key_agreement(
            channel=PerfectChannel(),
            member_ids=["alice", "bob", "carol"],
            params="ML-KEM-768",
            group_seed=b"g" * 32,
            member_seed_prefix="group-seed-prefix",
        )

        transcript_document = export_group_transcript(result)
        replay = replay_group_transcript(transcript_document)

        self.assertTrue(replay.valid)
        self.assertEqual(replay.session_id, result.session_id)
        self.assertGreater(replay.message_count, 0)

    def test_group_broadcast_authentication(self):
        result = perform_group_key_agreement(
            channel=PerfectChannel(),
            member_ids=["alice", "bob", "carol"],
            params="ML-KEM-768",
            group_seed=b"g" * 32,
            member_seed_prefix="group-seed-prefix",
        )

        broadcast = broadcast_group_message(result, "group-message")
        self.assertTrue(replay_group_broadcast(result, broadcast))
        self.assertEqual(len(broadcast.records), 3)

    def test_group_rekey_after_membership_change(self):
        result = perform_group_key_agreement(
            channel=PerfectChannel(),
            member_ids=["alice", "bob", "carol"],
            params="ML-KEM-768",
            group_seed=b"g" * 32,
            member_seed_prefix="group-seed-prefix",
        )

        rekeyed = rekey_group_membership(
            result,
            add_members=["dave"],
            remove_members=["carol"],
            member_seed_prefix="group-seed-prefix",
        )

        self.assertTrue(rekeyed.success)
        self.assertEqual(rekeyed.member_ids, ["alice", "bob", "dave"])
        self.assertNotEqual(
            rekeyed.rekeyed_result.coordinator_group_key, result.coordinator_group_key
        )

    def test_reordering_channel_can_disrupt_group_protocol(self):
        result = perform_group_key_agreement(
            channel=ReorderingChannel(
                reorder_on_stages=("group_join_alice", "group_distribute_alice")
            ),
            member_ids=["alice", "bob", "carol"],
            params="ML-KEM-768",
            group_seed=b"g" * 32,
            member_seed_prefix="group-seed-prefix",
        )

        self.assertFalse(result.success)
        self.assertEqual(result.coordinator_state.protocol_state, ProtocolState.FAILED)


if __name__ == "__main__":
    unittest.main()
