import unittest

from src.comms.channels import NoisyChannel, PerfectChannel
from src.comms.protocols.group_key_agreement import perform_group_key_agreement
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


if __name__ == "__main__":
    unittest.main()
