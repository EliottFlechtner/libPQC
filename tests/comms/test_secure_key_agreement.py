import unittest

from src.comms.channels.transports import AdversarialChannel, NoisyChannel, PerfectChannel
from src.comms.protocols.secure_key_agreement import perform_secure_key_agreement
from src.comms.state.session import HandshakePhase


class TestSecureKeyAgreement(unittest.TestCase):
    def test_secure_key_agreement_succeeds_over_perfect_channel(self):
        result = perform_secure_key_agreement(
            channel=PerfectChannel(),
            params="ML-KEM-768",
            server_aseed=b"server-seed-32-bytes-material!!!!"[:32],
            server_zseed=b"z" * 32,
            encaps_message=b"m" * 32,
        )

        self.assertTrue(result.success)
        self.assertEqual(result.client_state.phase, HandshakePhase.ESTABLISHED)
        self.assertEqual(result.server_state.phase, HandshakePhase.ESTABLISHED)
        self.assertIsNotNone(result.client_application_key)
        self.assertEqual(result.client_application_key, result.server_application_key)

    def test_secure_key_agreement_fails_on_noisy_channel(self):
        result = perform_secure_key_agreement(
            channel=NoisyChannel(bit_error_rate=1.0, seed=7),
            params="ML-KEM-768",
            server_aseed=b"server-seed-32-bytes-material!!!!"[:32],
            server_zseed=b"z" * 32,
            encaps_message=b"m" * 32,
        )

        self.assertFalse(result.success)
        self.assertEqual(result.client_state.phase, HandshakePhase.FAILED)
        self.assertEqual(result.server_state.phase, HandshakePhase.FAILED)

    def test_secure_key_agreement_fails_on_adversarial_tamper(self):
        def tamper_keyshare(payload: bytes, sender: str, receiver: str, stage: str) -> bytes:
            if stage != "client_keyshare":
                return payload
            mutated = bytearray(payload)
            mutated[-1] ^= 0x01
            return bytes(mutated)

        result = perform_secure_key_agreement(
            channel=AdversarialChannel(tamper_function=tamper_keyshare),
            params="ML-KEM-768",
            server_aseed=b"server-seed-32-bytes-material!!!!"[:32],
            server_zseed=b"z" * 32,
            encaps_message=b"m" * 32,
        )

        self.assertFalse(result.success)
        self.assertIn("failed", result.client_state.phase.value)

    def test_event_log_tracks_state_transitions(self):
        result = perform_secure_key_agreement(
            channel=PerfectChannel(),
            params="ML-KEM-768",
            server_aseed=b"server-seed-32-bytes-material!!!!"[:32],
            server_zseed=b"z" * 32,
            encaps_message=b"m" * 32,
        )

        self.assertTrue(result.success)
        self.assertGreaterEqual(len(result.events), 4)
        event_types = [event["event_type"] for event in result.events]
        self.assertIn("protocol_start", event_types)
        self.assertIn("state_transition", event_types)


if __name__ == "__main__":
    unittest.main()
