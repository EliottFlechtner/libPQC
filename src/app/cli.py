"""Command-line interface for libPQC demos and scheme workflows."""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from typing import Callable, Sequence

from demos import (
    attack_cost_comparison_demo,
    ml_dsa_security_demo,
    ml_kem_security_demo,
    security_analysis_demo,
)
from demos.ml_dsa_demo import main as run_ml_dsa_demo
from demos.ml_kem_demo import main as run_ml_kem_demo
from src.schemes.ml_dsa.keygen import ml_dsa_keygen
from src.schemes.ml_dsa.sign import ml_dsa_sign
from src.schemes.ml_dsa.verify import ml_dsa_verify
from src.schemes.ml_kem.decaps import ml_kem_decaps
from src.schemes.ml_kem.encaps import ml_kem_encaps
from src.schemes.ml_kem.keygen import ml_kem_keygen


DemoEntry = tuple[str, Callable[[], None]]

DEMO_COMMANDS: dict[str, list[DemoEntry]] = {
    "all": [
        ("ML-KEM Cryptography", run_ml_kem_demo),
        ("ML-DSA Cryptography", run_ml_dsa_demo),
        ("Lattice Attack Analysis", security_analysis_demo.main),
        ("ML-KEM Security Analysis", ml_kem_security_demo.main),
        ("ML-DSA Security Analysis", ml_dsa_security_demo.main),
        ("Comparative Attack Costs", attack_cost_comparison_demo.main),
    ],
    "ml-kem": [("ML-KEM Cryptography", run_ml_kem_demo)],
    "ml-dsa": [("ML-DSA Cryptography", run_ml_dsa_demo)],
    "analysis": [("Lattice Attack Analysis", security_analysis_demo.main)],
    "ml-kem-security": [("ML-KEM Security Analysis", ml_kem_security_demo.main)],
    "ml-dsa-security": [("ML-DSA Security Analysis", ml_dsa_security_demo.main)],
    "attack-costs": [("Comparative Attack Costs", attack_cost_comparison_demo.main)],
}


def _print_json(payload: dict[str, object]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _hex_bytes(value: str, label: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be valid hexadecimal") from exc


def _text_or_hex_bytes(
    text: str | None, hex_value: str | None, label: str
) -> bytes | str | None:
    if hex_value is not None:
        return _hex_bytes(hex_value, label)
    if text is not None:
        return text
    return None


def _run_demo_suite(selection: str) -> int:
    entries = DEMO_COMMANDS[selection]
    success = True

    print("\n" + "=" * 80)
    print("libPQC - POST-QUANTUM CRYPTOGRAPHY DEMONSTRATION SUITE")
    print("=" * 80)

    for index, (name, demo_func) in enumerate(entries, 1):
        print(f"\n[DEMO {index}/{len(entries)}] {name}")
        print("=" * 80)
        try:
            demo_func()
        except Exception as exc:  # pragma: no cover - defensive CLI guard
            success = False
            print(f"Demo failed: {exc}")
            traceback.print_exc()

    print("\n" + "=" * 80)
    print("ALL DEMOS COMPLETED" if success else "DEMO RUN COMPLETED WITH ERRORS")
    return 0 if success else 1


def _handle_demo(args: argparse.Namespace) -> int:
    return _run_demo_suite(args.demo_name)


def _handle_ml_kem_keygen(args: argparse.Namespace) -> int:
    encapsulation_key, decapsulation_key = ml_kem_keygen(
        args.params,
        aseed=args.aseed,
        zseed=args.zseed,
    )
    _print_json(
        {
            "params": args.params,
            "encapsulation_key_hex": encapsulation_key.hex(),
            "decapsulation_key_hex": decapsulation_key.hex(),
        }
    )
    return 0


def _handle_ml_kem_encaps(args: argparse.Namespace) -> int:
    encapsulation_key = _hex_bytes(args.ek_hex, "ek-hex")
    message = _text_or_hex_bytes(args.message, args.message_hex, "message")
    if isinstance(message, str):
        message = message.encode("utf-8")

    shared_key, ciphertext = ml_kem_encaps(
        encapsulation_key,
        params=args.params,
        message=message,
    )
    _print_json(
        {
            "params": args.params,
            "shared_key_hex": shared_key.hex(),
            "ciphertext_hex": ciphertext.hex(),
        }
    )
    return 0


def _handle_ml_kem_decaps(args: argparse.Namespace) -> int:
    ciphertext = _hex_bytes(args.ciphertext_hex, "ciphertext-hex")
    decapsulation_key = _hex_bytes(args.dk_hex, "dk-hex")
    shared_key = ml_kem_decaps(ciphertext, decapsulation_key, params=args.params)
    _print_json({"params": args.params, "shared_key_hex": shared_key.hex()})
    return 0


def _handle_ml_dsa_keygen(args: argparse.Namespace) -> int:
    verification_key, signing_key = ml_dsa_keygen(args.params, aseed=args.aseed)
    _print_json(
        {
            "params": args.params,
            "verification_key_hex": verification_key.hex(),
            "signing_key_hex": signing_key.hex(),
        }
    )
    return 0


def _handle_ml_dsa_sign(args: argparse.Namespace) -> int:
    message = _text_or_hex_bytes(args.message, args.message_hex, "message")
    if message is None:
        raise ValueError("message is required")

    signature = ml_dsa_sign(
        message,
        _hex_bytes(args.sk_hex, "sk-hex"),
        params=args.params,
        rnd=args.rnd,
    )
    _print_json({"params": args.params, "signature_hex": signature.hex()})
    return 0


def _handle_ml_dsa_verify(args: argparse.Namespace) -> int:
    message = _text_or_hex_bytes(args.message, args.message_hex, "message")
    if message is None:
        raise ValueError("message is required")

    verified = ml_dsa_verify(
        message,
        _hex_bytes(args.sig_hex, "sig-hex"),
        _hex_bytes(args.vk_hex, "vk-hex"),
        params=args.params,
    )
    _print_json({"params": args.params, "verified": verified})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="libPQC",
        description="Run libPQC demos or invoke ML-KEM / ML-DSA workflows.",
    )
    subparsers = parser.add_subparsers(dest="command")

    demo_parser = subparsers.add_parser("demo", help="Run the bundled demos")
    demo_parser.add_argument(
        "demo_name",
        nargs="?",
        choices=sorted(DEMO_COMMANDS),
        default="all",
        help="Which demo to run",
    )
    demo_parser.set_defaults(handler=_handle_demo)

    ml_kem_parser = subparsers.add_parser("ml-kem", help="ML-KEM command group")
    ml_kem_subparsers = ml_kem_parser.add_subparsers(
        dest="ml_kem_command", required=True
    )

    ml_kem_keygen = ml_kem_subparsers.add_parser(
        "keygen", help="Generate an ML-KEM keypair"
    )
    ml_kem_keygen.add_argument(
        "--params", default="ML-KEM-768", help="ML-KEM parameter preset"
    )
    ml_kem_keygen.add_argument("--aseed", help="Deterministic keygen seed")
    ml_kem_keygen.add_argument("--zseed", help="Deterministic fallback seed")
    ml_kem_keygen.set_defaults(handler=_handle_ml_kem_keygen)

    ml_kem_encaps = ml_kem_subparsers.add_parser(
        "encaps", help="Encapsulate under an ML-KEM public key"
    )
    ml_kem_encaps.add_argument(
        "--params", default="ML-KEM-768", help="ML-KEM parameter preset"
    )
    ml_kem_encaps.add_argument(
        "--ek-hex", required=True, help="Encapsulation key as hex"
    )
    msg_group = ml_kem_encaps.add_mutually_exclusive_group()
    msg_group.add_argument("--message", help="Message as UTF-8 text")
    msg_group.add_argument("--message-hex", help="Message as hex")
    ml_kem_encaps.set_defaults(handler=_handle_ml_kem_encaps)

    ml_kem_decaps = ml_kem_subparsers.add_parser(
        "decaps", help="Decapsulate an ML-KEM ciphertext"
    )
    ml_kem_decaps.add_argument(
        "--params", default="ML-KEM-768", help="ML-KEM parameter preset"
    )
    ml_kem_decaps.add_argument(
        "--ciphertext-hex", required=True, help="Ciphertext as hex"
    )
    ml_kem_decaps.add_argument(
        "--dk-hex", required=True, help="Decapsulation key as hex"
    )
    ml_kem_decaps.set_defaults(handler=_handle_ml_kem_decaps)

    ml_dsa_parser = subparsers.add_parser("ml-dsa", help="ML-DSA command group")
    ml_dsa_subparsers = ml_dsa_parser.add_subparsers(
        dest="ml_dsa_command", required=True
    )

    ml_dsa_keygen = ml_dsa_subparsers.add_parser(
        "keygen", help="Generate an ML-DSA keypair"
    )
    ml_dsa_keygen.add_argument(
        "--params", default="ML-DSA-87", help="ML-DSA parameter preset"
    )
    ml_dsa_keygen.add_argument("--aseed", help="Deterministic keygen seed")
    ml_dsa_keygen.set_defaults(handler=_handle_ml_dsa_keygen)

    ml_dsa_sign = ml_dsa_subparsers.add_parser("sign", help="Sign a message")
    ml_dsa_sign.add_argument(
        "--params", help="ML-DSA parameter preset; defaults to the key payload"
    )
    ml_dsa_sign.add_argument("--sk-hex", required=True, help="Signing key as hex")
    msg_group = ml_dsa_sign.add_mutually_exclusive_group(required=True)
    msg_group.add_argument("--message", help="Message as UTF-8 text")
    msg_group.add_argument("--message-hex", help="Message as hex")
    ml_dsa_sign.add_argument("--rnd", help="Optional signing randomness")
    ml_dsa_sign.set_defaults(handler=_handle_ml_dsa_sign)

    ml_dsa_verify = ml_dsa_subparsers.add_parser("verify", help="Verify a signature")
    ml_dsa_verify.add_argument(
        "--params", help="ML-DSA parameter preset; defaults to the key payload"
    )
    ml_dsa_verify.add_argument(
        "--vk-hex", required=True, help="Verification key as hex"
    )
    ml_dsa_verify.add_argument("--sig-hex", required=True, help="Signature as hex")
    msg_group = ml_dsa_verify.add_mutually_exclusive_group(required=True)
    msg_group.add_argument("--message", help="Message as UTF-8 text")
    msg_group.add_argument("--message-hex", help="Message as hex")
    ml_dsa_verify.set_defaults(handler=_handle_ml_dsa_verify)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        argv = ["demo"]

    parser = build_parser()
    args = parser.parse_args(list(argv))
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return handler(args)
    except (ValueError, TypeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
