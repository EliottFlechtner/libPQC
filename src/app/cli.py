"""Command-line interface for libPQC demos and scheme workflows."""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path
from typing import Callable, Mapping, Sequence

from demos import (
    attack_cost_comparison_demo,
    comms_demo,
    comms_group_demo,
    ml_dsa_security_demo,
    ml_kem_security_demo,
    security_analysis_demo,
)
from demos.ml_dsa_demo import main as run_ml_dsa_demo
from demos.ml_kem_demo import main as run_ml_kem_demo
from src.app import performance
from src.app import interoperability
from src.experiments import (
    DEFAULT_BUDGET_POWERS,
    DEFAULT_HYBRID_MODES,
    DEFAULT_ML_DSA_PARAMS,
    DEFAULT_ML_KEM_PARAMS,
    DEFAULT_SCHEMES,
    DEFAULT_TLS_MODES,
    render_adversary_budget_report,
    render_hybrid_scenarios_report,
    render_parametric_benchmark_report,
    render_performance_regression_report,
    render_tls_handshake_report,
    run_parametric_benchmark_sweep,
    simulate_hybrid_pq_scenarios,
    simulate_post_quantum_tls_handshake,
    simulate_lattice_attack_budgets,
    track_performance_regressions,
)
from src.comms.protocols import (
    broadcast_group_message,
    export_group_transcript,
    perform_group_key_agreement,
    rekey_group_membership,
    replay_group_transcript,
    run_group_key_agreement_batch,
    run_key_agreement_batch,
)
from src.comms.protocols.runner import build_channel
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
        ("Comms Secure Key Agreement", comms_demo.main),
        ("Comms Group Session Utilities", comms_group_demo.main),
        ("Lattice Attack Analysis", security_analysis_demo.main),
        ("ML-KEM Security Analysis", ml_kem_security_demo.main),
        ("ML-DSA Security Analysis", ml_dsa_security_demo.main),
        ("Comparative Attack Costs", attack_cost_comparison_demo.main),
    ],
    "ml-kem": [("ML-KEM Cryptography", run_ml_kem_demo)],
    "ml-dsa": [("ML-DSA Cryptography", run_ml_dsa_demo)],
    "comms": [("Comms Secure Key Agreement", comms_demo.main)],
    "comms-group": [("Comms Group Session Utilities", comms_group_demo.main)],
    "analysis": [("Lattice Attack Analysis", security_analysis_demo.main)],
    "ml-kem-security": [("ML-KEM Security Analysis", ml_kem_security_demo.main)],
    "ml-dsa-security": [("ML-DSA Security Analysis", ml_dsa_security_demo.main)],
    "attack-costs": [("Comparative Attack Costs", attack_cost_comparison_demo.main)],
}


def _print_json(payload: Mapping[str, object]) -> None:
    print(json.dumps(dict(payload), indent=2, sort_keys=True))


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


def _handle_benchmark(args: argparse.Namespace) -> int:
    benchmark_handlers = {
        ("ml-kem", "keygen"): performance.benchmark_ml_kem_keygen,
        ("ml-kem", "encaps"): performance.benchmark_ml_kem_encaps,
        ("ml-kem", "decaps"): performance.benchmark_ml_kem_decaps,
        ("ml-dsa", "keygen"): performance.benchmark_ml_dsa_keygen,
        ("ml-dsa", "sign"): performance.benchmark_ml_dsa_sign,
        ("ml-dsa", "verify"): performance.benchmark_ml_dsa_verify,
        ("core", "poly-mul"): performance.benchmark_polynomial_multiplication,
    }
    if args.benchmark_name == "all":
        _print_json(
            {
                "command": "benchmark",
                "results": performance.benchmark_all(
                    kem_params=args.kem_params,
                    dsa_params=args.dsa_params,
                    iterations=args.iterations,
                    warmup_iterations=args.warmup,
                ),
            }
        )
        return 0

    handler = benchmark_handlers[(args.group_name, args.benchmark_name)]
    if args.group_name == "core":
        result = handler(
            modulus=args.modulus,
            degree=args.degree,
            iterations=args.iterations,
            warmup_iterations=args.warmup,
        )
    else:
        result = handler(
            params=args.kem_params if args.group_name == "ml-kem" else args.dsa_params,
            iterations=args.iterations,
            warmup_iterations=args.warmup,
        )
    _print_json({"command": "benchmark", **result})
    return 0


def _handle_profile(args: argparse.Namespace) -> int:
    profile_handlers = {
        ("ml-kem", "keygen"): performance.profile_ml_kem_keygen,
        ("ml-kem", "encaps"): performance.profile_ml_kem_encaps,
        ("ml-kem", "decaps"): performance.profile_ml_kem_decaps,
        ("ml-dsa", "keygen"): performance.profile_ml_dsa_keygen,
        ("ml-dsa", "sign"): performance.profile_ml_dsa_sign,
        ("ml-dsa", "verify"): performance.profile_ml_dsa_verify,
        ("core", "poly-mul"): performance.profile_polynomial_multiplication,
    }
    if args.profile_name == "all":
        _print_json(
            {
                "command": "profile",
                "results": performance.profile_all(
                    kem_params=args.kem_params,
                    dsa_params=args.dsa_params,
                    iterations=args.iterations,
                    warmup_iterations=args.warmup,
                    limit=args.limit,
                    sort_by=args.sort_by,
                ),
            }
        )
        return 0

    handler = profile_handlers[(args.group_name, args.profile_name)]
    if args.group_name == "core":
        result = handler(
            modulus=args.modulus,
            degree=args.degree,
            iterations=args.iterations,
            warmup_iterations=args.warmup,
            limit=args.limit,
            sort_by=args.sort_by,
        )
    else:
        result = handler(
            params=args.kem_params if args.group_name == "ml-kem" else args.dsa_params,
            iterations=args.iterations,
            warmup_iterations=args.warmup,
            limit=args.limit,
            sort_by=args.sort_by,
        )
    _print_json({"command": "profile", **result})
    return 0


def _add_benchmark_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--kem-params",
        default=performance.DEFAULT_ML_KEM_PARAMS,
        help="ML-KEM parameter preset",
    )
    parser.add_argument(
        "--dsa-params",
        default=performance.DEFAULT_ML_DSA_PARAMS,
        help="ML-DSA parameter preset",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=performance.DEFAULT_ITERATIONS,
        help="Benchmark iterations",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=performance.DEFAULT_WARMUP,
        help="Warmup iterations before timing",
    )


def _add_profile_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--kem-params",
        default=performance.DEFAULT_ML_KEM_PARAMS,
        help="ML-KEM parameter preset",
    )
    parser.add_argument(
        "--dsa-params",
        default=performance.DEFAULT_ML_DSA_PARAMS,
        help="ML-DSA parameter preset",
    )
    parser.add_argument(
        "--iterations", type=int, default=1, help="Iterations to include in the profile"
    )
    parser.add_argument(
        "--warmup", type=int, default=0, help="Warmup iterations before profiling"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=25,
        help="Maximum number of functions to print in the profile summary",
    )
    parser.add_argument(
        "--sort-by",
        default="cumtime",
        choices=["cumtime", "tottime"],
        help="Profile sort key",
    )


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


def _emit_document(document: dict[str, object], output: Path | None) -> int:
    if output is not None:
        interoperability.dump_document(document, output)
        return 0
    _print_json(document)
    return 0


def _handle_interop_export(args: argparse.Namespace) -> int:
    if args.scheme == "ml-kem":
        if args.artifact == "keypair":
            encapsulation_key, decapsulation_key = ml_kem_keygen(
                args.params, aseed=args.aseed, zseed=args.zseed
            )
            document = interoperability.export_ml_kem_keypair(
                encapsulation_key, decapsulation_key, args.params
            )
        elif args.artifact == "ciphertext":
            if args.message is None and args.message_hex is None:
                message = interoperability.DEFAULT_ML_KEM_MESSAGE
            else:
                message = _text_or_hex_bytes(args.message, args.message_hex, "message")
                if isinstance(message, str):
                    message = message.encode("utf-8")
            shared_key, ciphertext = ml_kem_encaps(
                _hex_bytes(args.ek_hex, "ek-hex"),
                params=args.params,
                message=message,
            )
            document = interoperability.export_ml_kem_ciphertext(
                ciphertext, args.params, shared_key=shared_key
            )
        else:
            message = _text_or_hex_bytes(args.message, args.message_hex, "message")
            if isinstance(message, str):
                message = message.encode("utf-8")
            document = interoperability.export_ml_kem_test_vector(
                params=args.params,
                aseed=args.aseed,
                zseed=args.zseed,
                message=message,
            )
    else:
        if args.artifact == "keypair":
            verification_key, signing_key = ml_dsa_keygen(args.params, aseed=args.aseed)
            document = interoperability.export_ml_dsa_keypair(
                verification_key, signing_key, args.params
            )
        elif args.artifact == "signature":
            message = _text_or_hex_bytes(args.message, args.message_hex, "message")
            if message is None:
                message = interoperability.DEFAULT_ML_DSA_MESSAGE
            elif isinstance(message, str):
                message = message.encode("utf-8")
            signature = ml_dsa_sign(
                message,
                _hex_bytes(args.sk_hex, "sk-hex"),
                params=args.params,
                rnd=args.rnd,
            )
            document = interoperability.export_ml_dsa_signature(signature, args.params)
        else:
            message = _text_or_hex_bytes(args.message, args.message_hex, "message")
            if isinstance(message, str):
                message = message.encode("utf-8")
            document = interoperability.export_ml_dsa_test_vector(
                params=args.params,
                aseed=args.aseed,
                message=message,
                rnd=args.rnd,
            )

    return _emit_document(document, args.output)


def _handle_interop_import(args: argparse.Namespace) -> int:
    document = interoperability.load_document(args.input)
    if args.scheme == "ml-kem":
        if args.artifact == "keypair":
            encapsulation_key, decapsulation_key = (
                interoperability.import_ml_kem_keypair(document)
            )
            summary = {
                "scheme": "ML-KEM",
                "kind": "keypair",
                "encapsulation_key_hex": encapsulation_key.hex(),
                "decapsulation_key_hex": decapsulation_key.hex(),
            }
        elif args.artifact == "ciphertext":
            ciphertext = interoperability.import_ml_kem_ciphertext(document)
            summary = {
                "scheme": "ML-KEM",
                "kind": "ciphertext",
                "ciphertext_hex": ciphertext.hex(),
            }
        else:
            normalized = interoperability.import_ml_kem_test_vector(document)
            summary = {
                "scheme": "ML-KEM",
                "kind": "test-vector",
                "message_hex": normalized["test_vector"]["message_hex"],
                "verified": normalized["test_vector"]["decapsulation"]["shared_key_hex"]
                == normalized["test_vector"]["encapsulation"]["artifacts"][
                    "shared_key_hex"
                ],
            }
    else:
        if args.artifact == "keypair":
            verification_key, signing_key = interoperability.import_ml_dsa_keypair(
                document
            )
            summary = {
                "scheme": "ML-DSA",
                "kind": "keypair",
                "verification_key_hex": verification_key.hex(),
                "signing_key_hex": signing_key.hex(),
            }
        elif args.artifact == "signature":
            signature = interoperability.import_ml_dsa_signature(document)
            summary = {
                "scheme": "ML-DSA",
                "kind": "signature",
                "signature_hex": signature.hex(),
            }
        else:
            normalized = interoperability.import_ml_dsa_test_vector(document)
            summary = {
                "scheme": "ML-DSA",
                "kind": "test-vector",
                "message_hex": normalized["test_vector"]["message_hex"],
                "verified": normalized["test_vector"]["verification"]["verified"],
            }

    _print_json(summary)
    return 0


def _handle_comms_key_agreement(args: argparse.Namespace) -> int:
    encaps_message = None
    if args.encaps_message_hex is not None:
        encaps_message = _hex_bytes(args.encaps_message_hex, "encaps-message-hex")

    payload = run_key_agreement_batch(
        runs=args.runs,
        channel_name=args.channel,
        kem_params=args.kem_params,
        authenticate_server=args.authenticate_server,
        dsa_params=args.dsa_params,
        noisy_bit_error_rate=args.noisy_bit_error_rate,
        seed=args.seed,
        server_aseed=args.server_aseed,
        server_zseed=args.server_zseed,
        server_dsa_aseed=args.server_dsa_aseed,
        server_signing_rnd=args.server_signing_rnd,
        encaps_message=encaps_message,
        include_events=args.include_events,
    )
    _print_json({"command": "comms", "protocol": "secure-key-agreement", **payload})
    return 0


def _handle_comms_group_key_agreement(args: argparse.Namespace) -> int:
    if args.members < 2:
        raise ValueError("members must be >= 2")

    member_ids = [f"member-{index}" for index in range(1, args.members + 1)]
    group_seed = None
    if args.group_seed_hex is not None:
        group_seed = _hex_bytes(args.group_seed_hex, "group-seed-hex")

    payload = run_group_key_agreement_batch(
        runs=args.runs,
        channel_name=args.channel,
        member_ids=member_ids,
        kem_params=args.kem_params,
        noisy_bit_error_rate=args.noisy_bit_error_rate,
        seed=args.seed,
        group_seed=group_seed,
        member_seed_prefix=args.member_seed_prefix,
        include_events=args.include_events,
    )
    _print_json({"command": "comms", "protocol": "group-key-agreement", **payload})
    return 0


def _build_group_member_ids(member_count: int, member_prefix: str) -> list[str]:
    if member_count < 2:
        raise ValueError("members must be >= 2")
    return [f"{member_prefix}-{index}" for index in range(1, member_count + 1)]


def _build_group_session_from_args(args: argparse.Namespace):
    group_seed = None
    if getattr(args, "group_seed_hex", None) is not None:
        group_seed = _hex_bytes(args.group_seed_hex, "group-seed-hex")

    member_ids = _build_group_member_ids(args.members, args.member_prefix)
    channel = build_channel(
        args.channel,
        noisy_bit_error_rate=args.noisy_bit_error_rate,
        seed=getattr(args, "seed", None),
    )

    return perform_group_key_agreement(
        channel=channel,
        member_ids=member_ids,
        params=args.kem_params,
        coordinator_id=getattr(args, "coordinator_id", "coordinator"),
        group_seed=group_seed,
        member_seed_prefix=args.member_seed_prefix,
    )


def _handle_comms_group_export_transcript(args: argparse.Namespace) -> int:
    session = _build_group_session_from_args(args)
    document = export_group_transcript(session)
    return _emit_document(document, args.output)


def _handle_comms_group_replay_transcript(args: argparse.Namespace) -> int:
    document = interoperability.load_document(args.input)
    replay = replay_group_transcript(document)
    _print_json(
        {
            "command": "comms",
            "protocol": "group-transcript-replay",
            "session_id": replay.session_id,
            "valid": replay.valid,
            "transcript_hash_hex": replay.transcript_hash_hex,
            "message_count": replay.message_count,
        }
    )
    return 0


def _handle_comms_group_broadcast(args: argparse.Namespace) -> int:
    session = _build_group_session_from_args(args)
    message = _text_or_hex_bytes(args.message, args.message_hex, "message")
    if message is None:
        raise ValueError("message is required")
    broadcast = broadcast_group_message(session, message, label=args.label)
    _print_json(
        {
            "command": "comms",
            "protocol": "group-broadcast",
            "session_id": broadcast.session_id,
            "coordinator_id": broadcast.coordinator_id,
            "label": broadcast.label,
            "message": broadcast.message,
            "transcript_hash_hex": broadcast.transcript_hash_hex,
            "records": [
                {
                    "member_id": record.member_id,
                    "message": record.message,
                    "tag_hex": record.tag_hex,
                }
                for record in broadcast.records
            ],
        }
    )
    return 0


def _handle_comms_group_rekey(args: argparse.Namespace) -> int:
    session = _build_group_session_from_args(args)
    rekeyed = rekey_group_membership(
        session,
        add_members=list(args.add_member or []),
        remove_members=list(args.remove_member or []),
        member_seed_prefix=args.member_seed_prefix,
    )
    _print_json(
        {
            "command": "comms",
            "protocol": "group-rekey",
            "success": rekeyed.success,
            "previous_session_id": rekeyed.previous_session_id,
            "new_session_id": rekeyed.new_session_id,
            "member_ids": rekeyed.member_ids,
            "member_count": len(rekeyed.member_ids),
            "coordinator_protocol_state": rekeyed.rekeyed_result.coordinator_state.protocol_state.value,
            "group_key_consensus": (
                rekeyed.rekeyed_result.coordinator_group_key is not None
                and all(
                    member_key == rekeyed.rekeyed_result.coordinator_group_key
                    for member_key in rekeyed.rekeyed_result.member_group_keys.values()
                )
            ),
        }
    )
    return 0


def _handle_experiment_parametric_benchmarks(args: argparse.Namespace) -> int:
    records = run_parametric_benchmark_sweep(
        kem_params=args.kem_params,
        dsa_params=args.dsa_params,
        iterations=args.iterations,
        warmup_iterations=args.warmup,
    )
    _print_json(
        {
            "command": "experiment",
            "scenario": "parametric-benchmarks",
            "results": records,
            "report_markdown": render_parametric_benchmark_report(records),
        }
    )
    return 0


def _handle_experiment_adversary_simulations(args: argparse.Namespace) -> int:
    records = simulate_lattice_attack_budgets(
        budgets_pow=args.budget_exp,
        schemes=args.schemes,
    )
    _print_json(
        {
            "command": "experiment",
            "scenario": "adversary-simulations",
            "results": records,
            "report_markdown": render_adversary_budget_report(records),
        }
    )
    return 0


def _handle_experiment_tls_handshake(args: argparse.Namespace) -> int:
    record = simulate_post_quantum_tls_handshake(
        mode=args.mode,
        kem_params=args.kem_params,
        dsa_params=args.dsa_params,
        runs=args.runs,
        authenticate_server=args.authenticate_server,
    )
    _print_json(
        {
            "command": "experiment",
            "scenario": "pq-tls-handshake",
            "result": record,
            "report_markdown": render_tls_handshake_report(record),
        }
    )
    return 0


def _handle_experiment_hybrid_scenarios(args: argparse.Namespace) -> int:
    records = simulate_hybrid_pq_scenarios(
        modes=args.modes,
        kem_params=args.kem_params,
        dsa_params=args.dsa_params,
        iterations=args.iterations,
    )
    _print_json(
        {
            "command": "experiment",
            "scenario": "hybrid-scenarios",
            "results": records,
            "report_markdown": render_hybrid_scenarios_report(records),
        }
    )
    return 0


def _handle_experiment_performance_regression(args: argparse.Namespace) -> int:
    payload = track_performance_regressions(
        baseline_source=args.baseline,
        threshold_ratio=args.threshold_ratio,
        kem_params=args.kem_params,
        dsa_params=args.dsa_params,
        iterations=args.iterations,
        warmup_iterations=args.warmup,
    )
    _print_json(
        {
            "command": "experiment",
            "scenario": "performance-regression",
            **payload,
            "report_markdown": render_performance_regression_report(payload),
        }
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="libPQC")
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo_parser = subparsers.add_parser("demo", help="Run the demo suite")
    demo_parser.add_argument(
        "demo_name",
        nargs="?",
        choices=sorted(DEMO_COMMANDS),
        default="all",
        help="Which demo to run",
    )
    demo_parser.set_defaults(handler=_handle_demo)

    benchmark_parser = subparsers.add_parser(
        "benchmark", help="Run deterministic timing benchmarks"
    )
    benchmark_subparsers = benchmark_parser.add_subparsers(
        dest="group_name", required=True
    )

    benchmark_ml_kem = benchmark_subparsers.add_parser(
        "ml-kem", help="Benchmark ML-KEM operations"
    )
    benchmark_ml_kem_subparsers = benchmark_ml_kem.add_subparsers(
        dest="benchmark_name", required=True
    )
    for name in ["keygen", "encaps", "decaps", "all"]:
        parser_for_name = benchmark_ml_kem_subparsers.add_parser(name)
        _add_benchmark_common_args(parser_for_name)
        parser_for_name.set_defaults(
            group_name="ml-kem", benchmark_name=name, handler=_handle_benchmark
        )

    benchmark_ml_dsa = benchmark_subparsers.add_parser(
        "ml-dsa", help="Benchmark ML-DSA operations"
    )
    benchmark_ml_dsa_subparsers = benchmark_ml_dsa.add_subparsers(
        dest="benchmark_name", required=True
    )
    for name in ["keygen", "sign", "verify", "all"]:
        parser_for_name = benchmark_ml_dsa_subparsers.add_parser(name)
        _add_benchmark_common_args(parser_for_name)
        parser_for_name.set_defaults(
            group_name="ml-dsa", benchmark_name=name, handler=_handle_benchmark
        )

    benchmark_core = benchmark_subparsers.add_parser(
        "core", help="Benchmark core arithmetic"
    )
    benchmark_core_subparsers = benchmark_core.add_subparsers(
        dest="benchmark_name", required=True
    )
    benchmark_poly = benchmark_core_subparsers.add_parser("poly-mul")
    _add_benchmark_common_args(benchmark_poly)
    benchmark_poly.add_argument(
        "--modulus", type=int, default=3329, help="Coefficient modulus"
    )
    benchmark_poly.add_argument(
        "--degree", type=int, default=256, help="Quotient polynomial degree"
    )
    benchmark_poly.set_defaults(
        group_name="core", benchmark_name="poly-mul", handler=_handle_benchmark
    )

    benchmark_all = benchmark_subparsers.add_parser(
        "all", help="Benchmark all supported operations"
    )
    _add_benchmark_common_args(benchmark_all)
    benchmark_all.set_defaults(
        group_name="all", benchmark_name="all", handler=_handle_benchmark
    )

    profile_parser = subparsers.add_parser(
        "profile", help="Run cProfile profiles for supported operations"
    )
    profile_subparsers = profile_parser.add_subparsers(dest="group_name", required=True)

    profile_ml_kem = profile_subparsers.add_parser(
        "ml-kem", help="Profile ML-KEM operations"
    )
    profile_ml_kem_subparsers = profile_ml_kem.add_subparsers(
        dest="profile_name", required=True
    )
    for name in ["keygen", "encaps", "decaps", "all"]:
        parser_for_name = profile_ml_kem_subparsers.add_parser(name)
        _add_profile_common_args(parser_for_name)
        parser_for_name.set_defaults(
            group_name="ml-kem", profile_name=name, handler=_handle_profile
        )

    profile_ml_dsa = profile_subparsers.add_parser(
        "ml-dsa", help="Profile ML-DSA operations"
    )
    profile_ml_dsa_subparsers = profile_ml_dsa.add_subparsers(
        dest="profile_name", required=True
    )
    for name in ["keygen", "sign", "verify", "all"]:
        parser_for_name = profile_ml_dsa_subparsers.add_parser(name)
        _add_profile_common_args(parser_for_name)
        parser_for_name.set_defaults(
            group_name="ml-dsa", profile_name=name, handler=_handle_profile
        )

    profile_core = profile_subparsers.add_parser("core", help="Profile core arithmetic")
    profile_core_subparsers = profile_core.add_subparsers(
        dest="profile_name", required=True
    )
    profile_poly = profile_core_subparsers.add_parser("poly-mul")
    _add_profile_common_args(profile_poly)
    profile_poly.add_argument(
        "--modulus", type=int, default=3329, help="Coefficient modulus"
    )
    profile_poly.add_argument(
        "--degree", type=int, default=256, help="Quotient polynomial degree"
    )
    profile_poly.set_defaults(
        group_name="core", profile_name="poly-mul", handler=_handle_profile
    )

    profile_all = profile_subparsers.add_parser(
        "all", help="Profile all supported operations"
    )
    _add_profile_common_args(profile_all)
    profile_all.set_defaults(
        group_name="all", profile_name="all", handler=_handle_profile
    )

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

    interop_parser = subparsers.add_parser(
        "interop", help="Export and import interoperable payload bundles"
    )
    interop_subparsers = interop_parser.add_subparsers(
        dest="interop_command", required=True
    )

    interop_export = interop_subparsers.add_parser(
        "export", help="Export an interoperable bundle"
    )
    interop_export_subparsers = interop_export.add_subparsers(
        dest="scheme", required=True
    )

    interop_export_ml_kem = interop_export_subparsers.add_parser(
        "ml-kem", help="Export ML-KEM bundles"
    )
    interop_export_ml_kem_subparsers = interop_export_ml_kem.add_subparsers(
        dest="artifact", required=True
    )

    interop_export_ml_kem_keypair = interop_export_ml_kem_subparsers.add_parser(
        "keypair"
    )
    interop_export_ml_kem_keypair.add_argument(
        "--params", default="ML-KEM-768", help="ML-KEM parameter preset"
    )
    interop_export_ml_kem_keypair.add_argument(
        "--aseed", help="Deterministic keygen seed"
    )
    interop_export_ml_kem_keypair.add_argument(
        "--zseed", help="Deterministic fallback seed"
    )
    interop_export_ml_kem_keypair.add_argument(
        "--output", type=Path, help="Optional output file"
    )
    interop_export_ml_kem_keypair.set_defaults(handler=_handle_interop_export)

    interop_export_ml_kem_ciphertext = interop_export_ml_kem_subparsers.add_parser(
        "ciphertext"
    )
    interop_export_ml_kem_ciphertext.add_argument(
        "--params", default="ML-KEM-768", help="ML-KEM parameter preset"
    )
    interop_export_ml_kem_ciphertext.add_argument(
        "--ek-hex", required=True, help="Encapsulation key as hex"
    )
    interop_export_ml_kem_ciphertext.add_argument(
        "--message", help="Message as UTF-8 text"
    )
    interop_export_ml_kem_ciphertext.add_argument(
        "--message-hex", help="Message as hex"
    )
    interop_export_ml_kem_ciphertext.add_argument(
        "--output", type=Path, help="Optional output file"
    )
    interop_export_ml_kem_ciphertext.set_defaults(handler=_handle_interop_export)

    interop_export_ml_kem_vector = interop_export_ml_kem_subparsers.add_parser(
        "test-vector"
    )
    interop_export_ml_kem_vector.add_argument(
        "--params", default="ML-KEM-768", help="ML-KEM parameter preset"
    )
    interop_export_ml_kem_vector.add_argument(
        "--aseed", help="Deterministic keygen seed"
    )
    interop_export_ml_kem_vector.add_argument(
        "--zseed", help="Deterministic fallback seed"
    )
    interop_export_ml_kem_vector.add_argument("--message", help="Message as UTF-8 text")
    interop_export_ml_kem_vector.add_argument("--message-hex", help="Message as hex")
    interop_export_ml_kem_vector.add_argument(
        "--output", type=Path, help="Optional output file"
    )
    interop_export_ml_kem_vector.set_defaults(handler=_handle_interop_export)

    interop_export_ml_dsa = interop_export_subparsers.add_parser(
        "ml-dsa", help="Export ML-DSA bundles"
    )
    interop_export_ml_dsa_subparsers = interop_export_ml_dsa.add_subparsers(
        dest="artifact", required=True
    )

    interop_export_ml_dsa_keypair = interop_export_ml_dsa_subparsers.add_parser(
        "keypair"
    )
    interop_export_ml_dsa_keypair.add_argument(
        "--params", default="ML-DSA-87", help="ML-DSA parameter preset"
    )
    interop_export_ml_dsa_keypair.add_argument(
        "--aseed", help="Deterministic keygen seed"
    )
    interop_export_ml_dsa_keypair.add_argument(
        "--output", type=Path, help="Optional output file"
    )
    interop_export_ml_dsa_keypair.set_defaults(handler=_handle_interop_export)

    interop_export_ml_dsa_signature = interop_export_ml_dsa_subparsers.add_parser(
        "signature"
    )
    interop_export_ml_dsa_signature.add_argument(
        "--params", default="ML-DSA-87", help="ML-DSA parameter preset"
    )
    interop_export_ml_dsa_signature.add_argument(
        "--sk-hex", required=True, help="Signing key as hex"
    )
    interop_export_ml_dsa_signature.add_argument(
        "--message", help="Message as UTF-8 text"
    )
    interop_export_ml_dsa_signature.add_argument("--message-hex", help="Message as hex")
    interop_export_ml_dsa_signature.add_argument(
        "--rnd", help="Optional signing randomness"
    )
    interop_export_ml_dsa_signature.add_argument(
        "--output", type=Path, help="Optional output file"
    )
    interop_export_ml_dsa_signature.set_defaults(handler=_handle_interop_export)

    interop_export_ml_dsa_vector = interop_export_ml_dsa_subparsers.add_parser(
        "test-vector"
    )
    interop_export_ml_dsa_vector.add_argument(
        "--params", default="ML-DSA-87", help="ML-DSA parameter preset"
    )
    interop_export_ml_dsa_vector.add_argument(
        "--aseed", help="Deterministic keygen seed"
    )
    interop_export_ml_dsa_vector.add_argument("--message", help="Message as UTF-8 text")
    interop_export_ml_dsa_vector.add_argument("--message-hex", help="Message as hex")
    interop_export_ml_dsa_vector.add_argument(
        "--rnd", help="Optional signing randomness"
    )
    interop_export_ml_dsa_vector.add_argument(
        "--output", type=Path, help="Optional output file"
    )
    interop_export_ml_dsa_vector.set_defaults(handler=_handle_interop_export)

    interop_import = interop_subparsers.add_parser(
        "import", help="Import an interoperable bundle"
    )
    interop_import_subparsers = interop_import.add_subparsers(
        dest="scheme", required=True
    )

    interop_import_ml_kem = interop_import_subparsers.add_parser(
        "ml-kem", help="Import ML-KEM bundles"
    )
    interop_import_ml_kem_subparsers = interop_import_ml_kem.add_subparsers(
        dest="artifact", required=True
    )
    for artifact in ["keypair", "ciphertext", "test-vector"]:
        parser_for_name = interop_import_ml_kem_subparsers.add_parser(artifact)
        parser_for_name.add_argument(
            "--input", type=Path, required=True, help="Input bundle path"
        )
        parser_for_name.set_defaults(handler=_handle_interop_import)

    interop_import_ml_dsa = interop_import_subparsers.add_parser(
        "ml-dsa", help="Import ML-DSA bundles"
    )
    interop_import_ml_dsa_subparsers = interop_import_ml_dsa.add_subparsers(
        dest="artifact", required=True
    )
    for artifact in ["keypair", "signature", "test-vector"]:
        parser_for_name = interop_import_ml_dsa_subparsers.add_parser(artifact)
        parser_for_name.add_argument(
            "--input", type=Path, required=True, help="Input bundle path"
        )
        parser_for_name.set_defaults(handler=_handle_interop_import)

    comms_parser = subparsers.add_parser(
        "comms", help="Run communication protocol simulations"
    )
    comms_subparsers = comms_parser.add_subparsers(dest="comms_command", required=True)

    comms_key_agreement = comms_subparsers.add_parser(
        "key-agreement", help="Run an ML-KEM secure key agreement simulation"
    )
    comms_key_agreement.add_argument(
        "--channel",
        default="perfect",
        choices=["perfect", "noisy", "adversarial"],
        help="Channel model to simulate",
    )
    comms_key_agreement.add_argument(
        "--kem-params", default="ML-KEM-768", help="ML-KEM parameter preset"
    )
    comms_key_agreement.add_argument(
        "--runs", type=int, default=1, help="Number of handshake runs"
    )
    comms_key_agreement.add_argument(
        "--authenticate-server",
        action="store_true",
        help="Enable ML-DSA server authentication",
    )
    comms_key_agreement.add_argument(
        "--dsa-params", default="ML-DSA-87", help="ML-DSA parameter preset"
    )
    comms_key_agreement.add_argument(
        "--noisy-bit-error-rate",
        type=float,
        default=0.01,
        help="Bit error rate used by noisy channel",
    )
    comms_key_agreement.add_argument(
        "--seed", type=int, help="Optional deterministic seed for channel randomness"
    )
    comms_key_agreement.add_argument(
        "--encaps-message-hex",
        help="Optional deterministic 32-byte ML-KEM message as hex",
    )
    comms_key_agreement.add_argument(
        "--server-aseed", help="Optional deterministic ML-KEM keygen seed"
    )
    comms_key_agreement.add_argument(
        "--server-zseed", help="Optional deterministic ML-KEM fallback seed"
    )
    comms_key_agreement.add_argument(
        "--server-dsa-aseed", help="Optional deterministic ML-DSA keygen seed"
    )
    comms_key_agreement.add_argument(
        "--server-signing-rnd", help="Optional deterministic ML-DSA signing randomness"
    )
    comms_key_agreement.add_argument(
        "--include-events",
        action="store_true",
        help="Include per-run protocol event logs in JSON output",
    )
    comms_key_agreement.set_defaults(handler=_handle_comms_key_agreement)

    comms_group_key_agreement = comms_subparsers.add_parser(
        "group-key-agreement",
        help="Run a multi-entity ML-KEM group key agreement simulation",
    )
    comms_group_key_agreement.add_argument(
        "--channel",
        default="perfect",
        choices=["perfect", "noisy", "adversarial"],
        help="Channel model to simulate",
    )
    comms_group_key_agreement.add_argument(
        "--kem-params", default="ML-KEM-768", help="ML-KEM parameter preset"
    )
    comms_group_key_agreement.add_argument(
        "--runs", type=int, default=1, help="Number of group handshake runs"
    )
    comms_group_key_agreement.add_argument(
        "--members", type=int, default=3, help="Number of group members"
    )
    comms_group_key_agreement.add_argument(
        "--member-prefix", default="member", help="Prefix for generated member IDs"
    )
    comms_group_key_agreement.add_argument(
        "--noisy-bit-error-rate",
        type=float,
        default=0.01,
        help="Bit error rate used by noisy channel",
    )
    comms_group_key_agreement.add_argument(
        "--seed", type=int, help="Optional deterministic seed for channel randomness"
    )
    comms_group_key_agreement.add_argument(
        "--group-seed-hex",
        help="Optional deterministic 32-byte group seed as hex",
    )
    comms_group_key_agreement.add_argument(
        "--member-seed-prefix",
        help="Optional deterministic per-member keygen seed prefix",
    )
    comms_group_key_agreement.add_argument(
        "--include-events",
        action="store_true",
        help="Include per-run protocol event logs in JSON output",
    )
    comms_group_key_agreement.set_defaults(handler=_handle_comms_group_key_agreement)

    comms_group_export_transcript = comms_subparsers.add_parser(
        "group-export-transcript",
        help="Run a group session and export its transcript document",
    )
    comms_group_export_transcript.add_argument(
        "--channel",
        default="perfect",
        choices=["perfect", "noisy", "adversarial"],
        help="Channel model to simulate",
    )
    comms_group_export_transcript.add_argument(
        "--kem-params", default="ML-KEM-768", help="ML-KEM parameter preset"
    )
    comms_group_export_transcript.add_argument(
        "--members", type=int, default=3, help="Number of group members"
    )
    comms_group_export_transcript.add_argument(
        "--member-prefix", default="member", help="Prefix for generated member IDs"
    )
    comms_group_export_transcript.add_argument(
        "--noisy-bit-error-rate",
        type=float,
        default=0.01,
        help="Bit error rate used by noisy channel",
    )
    comms_group_export_transcript.add_argument(
        "--seed", type=int, help="Optional deterministic seed for channel randomness"
    )
    comms_group_export_transcript.add_argument(
        "--group-seed-hex",
        help="Optional deterministic 32-byte group seed as hex",
    )
    comms_group_export_transcript.add_argument(
        "--member-seed-prefix",
        help="Optional deterministic per-member keygen seed prefix",
    )
    comms_group_export_transcript.add_argument(
        "--output", type=Path, help="Optional output file"
    )
    comms_group_export_transcript.set_defaults(
        handler=_handle_comms_group_export_transcript
    )

    comms_group_replay_transcript = comms_subparsers.add_parser(
        "group-replay-transcript",
        help="Replay a previously exported group transcript document",
    )
    comms_group_replay_transcript.add_argument(
        "--input", type=Path, required=True, help="Input transcript document path"
    )
    comms_group_replay_transcript.set_defaults(
        handler=_handle_comms_group_replay_transcript
    )

    comms_group_broadcast = comms_subparsers.add_parser(
        "group-broadcast",
        help="Run a group session and produce authenticated broadcast tags",
    )
    comms_group_broadcast.add_argument(
        "--channel",
        default="perfect",
        choices=["perfect", "noisy", "adversarial"],
        help="Channel model to simulate",
    )
    comms_group_broadcast.add_argument(
        "--kem-params", default="ML-KEM-768", help="ML-KEM parameter preset"
    )
    comms_group_broadcast.add_argument(
        "--members", type=int, default=3, help="Number of group members"
    )
    comms_group_broadcast.add_argument(
        "--member-prefix", default="member", help="Prefix for generated member IDs"
    )
    comms_group_broadcast.add_argument(
        "--noisy-bit-error-rate",
        type=float,
        default=0.01,
        help="Bit error rate used by noisy channel",
    )
    comms_group_broadcast.add_argument(
        "--seed", type=int, help="Optional deterministic seed for channel randomness"
    )
    comms_group_broadcast.add_argument(
        "--group-seed-hex",
        help="Optional deterministic 32-byte group seed as hex",
    )
    comms_group_broadcast.add_argument(
        "--member-seed-prefix",
        help="Optional deterministic per-member keygen seed prefix",
    )
    msg_group = comms_group_broadcast.add_mutually_exclusive_group(required=True)
    msg_group.add_argument("--message", help="Broadcast message as UTF-8 text")
    msg_group.add_argument("--message-hex", help="Broadcast message as hex")
    comms_group_broadcast.add_argument(
        "--label", default="broadcast", help="Broadcast label for domain separation"
    )
    comms_group_broadcast.set_defaults(handler=_handle_comms_group_broadcast)

    comms_group_rekey = comms_subparsers.add_parser(
        "group-rekey",
        help="Run a group session and rekey after membership changes",
    )
    comms_group_rekey.add_argument(
        "--channel",
        default="perfect",
        choices=["perfect", "noisy", "adversarial"],
        help="Channel model to simulate",
    )
    comms_group_rekey.add_argument(
        "--kem-params", default="ML-KEM-768", help="ML-KEM parameter preset"
    )
    comms_group_rekey.add_argument(
        "--members", type=int, default=3, help="Number of group members"
    )
    comms_group_rekey.add_argument(
        "--member-prefix", default="member", help="Prefix for generated member IDs"
    )
    comms_group_rekey.add_argument(
        "--noisy-bit-error-rate",
        type=float,
        default=0.01,
        help="Bit error rate used by noisy channel",
    )
    comms_group_rekey.add_argument(
        "--seed", type=int, help="Optional deterministic seed for channel randomness"
    )
    comms_group_rekey.add_argument(
        "--group-seed-hex",
        help="Optional deterministic 32-byte group seed as hex",
    )
    comms_group_rekey.add_argument(
        "--member-seed-prefix",
        help="Optional deterministic per-member keygen seed prefix",
    )
    comms_group_rekey.add_argument(
        "--add-member",
        action="append",
        default=[],
        help="Add a member identifier to the next group session",
    )
    comms_group_rekey.add_argument(
        "--remove-member",
        action="append",
        default=[],
        help="Remove a member identifier from the next group session",
    )
    comms_group_rekey.set_defaults(handler=_handle_comms_group_rekey)

    experiment_parser = subparsers.add_parser(
        "experiment", help="Run experiment sweeps and adversary simulations"
    )
    experiment_subparsers = experiment_parser.add_subparsers(
        dest="experiment_command", required=True
    )

    experiment_parametric = experiment_subparsers.add_parser(
        "parametric-benchmarks",
        help="Sweep ML-KEM and ML-DSA benchmarks across parameter presets",
    )
    experiment_parametric.add_argument(
        "--kem-params",
        nargs="+",
        default=list(DEFAULT_ML_KEM_PARAMS),
        help="ML-KEM parameter presets to benchmark",
    )
    experiment_parametric.add_argument(
        "--dsa-params",
        nargs="+",
        default=list(DEFAULT_ML_DSA_PARAMS),
        help="ML-DSA parameter presets to benchmark",
    )
    experiment_parametric.add_argument(
        "--iterations", type=int, default=performance.DEFAULT_ITERATIONS
    )
    experiment_parametric.add_argument(
        "--warmup", type=int, default=performance.DEFAULT_WARMUP
    )
    experiment_parametric.set_defaults(handler=_handle_experiment_parametric_benchmarks)

    experiment_adversary = experiment_subparsers.add_parser(
        "adversary-simulations",
        help="Simulate lattice attacks under varying computational budgets",
    )
    experiment_adversary.add_argument(
        "--schemes",
        nargs="+",
        default=list(DEFAULT_SCHEMES),
        help="Scheme identifiers to include in the sweep",
    )
    experiment_adversary.add_argument(
        "--budget-exp",
        nargs="+",
        type=int,
        default=list(DEFAULT_BUDGET_POWERS),
        help="Budget exponents; each budget is 2^n bit operations",
    )
    experiment_adversary.set_defaults(handler=_handle_experiment_adversary_simulations)

    experiment_tls = experiment_subparsers.add_parser(
        "pq-tls-handshake",
        help="Simulate a TLS-style post-quantum or hybrid key exchange handshake",
    )
    experiment_tls.add_argument(
        "--mode",
        default="pq-only",
        choices=list(DEFAULT_TLS_MODES),
        help="Handshake key schedule mode",
    )
    experiment_tls.add_argument(
        "--kem-params",
        default="ML-KEM-768",
        help="ML-KEM parameter preset",
    )
    experiment_tls.add_argument(
        "--dsa-params",
        default="ML-DSA-87",
        help="ML-DSA parameter preset",
    )
    experiment_tls.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Number of handshake runs",
    )
    experiment_tls.add_argument(
        "--authenticate-server",
        action="store_true",
        help="Enable ML-DSA certificate verify stage",
    )
    experiment_tls.set_defaults(handler=_handle_experiment_tls_handshake)

    experiment_hybrid = experiment_subparsers.add_parser(
        "hybrid-scenarios",
        help="Compare classical-only, PQ-only, and hybrid handshake scenarios",
    )
    experiment_hybrid.add_argument(
        "--modes",
        nargs="+",
        default=list(DEFAULT_HYBRID_MODES),
        choices=list(DEFAULT_HYBRID_MODES),
        help="Scenario modes to include",
    )
    experiment_hybrid.add_argument(
        "--kem-params",
        default="ML-KEM-768",
        help="ML-KEM parameter preset",
    )
    experiment_hybrid.add_argument(
        "--dsa-params",
        default="ML-DSA-87",
        help="ML-DSA parameter preset",
    )
    experiment_hybrid.add_argument(
        "--iterations",
        type=int,
        default=1,
        help="Iterations per mode",
    )
    experiment_hybrid.set_defaults(handler=_handle_experiment_hybrid_scenarios)

    experiment_regression = experiment_subparsers.add_parser(
        "performance-regression",
        help="Track benchmark regressions against a baseline document",
    )
    experiment_regression.add_argument(
        "--baseline",
        type=Path,
        required=True,
        help="Baseline experiment JSON file (use experiment parametric-benchmarks output)",
    )
    experiment_regression.add_argument(
        "--threshold-ratio",
        type=float,
        default=1.15,
        help="Slowdown ratio considered a regression",
    )
    experiment_regression.add_argument(
        "--kem-params",
        nargs="+",
        default=list(DEFAULT_ML_KEM_PARAMS),
        help="ML-KEM parameter presets to benchmark",
    )
    experiment_regression.add_argument(
        "--dsa-params",
        nargs="+",
        default=list(DEFAULT_ML_DSA_PARAMS),
        help="ML-DSA parameter presets to benchmark",
    )
    experiment_regression.add_argument(
        "--iterations",
        type=int,
        default=1,
        help="Benchmark iterations",
    )
    experiment_regression.add_argument(
        "--warmup",
        type=int,
        default=0,
        help="Benchmark warmup iterations",
    )
    experiment_regression.set_defaults(
        handler=_handle_experiment_performance_regression
    )

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
