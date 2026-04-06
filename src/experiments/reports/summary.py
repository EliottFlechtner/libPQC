"""Report helpers for experiment outputs."""

from __future__ import annotations

from collections import defaultdict
from typing import Sequence


def render_parametric_benchmark_report(records: Sequence[dict[str, object]]) -> str:
    lines = ["PARAMETRIC BENCHMARK SWEEP", "=" * 80, ""]
    grouped: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for record in records:
        grouped[(str(record["family"]), str(record["operation"]))].append(record)

    for (family, operation), items in grouped.items():
        lines.append(f"{family.upper()} / {operation}")
        lines.append("-" * 80)
        lines.append("| params | mean ms | baseline | slowdown | throughput ops/s |")
        lines.append("| --- | ---: | ---: | ---: | ---: |")
        for item in items:
            lines.append(
                "| {params} | {mean:.3f} | {baseline:.3f} | {slowdown:.3f} | {throughput:.2f} |".format(
                    params=item["params"],
                    mean=float(item["mean_seconds"]) * 1000.0,
                    baseline=float(item["baseline_mean_seconds"]) * 1000.0,
                    slowdown=float(item["relative_slowdown"]),
                    throughput=float(item["throughput_ops_per_second"]),
                )
            )
        lines.append("")

    return "\n".join(lines).rstrip()


def render_adversary_budget_report(records: Sequence[dict[str, object]]) -> str:
    lines = ["LATTICE ADVERSARY BUDGET SWEEP", "=" * 80, ""]
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for record in records:
        grouped[str(record["scheme"])].append(record)

    for scheme, items in grouped.items():
        lines.append(scheme.upper())
        lines.append("-" * 80)
        lines.append("| budget 2^n | LLL | BKZ-200 | max affordable BKZ block |")
        lines.append("| --- | --- | --- | ---: |")
        for item in items:
            lines.append(
                "| 2^{power} | {lll} | {bkz} | {block} |".format(
                    power=item["budget_power"],
                    lll="yes" if item["lll_affordable"] else "no",
                    bkz="yes" if item["bkz_200_affordable"] else "no",
                    block=(
                        item["max_affordable_block_size"]
                        if item["max_affordable_block_size"] is not None
                        else "-"
                    ),
                )
            )
        lines.append("")

    return "\n".join(lines).rstrip()


def render_tls_handshake_report(record: dict[str, object]) -> str:
    draft_policy = dict(record.get("draft_policy") or {})
    policy_status = str(draft_policy.get("status", "unknown"))
    policy_recommendation = str(
        draft_policy.get("recommended_draft", record.get("draft", "unknown"))
    )
    lines = [
        "POST-QUANTUM TLS HANDSHAKE",
        "=" * 80,
        f"Mode: {record['mode']}",
        f"KEM: {record['kem_params']}",
        f"DSA: {record['dsa_params']}",
        f"Runs: {record['runs']}",
        f"Successes: {record['handshake_successes']}",
        f"Failures: {record['handshake_failures']}",
        f"Shared secret match rate: {float(record['shared_secret_match_rate']):.3f}",
        f"Mean latency (ms): {float(record['mean_seconds']) * 1000.0:.3f}",
        f"Estimated handshake bytes: {record['estimated_total_bytes']}",
        f"Ciphersuite: {record['ciphersuite']}",
        f"Draft: {record['draft']}",
        f"Compatibility: {'ok' if record['compatibility']['compatible'] else 'failed'}",
        f"Draft policy: {policy_status}",
        f"Draft policy enforced: {'yes' if draft_policy.get('enforced') else 'no'}",
        f"Recommended draft: {policy_recommendation}",
        f"Flight count: {record['flight_count']}",
        f"Transcript hash: {record['transcript_hash_hex']}",
        "Semantic bindings:",
    ]
    policy_notes = list(draft_policy.get("warnings", [])) + list(
        draft_policy.get("issues", [])
    )
    if policy_notes:
        lines.append("Draft policy notes:")
        for note in policy_notes:
            lines.append(f"- {note}")
    for binding in record["semantic_bindings"]:
        lines.append(f"- {binding}")
    return "\n".join(lines)


def render_hybrid_scenarios_report(records: Sequence[dict[str, object]]) -> str:
    lines = ["HYBRID PQ SCENARIO SWEEP", "=" * 80, ""]
    lines.append(
        "| requested | negotiated | attack | detected | success | mean ms | effective bits | downgrade score | notes |"
    )
    lines.append("| --- | --- | --- | --- | --- | ---: | ---: | ---: | --- |")
    for record in records:
        lines.append(
            "| {mode} | {negotiated} | {variant} | {detected} | {succeeded} | {mean:.3f} | {effective} | {score:.2f} | {notes} |".format(
                mode=record["mode"],
                negotiated=record["negotiated_mode"],
                variant=record["attack_variant"],
                detected="yes" if record["attack_detected"] else "no",
                succeeded="yes" if record["attack_succeeded"] else "no",
                mean=float(record["mean_seconds"]) * 1000.0,
                effective=record["effective_security_bits"],
                score=float(record["downgrade_resistance_score"]),
                notes="; ".join(str(note) for note in record.get("attack_notes", [])),
            )
        )
    return "\n".join(lines)


def render_performance_regression_report(payload: dict[str, object]) -> str:
    lines = [
        "PERFORMANCE REGRESSION TRACKING",
        "=" * 80,
        f"Threshold ratio: {float(payload['threshold_ratio']):.3f}",
        f"Comparisons: {payload['comparison_count']}",
        f"Regressions: {payload['regression_count']}",
        f"Missing entries: {len(payload['missing_in_current'])}",
        f"New entries: {len(payload['new_in_current'])}",
        "",
        "| family | operation | params | baseline ms | current ms | slowdown | regression |",
        "| --- | --- | --- | ---: | ---: | ---: | --- |",
    ]
    for delta in payload["deltas"]:
        lines.append(
            "| {family} | {operation} | {params} | {baseline:.3f} | {current:.3f} | {ratio:.3f} | {regression} |".format(
                family=delta["family"],
                operation=delta["operation"],
                params=delta["params"],
                baseline=float(delta["baseline_mean_seconds"]) * 1000.0,
                current=float(delta["current_mean_seconds"]) * 1000.0,
                ratio=float(delta["slowdown_ratio"]),
                regression="yes" if delta["regression"] else "no",
            )
        )
    return "\n".join(lines)
