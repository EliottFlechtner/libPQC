"""Run per-vector conformance checks and print a compact summary table.

This script executes the existing unittest-based conformance suites one vector
file at a time by setting ``LIBPQC_KAT_VECTOR_FILTER``. It reports pass/fail,
processed record counts, and per-file elapsed time.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# Ensure repository root is importable when this script is run as
# `python3 scripts/conformance_summary.py`.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.conformance.common.kat import require_rsp_vectors


DONE_PATTERN = re.compile(
    r"\[(?P<tag>ML-KEM|ML-DSA)\]\s+(?P<file>[^:]+): done \((?P<body>.*)\)"
)


@dataclass(frozen=True)
class SuiteConfig:
    scheme_dir: str
    suite_tag: str
    module_name: str


@dataclass(frozen=True)
class VectorResult:
    suite_tag: str
    vector_name: str
    status: str
    processed: str
    elapsed_s: str


def _parse_done_metrics(
    output: str, suite_tag: str, vector_name: str
) -> tuple[str, str]:
    processed = "-"
    elapsed_s = "-"

    for line in output.splitlines():
        match = DONE_PATTERN.search(line)
        if not match:
            continue
        if match.group("tag") != suite_tag or match.group("file") != vector_name:
            continue

        body = match.group("body")
        for chunk in body.split(","):
            if "=" not in chunk:
                continue
            key, value = chunk.strip().split("=", 1)
            if key == "processed":
                processed = value
            elif key == "elapsed_s":
                elapsed_s = value
    return processed, elapsed_s


def _run_vector(
    *,
    config: SuiteConfig,
    vector_path: Path,
    max_records: int,
    require_full: bool,
) -> VectorResult:
    env = os.environ.copy()
    env["LIBPQC_KAT_PROGRESS"] = "1"
    env["LIBPQC_KAT_TIMING"] = "1"
    env["LIBPQC_KAT_MAX_RECORDS"] = str(max_records)
    env["LIBPQC_KAT_VECTOR_FILTER"] = rf"^{re.escape(vector_path.name)}$"
    if require_full:
        env["LIBPQC_KAT_REQUIRE_FULL"] = "1"
    else:
        env.pop("LIBPQC_KAT_REQUIRE_FULL", None)

    cmd = [sys.executable, "-m", "unittest", config.module_name]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)

    combined = f"{proc.stdout}\n{proc.stderr}"
    processed, elapsed_s = _parse_done_metrics(
        combined, config.suite_tag, vector_path.name
    )
    status = "PASS" if proc.returncode == 0 else "FAIL"
    return VectorResult(
        suite_tag=config.suite_tag,
        vector_name=vector_path.name,
        status=status,
        processed=processed,
        elapsed_s=elapsed_s,
    )


def _print_summary(rows: list[VectorResult]) -> None:
    print("suite   vector_file                           status processed elapsed_s")
    print("------  ------------------------------------ ------ --------- ---------")
    for row in rows:
        print(
            f"{row.suite_tag:<6} "
            f"{row.vector_name:<36} "
            f"{row.status:<6} "
            f"{row.processed:>9} "
            f"{row.elapsed_s:>9}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize KAT conformance per vector file"
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=2,
        help="Maximum records per vector file (default: 2)",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Enable full mode (sets LIBPQC_KAT_REQUIRE_FULL=1)",
    )
    args = parser.parse_args()

    if args.max_records <= 0:
        raise ValueError("--max-records must be positive")

    suite_configs = [
        SuiteConfig(
            scheme_dir="ml_kem",
            suite_tag="ML-KEM",
            module_name="tests.conformance.test_ml_kem_kat",
        ),
        SuiteConfig(
            scheme_dir="ml_dsa",
            suite_tag="ML-DSA",
            module_name="tests.conformance.test_ml_dsa_kat",
        ),
    ]

    results: list[VectorResult] = []
    for config in suite_configs:
        for vector_path in require_rsp_vectors(config.scheme_dir):
            results.append(
                _run_vector(
                    config=config,
                    vector_path=vector_path,
                    max_records=args.max_records,
                    require_full=args.full,
                )
            )

    _print_summary(results)
    return 0 if all(row.status == "PASS" for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
