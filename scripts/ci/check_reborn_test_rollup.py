#!/usr/bin/env python3
"""Fail-closed decision logic for the Tests (Reborn) aggregate job."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence


CONSTITUENT_JOBS = (
    "package-matrix",
    "crate-tests",
    "root-reborn-parity-tests",
    "reborn-group-tests",
    "reborn-integration-coverage",
    "coverage-report",
    "webui-v2-js-tests",
    "qa-recorded-fixtures",
)
EXPECTED_JOBS = ("changes", *CONSTITUENT_JOBS)
KNOWN_RESULTS = frozenset(("success", "failure", "cancelled", "skipped"))


def validate_rollup(
    docs_only: bool,
    has_reborn_tests: bool,
    results: Mapping[str, str],
) -> None:
    """Raise ValueError unless the aggregate may report success."""
    missing = [name for name in EXPECTED_JOBS if name not in results]
    extras = [name for name in results if name not in EXPECTED_JOBS]
    if missing or extras:
        raise ValueError(
            f"job result set mismatch; missing={missing or 'none'}, "
            f"unexpected={extras or 'none'}"
        )

    for name in EXPECTED_JOBS:
        result = results[name]
        if result not in KNOWN_RESULTS:
            raise ValueError(f"{name} has unknown result {result!r}")

    if results["changes"] != "success":
        raise ValueError(f"changes did not succeed: {results['changes']}")

    interrupted = [
        f"{name}={results[name]}"
        for name in CONSTITUENT_JOBS
        if results[name] in {"failure", "cancelled"}
    ]
    if interrupted:
        raise ValueError(
            "scope fast-pass cannot mask failed or cancelled jobs: "
            + ", ".join(interrupted)
        )

    if docs_only:
        print("Docs-only change detected; Tests (Reborn) passes with skipped test jobs")
        return
    if not has_reborn_tests:
        print("No Reborn test scope detected; Tests (Reborn) passes with skipped test jobs")
        return

    failed = [
        f"{name}={results[name]}"
        for name in CONSTITUENT_JOBS
        if results[name] != "success"
    ]
    if failed:
        raise ValueError(
            "in-scope Reborn jobs must all succeed; unexpected results: "
            + ", ".join(failed)
        )

    print("All in-scope Reborn test jobs succeeded")


def parse_bool(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("expected exactly 'true' or 'false'")


def parse_results(values: Sequence[str]) -> dict[str, str]:
    results: dict[str, str] = {}
    for value in values:
        name, separator, result = value.partition("=")
        if not separator or not name or not result:
            raise ValueError(f"invalid --result value {value!r}; expected JOB=RESULT")
        if name in results:
            raise ValueError(f"duplicate result for {name}")
        results[name] = result
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--docs-only", required=True, type=parse_bool)
    parser.add_argument("--has-reborn-tests", required=True, type=parse_bool)
    parser.add_argument("--result", action="append", default=[], metavar="JOB=RESULT")
    args = parser.parse_args()

    try:
        validate_rollup(
            docs_only=args.docs_only,
            has_reborn_tests=args.has_reborn_tests,
            results=parse_results(args.result),
        )
    except ValueError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
