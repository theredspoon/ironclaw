#!/usr/bin/env python3
"""Contract tests for the Reborn PR test roll-up."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "ci" / "check_reborn_test_rollup.py"
WORKFLOW = ROOT / ".github" / "workflows" / "reborn-tests.yml"

CONSTITUENTS = (
    "package-matrix",
    "crate-tests",
    "root-reborn-parity-tests",
    "reborn-group-tests",
    "reborn-integration-coverage",
    "coverage-report",
    "webui-v2-js-tests",
    "qa-recorded-fixtures",
)


def load_checker():
    spec = importlib.util.spec_from_file_location("check_reborn_test_rollup", CHECKER)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {CHECKER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RollupDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.checker = load_checker()

    def successful_results(self) -> dict[str, str]:
        return {"changes": "success", **dict.fromkeys(CONSTITUENTS, "success")}

    def test_in_scope_success_passes(self) -> None:
        self.checker.validate_rollup(
            docs_only=False,
            has_reborn_tests=True,
            results=self.successful_results(),
        )

    def test_each_unexpected_constituent_result_fails_closed(self) -> None:
        for job in CONSTITUENTS:
            for result in ("failure", "cancelled", "skipped"):
                with self.subTest(job=job, result=result):
                    results = self.successful_results()
                    results[job] = result
                    with self.assertRaisesRegex(ValueError, job):
                        self.checker.validate_rollup(
                            docs_only=False,
                            has_reborn_tests=True,
                            results=results,
                        )

    def test_fast_pass_never_masks_failed_or_cancelled_job(self) -> None:
        for docs_only, has_reborn_tests in ((True, False), (False, False)):
            for job in CONSTITUENTS:
                for result in ("failure", "cancelled"):
                    with self.subTest(
                        docs_only=docs_only,
                        job=job,
                        result=result,
                    ):
                        results = {
                            "changes": "success",
                            **dict.fromkeys(CONSTITUENTS, "skipped"),
                        }
                        results[job] = result
                        with self.assertRaisesRegex(ValueError, job):
                            self.checker.validate_rollup(
                                docs_only=docs_only,
                                has_reborn_tests=has_reborn_tests,
                                results=results,
                            )

    def test_scope_detection_must_succeed_even_for_fast_pass(self) -> None:
        for result in ("failure", "cancelled", "skipped"):
            with self.subTest(result=result):
                results = self.successful_results()
                results["changes"] = result
                with self.assertRaisesRegex(ValueError, "changes"):
                    self.checker.validate_rollup(
                        docs_only=True,
                        has_reborn_tests=False,
                        results=results,
                    )

    def test_docs_only_legitimately_skips_constituents(self) -> None:
        results = {"changes": "success", **dict.fromkeys(CONSTITUENTS, "skipped")}
        self.checker.validate_rollup(
            docs_only=True,
            has_reborn_tests=False,
            results=results,
        )

    def test_out_of_scope_legitimately_skips_constituents(self) -> None:
        results = {"changes": "success", **dict.fromkeys(CONSTITUENTS, "skipped")}
        self.checker.validate_rollup(
            docs_only=False,
            has_reborn_tests=False,
            results=results,
        )

    def test_missing_or_unknown_results_fail_closed(self) -> None:
        results = self.successful_results()
        del results["crate-tests"]
        with self.assertRaisesRegex(ValueError, "crate-tests"):
            self.checker.validate_rollup(False, True, results)

        results = self.successful_results()
        results["crate-tests"] = "neutral"
        with self.assertRaisesRegex(ValueError, "neutral"):
            self.checker.validate_rollup(False, True, results)


class WorkflowContractTests(unittest.TestCase):
    def test_pilot_pull_requests_trigger_real_workflow(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        pull_request = workflow.split("  pull_request:", 1)[1].split(
            "  merge_group:", 1
        )[0]
        self.assertIn("      - main", pull_request)
        self.assertIn("      - reborn-matrix-pilot", pull_request)

    def test_rollup_always_reports_and_calls_tested_checker(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        aggregate = workflow.split("  reborn-tests:", 1)[1]
        self.assertIn("    name: Tests (Reborn)", aggregate)
        self.assertIn("    if: always()", aggregate)
        self.assertIn("scripts/ci/check_reborn_test_rollup.py", aggregate)


if __name__ == "__main__":
    unittest.main()
