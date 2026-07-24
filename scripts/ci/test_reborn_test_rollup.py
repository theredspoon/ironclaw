#!/usr/bin/env python3
"""Contract tests for the Reborn PR test roll-up."""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path
from types import ModuleType


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


def extract_indented_block(text: str, header: str, indent: int) -> str:
    """Return one YAML mapping block, stopping at its next sibling."""
    lines = text.splitlines(keepends=True)
    marker = f"{' ' * indent}{header}:"
    start = next(
        (index for index, line in enumerate(lines) if line.rstrip() == marker),
        None,
    )
    if start is None:
        raise AssertionError(f"missing YAML block {header!r}")
    end = len(lines)
    sibling = re.compile(rf"^ {{{indent}}}[A-Za-z0-9_-]+:\s*(?:#.*)?$")
    for index in range(start + 1, len(lines)):
        if sibling.fullmatch(lines[index].rstrip("\n")):
            end = index
            break
    return "".join(lines[start:end])


def aggregate_shape(workflow: str) -> tuple[tuple[str, ...], dict[str, str], tuple[str, ...], str]:
    aggregate = extract_indented_block(workflow, "reborn-tests", 2)
    needs_block = extract_indented_block(aggregate, "needs", 4)
    needs = tuple(
        match.group(1)
        for line in needs_block.splitlines()
        if (match := re.fullmatch(r"\s{6}- ([a-z0-9-]+)", line))
    )
    env_to_job = {
        match.group(1): match.group(2)
        for match in re.finditer(
            r"(?m)^\s{10}([A-Z0-9_]+): \$\{\{ needs\.([a-z0-9-]+)\.result \}\}$",
            aggregate,
        )
    }
    result_pairs = tuple(
        (match.group(1), match.group(2))
        for match in re.finditer(
            r'--result "([a-z0-9-]+)=\$\{([A-Z0-9_]+)\}"',
            aggregate,
        )
    )
    result_jobs = tuple(job for job, _environment in result_pairs)
    for job, environment in result_pairs:
        if env_to_job.get(environment) != job:
            raise AssertionError(
                f"--result {job} uses {environment}, which maps to "
                f"{env_to_job.get(environment)!r}"
            )
    run_match = re.search(
        r"(?ms)^\s{8}run: \|\n(?P<body>(?:^\s{10}.*\n?)+)",
        aggregate,
    )
    if run_match is None:
        raise AssertionError("aggregate has no run block")
    run_body = "".join(
        line[10:] if line.strip() else "\n"
        for line in run_match.group("body").splitlines(keepends=True)
    )
    return needs, env_to_job, result_jobs, run_body


def assert_workflow_parity(workflow: str, checker: ModuleType) -> None:
    needs, env_to_job, result_jobs, _run_body = aggregate_shape(workflow)
    expected = tuple(checker.EXPECTED_JOBS)
    test_matrix = ("changes", *CONSTITUENTS)
    if needs != expected:
        raise AssertionError(f"aggregate needs {needs!r} != production {expected!r}")
    if tuple(env_to_job.values()) != expected:
        raise AssertionError(
            f"aggregate result env {tuple(env_to_job.values())!r} != production {expected!r}"
        )
    if result_jobs != expected:
        raise AssertionError(
            f"aggregate --result jobs {result_jobs!r} != production {expected!r}"
        )
    if test_matrix != expected:
        raise AssertionError(f"test matrix {test_matrix!r} != production {expected!r}")


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
    @classmethod
    def setUpClass(cls) -> None:
        cls.checker = load_checker()
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_pilot_pull_requests_trigger_real_workflow(self) -> None:
        pull_request = extract_indented_block(self.workflow, "pull_request", 2)
        self.assertIn("      - main", pull_request)
        self.assertIn("      - reborn-matrix-pilot", pull_request)
        self.assertIn("      - edited", pull_request)

    def test_rollup_always_reports_and_calls_tested_checker(self) -> None:
        aggregate = extract_indented_block(self.workflow, "reborn-tests", 2)
        self.assertIn("    name: Tests (Reborn)", aggregate)
        self.assertIn("    if: always()", aggregate)
        self.assertIn("scripts/ci/check_reborn_test_rollup.py", aggregate)

    def test_pull_request_concurrency_is_number_specific_and_update_stable(self) -> None:
        concurrency = extract_indented_block(self.workflow, "concurrency", 0)
        self.assertIn(
            "inputs.ref || github.event.pull_request.number || github.head_ref || github.ref",
            concurrency,
        )
        self.assertNotIn("github.sha", concurrency)

    def test_crate_buckets_install_wasip2_target_and_pinned_wasm_tools(self) -> None:
        crate_tests = extract_indented_block(self.workflow, "crate-tests", 2)
        self.assertRegex(
            crate_tests,
            (
                r"(?ms)^      - name: Install Rust\n"
                r"        uses: dtolnay/rust-toolchain@"
                r"29eef336d9b2848a0b548edc03f92a220660cdb8 # stable\n"
                r"        with:\n"
                r"          components: llvm-tools-preview\n"
                r"          targets: wasm32-wasip2$"
            ),
        )
        self.assertRegex(
            crate_tests,
            (
                r"(?ms)^      - name: Install wasm-tools\n"
                r"        uses: taiki-e/install-action@"
                r"62b0f2dec647a8e604c6a0fda0e38530180dce20 # v2\n"
                r"        with:\n"
                r"          tool: wasm-tools@1\.246\.2\n"
                r"          checksum: true$"
            ),
        )

    def test_aggregate_extraction_stops_at_next_job(self) -> None:
        mutated = (
            self.workflow
            + "\n  unrelated-job:\n"
            + "    run: scripts/ci/check_reborn_test_rollup.py --result fake=${FAKE}\n"
        )
        aggregate = extract_indented_block(mutated, "reborn-tests", 2)
        self.assertNotIn("unrelated-job", aggregate)
        self.assertNotIn("--result fake=", aggregate)

    def test_workflow_job_sets_match_production_and_test_matrix_exactly(self) -> None:
        assert_workflow_parity(self.workflow, self.checker)

    def test_job_set_drift_mutations_fail_parity(self) -> None:
        mutations = {
            "removed": self.workflow.replace("      - crate-tests\n", "", 1),
            "added": self.workflow.replace(
                "      - crate-tests\n",
                "      - crate-tests\n      - invented-tests\n",
                1,
            ),
            "renamed": self.workflow.replace("crate-tests", "renamed-crate-tests"),
        }
        for name, mutated in mutations.items():
            with self.subTest(name=name), self.assertRaises(AssertionError):
                assert_workflow_parity(mutated, self.checker)


class RollupCliContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.needs, cls.env_to_job, cls.result_jobs, cls.run_body = aggregate_shape(
            workflow
        )

    def workflow_environment(
        self,
        *,
        docs_only: str = "false",
        has_reborn_tests: str = "true",
        overrides: dict[str, str] | None = None,
    ) -> dict[str, str]:
        results = dict.fromkeys(self.needs, "success")
        results.update(overrides or {})
        environment = {
            variable: results[job] for variable, job in self.env_to_job.items()
        }
        return {
            **os.environ,
            **environment,
            "DOCS_ONLY": docs_only,
            "HAS_REBORN_TESTS": has_reborn_tests,
        }

    def run_workflow_shape(
        self,
        *,
        overrides: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "-eu", "-o", "pipefail", "-c", self.run_body],
            cwd=ROOT,
            env=self.workflow_environment(overrides=overrides),
            text=True,
            capture_output=True,
            check=False,
        )

    def checker_command(self, results: list[str]) -> list[str]:
        command = [
            sys.executable,
            str(CHECKER),
            "--docs-only",
            "false",
            "--has-reborn-tests",
            "true",
        ]
        for result in results:
            command.extend(("--result", result))
        return command

    def test_exact_workflow_command_shape_executes_production_cli(self) -> None:
        completed = self.run_workflow_shape()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("All in-scope Reborn test jobs succeeded", completed.stdout)

    def test_exact_workflow_command_shape_reports_failure_and_unknown(self) -> None:
        failed = self.run_workflow_shape(overrides={"crate-tests": "cancelled"})
        self.assertEqual(failed.returncode, 2)
        self.assertIn("crate-tests=cancelled", failed.stderr)

        unknown = self.run_workflow_shape(overrides={"crate-tests": "neutral"})
        self.assertEqual(unknown.returncode, 2)
        self.assertIn("crate-tests has unknown result 'neutral'", unknown.stderr)

    def test_cli_rejects_duplicate_and_missing_results_with_diagnostics(self) -> None:
        results = [f"{job}=success" for job in self.result_jobs]
        duplicate = subprocess.run(
            self.checker_command([*results, "crate-tests=success"]),
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(duplicate.returncode, 2)
        self.assertIn("duplicate result for crate-tests", duplicate.stderr)

        missing = subprocess.run(
            self.checker_command(
                [result for result in results if not result.startswith("crate-tests=")]
            ),
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(missing.returncode, 2)
        self.assertIn("missing=['crate-tests']", missing.stderr)


if __name__ == "__main__":
    unittest.main()
