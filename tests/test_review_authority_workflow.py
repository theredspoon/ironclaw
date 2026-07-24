from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "review-authority.yml"
README = ROOT / "README.md"
LIGHTHOUSE_PIN_PLACEHOLDER = "__LIGHTHOUSE_GUARD_COMMIT__"
LIGHTHOUSE_GUARD_COMMIT = "b7938365ae4bfcc2b00aa59e08478fa127abfc0c"


class ReviewAuthorityWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_uses_base_controlled_pull_request_target_for_only_the_pilot(self) -> None:
        self.assertRegex(self.workflow, r"(?m)^  pull_request_target:\s*$")
        self.assertRegex(
            self.workflow,
            r"(?ms)^  pull_request_target:\s*\n    branches:\s*\n      - reborn-matrix-pilot\s*$",
        )
        self.assertNotRegex(self.workflow, r"(?m)^  pull_request:\s*$")
        self.assertRegex(self.workflow, r"(?m)^      - edited\s*$")

    def test_has_minimum_read_only_permissions_and_stable_job_name(self) -> None:
        self.assertRegex(
            self.workflow,
            r"(?ms)^permissions:\s*\n  contents: read\s*\n  pull-requests: read\s*$",
        )
        self.assertNotRegex(
            self.workflow,
            r"(?m)^\s*(actions|checks|contents|issues|pull-requests): write\s*$",
        )
        self.assertRegex(self.workflow, r"(?m)^    name: Review Authority\s*$")

    def test_checks_out_only_trusted_lighthouse_at_an_exact_commit(self) -> None:
        checkout_blocks = re.findall(
            r"(?ms)^\s+- name: .*?\n\s+uses: actions/checkout@[^\n]+\n"
            r"(?:(?!^\s+- name: ).)*",
            self.workflow,
        )
        self.assertEqual(len(checkout_blocks), 1)
        checkout = checkout_blocks[0]
        self.assertIn("repository: enjimi/lighthouse", checkout)
        self.assertIn("path: lighthouse-tools", checkout)
        self.assertIn("persist-credentials: false", checkout)
        self.assertNotIn("github.event.pull_request.head", checkout)
        self.assertNotIn("github.head_ref", checkout)

    def test_passes_event_values_as_quoted_data_to_the_trusted_guard(self) -> None:
        self.assertIn("GH_TOKEN: ${{ github.token }}", self.workflow)
        self.assertIn(
            "PR_NUMBER: ${{ github.event.pull_request.number }}", self.workflow
        )
        self.assertIn(
            "PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}", self.workflow
        )
        self.assertIn(
            "PR_BASE_REF: ${{ github.event.pull_request.base.ref }}", self.workflow
        )
        self.assertIn(
            "PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}", self.workflow
        )
        self.assertIn('--repository "$GITHUB_REPOSITORY"', self.workflow)
        self.assertIn('--pr "$PR_NUMBER"', self.workflow)
        self.assertIn('--expected-head "$PR_HEAD_SHA"', self.workflow)
        self.assertIn('--expected-base-ref "$PR_BASE_REF"', self.workflow)
        self.assertIn('--expected-base-sha "$PR_BASE_SHA"', self.workflow)
        self.assertIn("--allow-policy-change", self.workflow)
        self.assertIn("--protected-path deny.toml", self.workflow)
        self.assertIn(
            "--schema lighthouse-tools/schemas/required-check-policy.schema.json",
            self.workflow,
        )

    def test_never_checks_out_or_executes_candidate_content(self) -> None:
        prohibited = (
            "pull_request.head.repo",
            "github.event.pull_request.head.ref",
            "github.head_ref",
            "git checkout",
            "git fetch",
            "source ",
            "bash ",
            "sh ",
        )
        for value in prohibited:
            with self.subTest(value=value):
                self.assertNotIn(value, self.workflow)

    def test_all_third_party_actions_are_commit_pinned(self) -> None:
        uses = re.findall(r"(?m)^\s+uses: ([^\s#]+)", self.workflow)
        self.assertGreaterEqual(len(uses), 2)
        for action in uses:
            with self.subTest(action=action):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")

    def test_lighthouse_guard_pin_is_final_not_a_placeholder(self) -> None:
        self.assertNotIn(LIGHTHOUSE_PIN_PLACEHOLDER, self.workflow)
        self.assertIn(
            f"ref: {LIGHTHOUSE_GUARD_COMMIT}",
            self.workflow,
        )

    def test_docs_explain_authority_and_candidate_inertness(self) -> None:
        readme = README.read_text(encoding="utf-8")
        normalized = " ".join(readme.split())
        self.assertIn("Review Authority", normalized)
        self.assertIn("pull_request_target", normalized)
        self.assertIn("reborn-matrix-pilot", normalized)
        self.assertIn("exact base branch and base commit", normalized)
        self.assertIn("never checks out or executes pull request code", normalized)


if __name__ == "__main__":
    unittest.main()
