#!/usr/bin/env python3
"""Deterministic sabotage tests for the standalone publication verifier."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SOURCE_HARNESS = Path(__file__).resolve().parent
SOURCE_REPOSITORY = SOURCE_HARNESS.parent.parent
SOURCE_DOCS = SOURCE_REPOSITORY / "docs/internal/research/icwm-g0c"
GENERATED_DIRECTORIES = {"target", "__pycache__", ".pytest_cache"}
SELF_FILES = {"PUBLICATION-MANIFEST.json", "PUBLICATION-MANIFEST.sha256"}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class PublicationVerifierSabotageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name) / "repository"
        self.harness = self.repository / "harness/icwm-g0c"
        self.docs = self.repository / "docs/internal/research/icwm-g0c"
        shutil.copytree(
            SOURCE_HARNESS,
            self.harness,
            ignore=shutil.ignore_patterns(*GENERATED_DIRECTORIES),
        )
        shutil.copytree(SOURCE_DOCS, self.docs)
        self.capture_manifest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def relative(self, path: Path) -> str:
        return Path(os.path.relpath(path, self.harness)).as_posix()

    def payload_files(self) -> list[Path]:
        files: list[Path] = []
        for root in (self.harness, self.docs):
            for path in root.rglob("*"):
                parts = path.relative_to(root).parts
                if any(part in GENERATED_DIRECTORIES for part in parts):
                    continue
                if path.is_symlink() or not path.is_file():
                    continue
                if root == self.harness and path.parent == root and path.name in SELF_FILES:
                    continue
                files.append(path)
        return sorted(files, key=lambda path: self.relative(path).encode("utf-8"))

    def capture_manifest(self) -> None:
        manifest = json.loads(
            (SOURCE_HARNESS / "PUBLICATION-MANIFEST.json").read_bytes()
        )
        entries = []
        for path in self.payload_files():
            data = path.read_bytes()
            entries.append(
                {
                    "bytes": len(data),
                    "path": self.relative(path),
                    "sha256": sha256(data),
                }
            )
        manifest["entries"] = entries
        manifest["exclusions"] = {
            "self_files_relative_to_harness_root": sorted(SELF_FILES),
            "generated_directory_exact_basenames": sorted(GENERATED_DIRECTORIES),
        }
        aggregate_input = "".join(
            f"{entry['sha256']}  {entry['path']}\n" for entry in entries
        ).encode("utf-8")
        manifest["aggregate_sha256"] = sha256(aggregate_input)
        manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
        (self.harness / "PUBLICATION-MANIFEST.json").write_bytes(manifest_bytes)
        (self.harness / "PUBLICATION-MANIFEST.sha256").write_text(
            f"{sha256(manifest_bytes)}  PUBLICATION-MANIFEST.json\n",
            encoding="utf-8",
        )

    def refresh_detached(self) -> None:
        data = (self.harness / "PUBLICATION-MANIFEST.json").read_bytes()
        (self.harness / "PUBLICATION-MANIFEST.sha256").write_text(
            f"{sha256(data)}  PUBLICATION-MANIFEST.json\n", encoding="utf-8"
        )

    def write_manifest(self, manifest: dict[str, object]) -> None:
        (self.harness / "PUBLICATION-MANIFEST.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        self.refresh_detached()

    def run_verifier(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(self.harness / "verify-publication.py")],
            cwd=self.repository,
            text=True,
            capture_output=True,
            check=False,
        )

    def assert_rejected(self, expected: str) -> None:
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected, result.stdout + result.stderr)

    def test_clean_snapshot_is_accepted(self) -> None:
        self.assertEqual(self.run_verifier().returncode, 0)

    def test_detached_digest_sabotage_is_rejected(self) -> None:
        (self.harness / "PUBLICATION-MANIFEST.sha256").write_text(
            f"{'0' * 64}  PUBLICATION-MANIFEST.json\n", encoding="utf-8"
        )
        self.assert_rejected("publication manifest digest mismatch")

    def test_entry_sabotage_is_rejected(self) -> None:
        (self.harness / "README.md").write_text("sabotaged\n", encoding="utf-8")
        self.assert_rejected("publication artifact mismatch")

    def test_aggregate_sabotage_is_rejected(self) -> None:
        path = self.harness / "PUBLICATION-MANIFEST.json"
        manifest = json.loads(path.read_bytes())
        manifest["aggregate_sha256"] = "0" * 64
        self.write_manifest(manifest)
        self.assert_rejected("publication aggregate mismatch")

    def test_unlisted_payload_is_rejected(self) -> None:
        (self.harness / "UNLISTED.txt").write_text("unlisted\n", encoding="utf-8")
        self.assert_rejected("unlisted publication payload files")

    def test_missing_listed_payload_is_rejected(self) -> None:
        (self.harness / "README.md").unlink()
        self.assert_rejected("manifest entries outside declared payload roots")

    def test_outside_entry_is_rejected(self) -> None:
        path = self.harness / "PUBLICATION-MANIFEST.json"
        manifest = json.loads(path.read_bytes())
        manifest["entries"].append(
            {"bytes": 0, "path": "../../../outside", "sha256": sha256(b"")}
        )
        manifest["entries"].sort(key=lambda entry: entry["path"].encode("utf-8"))
        self.write_manifest(manifest)
        self.assert_rejected("manifest entries outside declared payload roots")

    def test_symlink_payload_is_rejected(self) -> None:
        (self.harness / "linked").symlink_to(self.harness / "README.md")
        self.assert_rejected("publication payload contains unsupported symlink")

    def test_named_evidence_sabotage_is_rejected(self) -> None:
        path = self.harness / "fixtures/CONTROL-RESULT.json"
        result = json.loads(path.read_bytes())
        result["dependency_graph"]["sha256"] = "0" * 64
        path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        self.capture_manifest()
        self.assert_rejected("named evidence hash mismatch: dependency_graph")


if __name__ == "__main__":
    unittest.main()
