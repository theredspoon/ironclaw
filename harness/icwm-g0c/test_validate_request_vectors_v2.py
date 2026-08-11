#!/usr/bin/env python3
"""Sabotage tests for the v2 request-vector semantic validator."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("validator", ROOT / "validate-request-vectors-v2.py")
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)
BASE = json.loads((ROOT / "fixtures/REQUEST-VECTORS-v2.json").read_bytes())


class SemanticValidatorSabotageTests(unittest.TestCase):
    def corpus(self):
        return copy.deepcopy(BASE)

    def rejected(self, corpus, message):
        with self.assertRaisesRegex(ValueError, message):
            VALIDATOR.validate(corpus)

    def test_authorization_header_is_rejected(self):
        value = self.corpus()
        value["vectors"][0]["request"]["headers"].append({"name":"Authorization","value":"Bearer x"})
        self.rejected(value, "credential-like name")

    def test_cookie_header_is_rejected(self):
        value = self.corpus()
        value["vectors"][0]["request"]["headers"].append({"name":"Cookie","value":"sid=x"})
        self.rejected(value, "credential-like name")

    def test_access_token_query_is_rejected(self):
        value = self.corpus()
        value["vectors"][0]["request"]["query"].append({"name":"access_token","value":"x"})
        self.rejected(value, "credential-like name")

    def test_token_path_parameter_is_rejected(self):
        value = self.corpus()
        value["vectors"][3]["request"]["path"] += "/{token}"
        value["vectors"][3]["request"]["path_parameters"].append({"name":"token","value":"x"})
        self.rejected(value, "credential-like name")

    def test_token_body_is_rejected(self):
        value = self.corpus()
        value["vectors"][1]["request"]["body"]["access_token"] = "x"
        self.rejected(value, "credential-like name")

    def test_duplicate_query_key_is_rejected(self):
        value = self.corpus()
        value["vectors"][0]["request"]["query"].append({"name":"since","value":"s1"})
        self.rejected(value, "duplicate query key")

    def test_multibyte_path_limit_is_measured_in_bytes(self):
        value = self.corpus()
        value["limits"]["max_path_bytes"] = 4
        self.rejected(value, "path exceeds byte limit")

    def test_body_limit_is_rejected(self):
        value = self.corpus()
        value["limits"]["max_body_bytes"] = 1
        self.rejected(value, "body exceeds byte limit")

    def test_encoded_uri_drift_is_rejected(self):
        value = self.corpus()
        value["vectors"][0]["request"]["encoded_uri"] += "&drift=1"
        self.rejected(value, "encoded URI mismatch")

    def test_retry_precedence_drift_is_rejected(self):
        value = self.corpus()
        value["vectors"][0]["responses"][2]["parsing"]["retry_after_ms"] = 5000
        self.rejected(value, "Retry-After precedence mismatch")


if __name__ == "__main__":
    unittest.main()
