#!/usr/bin/env python3
"""Deterministically validate the semantic REQUEST-VECTORS-v2 contract."""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_CORPUS = ROOT / "fixtures/REQUEST-VECTORS-v2.json"
FORBIDDEN_NAMES = {
    "access_token", "access-token", "authorization", "proxy-authorization",
    "cookie", "set-cookie", "token", "api_key", "api-key", "password",
    "secret", "credential",
}
FORBIDDEN_VALUE_MARKERS = ("bearer ", "basic ", "access_token=", "access-token=", "cookie:")


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def fail(message: str) -> None:
    raise ValueError(message)


def check_pair(pair: dict[str, object], surface: str, limits: dict[str, int]) -> None:
    name = pair["name"]
    value = pair["value"]
    if not isinstance(name, str) or not isinstance(value, str):
        fail(f"{surface}: pair names and values must be strings")
    if len(name.encode()) > limits["max_name_bytes"]:
        fail(f"{surface}: name exceeds byte limit")
    if len(value.encode()) > limits["max_value_bytes"]:
        fail(f"{surface}: value exceeds byte limit")
    if name.casefold() in FORBIDDEN_NAMES:
        fail(f"{surface}: credential-like name is forbidden")
    folded_value = value.casefold()
    if any(marker in folded_value for marker in FORBIDDEN_VALUE_MARKERS):
        fail(f"{surface}: credential-like value is forbidden")


def check_json_credentials(value: object, surface: str = "body") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key.casefold() in FORBIDDEN_NAMES:
                fail(f"{surface}: credential-like name is forbidden")
            check_json_credentials(nested, surface)
    elif isinstance(value, list):
        for nested in value:
            check_json_credentials(nested, surface)
    elif isinstance(value, str):
        folded = value.casefold()
        if any(marker in folded for marker in FORBIDDEN_VALUE_MARKERS):
            fail(f"{surface}: credential-like value is forbidden")


def encoded_uri(request: dict[str, object]) -> str:
    path = request["path"]
    for pair in request["path_parameters"]:
        placeholder = "{" + pair["name"] + "}"
        if placeholder not in path:
            fail("path: parameter has no matching placeholder")
        path = path.replace(
            placeholder,
            urllib.parse.quote(pair["value"], safe="!:@-._~"),
        )
    if "{" in path or "}" in path:
        fail("path: unresolved placeholder")
    query = urllib.parse.urlencode(
        [(pair["name"], pair["value"]) for pair in request["query"]]
    )
    return path + ("?" + query if query else "")


def validate(corpus: dict[str, object]) -> None:
    limits = corpus["limits"]
    vectors = corpus["vectors"]
    operations: list[str] = []
    purposes: set[str] = set()
    for vector in vectors:
        operation = vector["operation"]
        operations.append(operation)
        purposes.add(vector["purpose"])
        request = vector["request"]
        if len(request["path"].encode()) > limits["max_path_bytes"]:
            fail(f"{operation}: path exceeds byte limit")
        if len(canonical_json(request["body"])) > limits["max_body_bytes"]:
            fail(f"{operation}: body exceeds byte limit")
        for surface, maximum in (("headers", "max_headers"), ("query", "max_query_pairs")):
            if len(request[surface]) > limits[maximum]:
                fail(f"{operation}: too many {surface}")
        query_names = [pair["name"] for pair in request["query"]]
        if len(query_names) != len(set(query_names)):
            fail(f"{operation}: duplicate query key")
        for surface in ("headers", "query", "path_parameters"):
            for pair in request[surface]:
                check_pair(pair, f"{operation}/{surface}", limits)
        check_json_credentials(request["body"], f"{operation}/body")
        expected_uri = encoded_uri(request)
        if request["encoded_uri"] != expected_uri:
            fail(f"{operation}: encoded URI mismatch")
        if len(expected_uri.encode()) > limits["max_path_bytes"]:
            fail(f"{operation}: encoded URI exceeds byte limit")

        responses = vector["responses"]
        if [case["kind"] for case in responses] != ["success", "error", "rate_limited"]:
            fail(f"{operation}: response case order mismatch")
        for response in responses:
            for pair in response["headers"]:
                check_pair(pair, f"{operation}/response_headers", limits)
            if len(canonical_json(response["body"])) > limits["max_body_bytes"]:
                fail(f"{operation}: response body exceeds byte limit")
        rate = responses[2]
        if rate["status"] != 429 or rate["body"].get("errcode") != "M_LIMIT_EXCEEDED":
            fail(f"{operation}: invalid rate-limit response")
        retry_headers = [p["value"] for p in rate["headers"] if p["name"].casefold() == "retry-after"]
        if retry_headers != ["120"]:
            fail(f"{operation}: Retry-After header grammar mismatch")
        if rate["body"].get("retry_after_ms") > limits["max_retry_after_ms"]:
            fail(f"{operation}: legacy retry_after_ms exceeds limit")
        if rate["parsing"] != {
            "expectation": "retry_after",
            "retry_source": "retry_after_header_precedes_legacy_body",
            "retry_after_ms": 120000,
        }:
            fail(f"{operation}: Retry-After precedence mismatch")

        identity = {
            key: vector[key]
            for key in (
                "schema_version", "operation", "purpose", "request",
                "response_cases", "responses", "oracle_comparison",
            )
        }
        if vector["vector_id"] != digest(identity):
            fail(f"{operation}: vector identity mismatch")

    if len(operations) != len(set(operations)) or set(operations) != set(corpus["required_operations"]):
        fail("required operation inventory mismatch")
    if len(corpus["required_purposes"]) != len(set(corpus["required_purposes"])):
        fail("required purpose inventory contains duplicates")
    if purposes != set(corpus["required_purposes"]) or purposes != set(corpus["capability_expectations"]):
        fail("required purpose inventory mismatch")
    corpus_identity = {
        key: corpus[key]
        for key in (
            "schema_version", "oracle", "limits", "duplicate_query_key_policy",
            "response_grammar", "required_operations", "required_purposes",
            "vectors", "capability_expectations",
        )
    }
    if corpus["corpus_id"] != digest(corpus_identity):
        fail("corpus identity mismatch")


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CORPUS
    validate(json.loads(path.read_bytes()))


if __name__ == "__main__":
    try:
        main()
    except (KeyError, TypeError, ValueError) as error:
        raise SystemExit(str(error)) from error
