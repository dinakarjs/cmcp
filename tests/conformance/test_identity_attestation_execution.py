"""Executable fixture boundary for #568, not a production gateway integration.

The trusted signer and independently authenticated workload are fixture premises.
Synthetic signed statements are not hardware attestation. Local disposition
names select no TRACE fields or token-exchange format.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from unittest.mock import Mock

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


@dataclass(frozen=True)
class Assessment:
    authentication: str
    status: str
    reason: str
    positive_attestation: bool


def _assess(evidence: tuple[bytes, bytes] | None, workload: str) -> Assessment:
    if evidence is None:
        return Assessment("authenticated", "not_established", "absent", False)
    payload, signature = evidence
    try:
        _KEY.public_key().verify(signature, payload)
    except InvalidSignature:
        return Assessment("authenticated", "not_established", "unverifiable", False)
    statement = json.loads(payload)
    if statement["workload"] != workload:
        return Assessment("authenticated", "contradictory", "binding_mismatch", False)
    return Assessment("authenticated", "established", "verified_fixture_binding", True)


def _admit(result: Assessment, required: bool) -> bool:
    if result.status == "contradictory":
        return False
    return not (required and result.status != "established")


def _invoke(
    evidence: tuple[bytes, bytes] | None, *, required: bool, policy_permits: bool, upstream: Mock
) -> Assessment:
    result = _assess(evidence, "workload-A")
    if _admit(result, required) and policy_permits:
        upstream()
    return result


def _signed(workload: str) -> tuple[bytes, bytes]:
    payload = json.dumps({"workload": workload}, sort_keys=True).encode()
    return payload, _KEY.sign(payload)


def _evidence(condition: str) -> tuple[bytes, bytes] | None:
    if condition == "absent":
        return None
    if condition == "unverifiable":
        payload, signature = _signed("workload-A")
        return payload, bytes([signature[0] ^ 1]) + signature[1:]
    return _signed("workload-A" if condition == "matching" else "workload-B")


@pytest.mark.parametrize("condition", ["absent", "unverifiable"])
@pytest.mark.parametrize("required", [False, True])
def test_missing_evidence_keeps_authentication_but_obeys_required_boundary(
    condition: str, required: bool
) -> None:
    upstream = Mock()
    result = _invoke(
        _evidence(condition), required=required, policy_permits=True, upstream=upstream
    )
    assert result == Assessment("authenticated", "not_established", condition, False)
    assert upstream.call_count == (0 if required else 1)


@pytest.mark.parametrize("required", [False, True])
def test_verified_contradiction_refuses_even_with_permitting_policy(required: bool) -> None:
    upstream = Mock()
    result = _invoke(
        _evidence("mismatch"), required=required, policy_permits=True, upstream=upstream
    )
    assert result == Assessment("authenticated", "contradictory", "binding_mismatch", False)
    upstream.assert_not_called()


@pytest.mark.parametrize("required", [False, True])
@pytest.mark.parametrize("policy_permits", [False, True])
def test_matching_evidence_continues_only_when_policy_permits(
    required: bool, policy_permits: bool
) -> None:
    upstream = Mock()
    result = _invoke(
        _evidence("matching"), required=required, policy_permits=policy_permits, upstream=upstream
    )
    assert result == Assessment("authenticated", "established", "verified_fixture_binding", True)
    assert upstream.call_count == int(policy_permits)


@pytest.mark.parametrize("condition", ["absent", "unverifiable"])
def test_optional_absence_does_not_override_policy_deny(condition: str) -> None:
    upstream = Mock()
    result = _invoke(_evidence(condition), required=False, policy_permits=False, upstream=upstream)
    assert result.status == "not_established"
    upstream.assert_not_called()
