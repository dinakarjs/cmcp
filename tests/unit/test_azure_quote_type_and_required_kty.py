"""Independent signed controls for the two outstanding #805 review requests."""
import base64
import hashlib
import json
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from cmcp_verify.azure_cvm import verify_azure_cvm_measurement
from tests.unit.test_azure_cvm_verify import (
    _build_evidence,
    _signed_snp,
    _synthetic_chain,
    _tpmt_signature,
)


@pytest.mark.parametrize("wrapped", [False, True])
def test_signed_non_quote_attestation_is_refused_with_quote_twin(wrapped):
    nonce = bytes(range(64))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raw, measurement, root = _build_evidence(nonce, ak_key=key)
    envelope = json.loads(raw)
    body = base64.b64decode(envelope["quote_msg"])[2:]
    for kind, expected in [(0x8018, True), (0x8017, False)]:
        attest = bytearray(body)
        struct.pack_into(">H", attest, 4, kind)
        message = (struct.pack(">H", len(attest)) if wrapped else b"") + bytes(attest)
        envelope["quote_msg"] = base64.b64encode(message).decode()
        envelope["quote_sig"] = base64.b64encode(_tpmt_signature(key, message)).decode()
        result = verify_azure_cvm_measurement(
            measurement, json.dumps(envelope).encode(), nonce.hex(), root
        )
        assert result.verified is expected
        if not expected:
            assert result.failure_reason == "quote_parse_error"
            assert "quote_nonce_binding" not in result.verified_fields


def test_hardware_bound_hcl_key_requires_kty_with_signed_valid_twin():
    nonce = bytes(range(64))
    raw, _, _ = _build_evidence(nonce)
    original = json.loads(raw)
    chain, root, signer = _synthetic_chain()
    runtime = json.loads(base64.b64decode(original["runtime_data"]))
    for missing, expected in [(False, True), (True, False)]:
        candidate = json.loads(json.dumps(runtime))
        if missing:
            candidate["keys"][0].pop("kty")
        runtime_bytes = json.dumps(candidate).encode()
        report, measurement = _signed_snp(signer, runtime_bytes)
        assert hashlib.sha256(runtime_bytes).digest() in report
        envelope = dict(
            original,
            runtime_data=base64.b64encode(runtime_bytes).decode(),
            snp_report=base64.b64encode(report).decode(),
            vcek_chain_pem=base64.b64encode(chain).decode(),
        )
        result = verify_azure_cvm_measurement(
            measurement, json.dumps(envelope).encode(), nonce.hex(), root
        )
        assert result.verified is expected
        if not expected:
            assert result.failure_reason == "ak_parse_error"
