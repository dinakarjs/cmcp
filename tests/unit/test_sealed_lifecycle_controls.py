"""Real reseal/rotation orchestration with TPM calls replaced by observed seams.

No ESAPI device is opened. These tests establish software sequencing and stored
contents, not TPM enforcement, crash recovery, or hardware gate state.
"""

from __future__ import annotations

import sys
from contextlib import nullcontext
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

from cmcp_runtime.policy.bundle import bundle_hash_of_files
from cmcp_runtime.tee import measurement, seal


@pytest.mark.parametrize("changed_after_verification", [False, True])
def test_reseal_uses_only_the_verified_policy_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed_after_verification: bool
) -> None:
    policy = tmp_path / "policy"
    policy.mkdir()
    (policy / "manifest.json").write_text("{}", encoding="utf-8")
    (policy / "schema.cedarschema").write_text("namespace Test {}", encoding="utf-8")
    source = policy / "policy.cedar"
    source.write_text("permit(principal, action, resource);", encoding="utf-8")
    files = measurement.read_policy_files(str(policy))
    accepted = bundle_hash_of_files(files)
    assert accepted is not None
    old = measurement.measurement_from_components(
        {"code": "a" * 64, "policy": "b" * 64, "config": "c" * 64}
    )
    reseal = Mock()
    held = SimpleNamespace(sealed_digest=old.digest, reseal=reseal)
    ctx = SimpleNamespace(
        sealed_key=held,
        gateway_measurement=old,
        config=SimpleNamespace(policy_bundle_path=str(policy)),
        policy_bundle=SimpleNamespace(bundle=SimpleNamespace(bundle_hash=accepted)),
    )
    if changed_after_verification:
        source.write_text("forbid(principal, action, resource);", encoding="utf-8")
    module = ModuleType("tpm2_pytss.ESAPI")
    device = object()
    factory = Mock(return_value=nullcontext(device))
    module.ESAPI = factory
    monkeypatch.setitem(sys.modules, "tpm2_pytss.ESAPI", module)
    assert seal.reseal_after_reload(ctx) is (not changed_after_verification)
    if changed_after_verification:
        factory.assert_not_called()
        reseal.assert_not_called()
    else:
        expected = measurement.measurement_from_components(
            {
                "code": "a" * 64,
                "policy": measurement.policy_digest_of_files(files),
                "config": "c" * 64,
            }
        ).digest
        factory.assert_called_once_with()
        reseal.assert_called_once_with(device, expected)


@pytest.mark.parametrize("profile", ["absent", "unwritten", "written", "foreign"])
def test_rotation_finishes_only_expected_gate_and_replaces_old_blobs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str
) -> None:
    store = seal.SealedKeyStore(tmp_path / "store")
    old = seal.StoreContents(
        seal.DEFAULT_GATE_NV_INDEX,
        seal.ed25519_public_key(b"a" * 32),
        (seal.SealedBlob(b"b" * 32, b"old-private", b"old-public"),),
    )
    store.write(old)
    original_bytes = store.path.read_bytes()
    index = seal.DEFAULT_GATE_NV_INDEX
    name = {
        "absent": b"",
        "unwritten": seal.gate_nv_name(index, written=False),
        "written": seal.gate_nv_name(index),
        "foreign": b"foreign-profile",
    }[profile]
    device = Mock()
    device.nv_read_public.side_effect = lambda handle: (None, name)
    monkeypatch.setattr(seal, "_gate_handle", lambda ctx, idx: None if profile == "absent" else 7)
    define = Mock(return_value=7)
    monkeypatch.setattr(seal, "_define_gate", define)
    writes = []

    def write_gate(ctx, handle, value):
        nonlocal name
        writes.append((ctx, handle, value))
        name = seal.gate_nv_name(index)

    monkeypatch.setattr(seal, "_write_gate", write_gate)
    monkeypatch.setattr(seal.os, "urandom", lambda length: b"d" * length)
    blob = seal.SealedBlob(b"e" * 32, b"new-private", b"new-public")
    sealing = Mock(return_value=blob)
    monkeypatch.setattr(seal, "_seal", sealing)
    if profile == "foreign":
        with pytest.raises(seal.SealedKeyUnavailable, match="profile"):
            seal.rotate_sealed_key(device, store, blob.digest)
        sealing.assert_not_called()
        assert store.path.read_bytes() == original_bytes
        assert writes == []
        define.assert_not_called()
    else:
        public = seal.rotate_sealed_key(device, store, blob.digest)
        assert public == seal.ed25519_public_key(b"d" * 32)
        assert public != old.public_key
        assert store.read() == seal.StoreContents(index, public, (blob,))
        sealing.assert_called_once_with(device, b"d" * 32, blob.digest, index)
        assert writes == (
            [(device, 7, seal.GATE_SENTINEL)] if profile in {"absent", "unwritten"} else []
        )
        assert define.call_count == int(profile == "absent")
