"""ROS/GPU-independent checks for TQC artifact persistence."""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
TQC_DIR = ROOT / "src" / "turtlebot3_dqn" / "turtlebot3_dqn"
ATOMIC_IO = TQC_DIR / "atomic_io.py"


def _load_atomic_io():
    spec = importlib.util.spec_from_file_location(
        "tqc_atomic_io_under_test", ATOMIC_IO
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def atomic_io():
    return _load_atomic_io()


def _sign_artifact(atomic_io, artifact: Path, secret: bytes) -> None:
    digest = hmac.new(
        secret,
        artifact.read_bytes(),
        hashlib.sha256,
    ).hexdigest()
    atomic_io.signature_path(artifact).write_text(digest, encoding="ascii")


def test_atomic_model_temp_keeps_zip_suffix(atomic_io, tmp_path):
    final = tmp_path / "tqc_latest.zip"
    seen = []

    def sb3_like_save(path):
        requested = Path(path)
        seen.append(requested)
        # This mirrors SB3: append .zip unless the requested path ends in .zip.
        actual = requested if requested.suffix == ".zip" else Path(f"{path}.zip")
        actual.write_bytes(b"new-model")

    atomic_io.atomic_save(sb3_like_save, final)

    assert final.read_bytes() == b"new-model"
    assert seen[0].suffix == ".zip"
    assert not list(tmp_path.glob("*.tmp*"))


def test_atomic_signed_save_installs_matching_sidecar(atomic_io, tmp_path):
    final = tmp_path / "tqc_buffer.pkl"

    def write(path):
        Path(path).write_bytes(b"buffer")

    def sign(path, secret):
        atomic_io.signature_path(path).write_text(
            f"{secret.decode()}:{Path(path).read_bytes().decode()}"
        )

    atomic_io.atomic_save(write, final, sign_fn=sign, secret=b"key")

    assert final.read_bytes() == b"buffer"
    assert atomic_io.signature_path(final).read_text() == "key:buffer"


def test_sign_failure_preserves_previous_pair(atomic_io, tmp_path):
    final = tmp_path / "tqc_latest.zip"
    final.write_bytes(b"old")
    final_sig = atomic_io.signature_path(final)
    final_sig.write_text("old-signature")

    def write(path):
        Path(path).write_bytes(b"new")

    def fail_sign(_path, _secret):
        raise RuntimeError("signing unavailable")

    with pytest.raises(RuntimeError):
        atomic_io.atomic_save(write, final, sign_fn=fail_sign, secret=b"key")

    assert final.read_bytes() == b"old"
    assert final_sig.read_text() == "old-signature"
    assert not [p for p in tmp_path.iterdir() if ".tmp" in p.name]


def test_unsigned_replacement_removes_stale_signature(atomic_io, tmp_path):
    final = tmp_path / "tqc_latest.zip"
    final.write_bytes(b"old")
    stale_sig = atomic_io.signature_path(final)
    stale_sig.write_text("signature-for-old-content")

    atomic_io.atomic_save(lambda path: Path(path).write_bytes(b"new"), final)

    assert final.read_bytes() == b"new"
    assert not stale_sig.exists()


def test_unsigned_artifact_is_rejected(atomic_io, tmp_path):
    artifact = tmp_path / "tqc_latest.zip"
    artifact.write_bytes(b"model")

    with pytest.raises(atomic_io.ArtifactIntegrityError, match="缺少 HMAC"):
        with atomic_io.open_verified_snapshot(
            artifact,
            secret=b"k" * 32,
            label="TQC model",
        ):
            pytest.fail("unsigned artifact must never yield a snapshot")


def test_bad_signature_is_rejected_before_snapshot_yield(atomic_io, tmp_path):
    artifact = tmp_path / "tqc_latest.zip"
    artifact.write_bytes(b"model")
    atomic_io.signature_path(artifact).write_text("0" * 64, encoding="ascii")

    with pytest.raises(atomic_io.ArtifactIntegrityError, match="HMAC 驗證失敗"):
        with atomic_io.open_verified_snapshot(
            artifact,
            secret=b"k" * 32,
            label="TQC model",
        ):
            pytest.fail("bad signature must never yield a snapshot")


def test_short_secret_never_opens_snapshot(atomic_io, tmp_path):
    artifact = tmp_path / "tqc_latest.zip"
    artifact.write_bytes(b"model")
    with pytest.raises(atomic_io.ArtifactIntegrityError, match="HMAC key"):
        with atomic_io.open_verified_snapshot(
            artifact,
            secret=b"short",
        ):
            pytest.fail("short key must never yield a snapshot")


def test_verified_snapshot_is_immutable_after_source_replacement(
    atomic_io, tmp_path
):
    secret = b"k" * 32
    original = b"authenticated-model-bytes"
    artifact = tmp_path / "tqc_latest.zip"
    artifact.write_bytes(original)
    _sign_artifact(atomic_io, artifact, secret)

    with atomic_io.open_verified_snapshot(
        artifact,
        secret=secret,
        label="TQC model",
    ) as snapshot:
        assert hasattr(snapshot, "read")
        assert hasattr(snapshot, "seek")
        assert not isinstance(snapshot, (str, bytes, Path))

        # Simulate replacement after authentication.  The deserializer must
        # continue reading the already-verified byte sequence, not this path.
        artifact.write_bytes(b"attacker-replacement")
        assert snapshot.read() == original

    assert snapshot.closed


@pytest.mark.parametrize(
    ("script", "loader"),
    [
        ("train_top.py", "TQC"),
        ("eval_top.py", "TQC"),
        ("bench_top.py", "TQC"),
        ("train_sac.py", "SAC"),
        ("run_policy_sac.py", "SAC"),
    ],
)
def test_formal_entrypoints_load_only_verified_filelike_snapshots(script, loader):
    source = (TQC_DIR / script).read_text(encoding="utf-8")
    assert "open_verified_snapshot" in source
    assert f"{loader}.load(model_snapshot" in source
    assert "--allow-unsigned-legacy" not in source
    assert "allow_unsigned_legacy" not in source


@pytest.mark.parametrize("script", ["train_top.py", "train_sac.py"])
def test_replay_pickle_loads_only_from_verified_snapshot(script):
    source = (TQC_DIR / script).read_text(encoding="utf-8")
    assert "open_verified_snapshot" in source
    assert "model.load_replay_buffer(buffer_snapshot)" in source
    assert "--allow-unsigned-legacy" not in source
    assert "allow_unsigned_legacy" not in source


def test_legacy_dqn_uses_restricted_torch_loader():
    source = (TQC_DIR / "dqn_agent.py").read_text(encoding="utf-8")
    assert "weights_only=True" in source
    assert "weights_only=False" not in source


def test_legacy_sac_model_and_pickle_loads_are_fail_closed():
    train = (TQC_DIR / "train_sac.py").read_text(encoding="utf-8")
    deploy = (TQC_DIR / "run_policy_sac.py").read_text(encoding="utf-8")
    assert train.count("open_verified_snapshot(") >= 2
    assert "SAC.load(model_snapshot" in train
    assert "model.load_replay_buffer(buffer_snapshot)" in train
    assert "atomic_save(" in train
    assert "跳過完整性驗證" not in deploy
    assert "open_verified_snapshot(" in deploy
    assert deploy.count("SAC.load(model_snapshot") == 2
    assert "--allow-unsigned-legacy" not in train + deploy
    assert "allow_unsigned_legacy" not in train + deploy
