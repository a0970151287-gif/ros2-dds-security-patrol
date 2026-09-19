"""Authenticated persistence helpers for standalone ML-IDS artifacts.

``joblib`` ultimately relies on pickle and must never deserialize an
attacker-replaced file.  Training therefore writes a SHA-256 HMAC sidecar and
runtime loading verifies it *before* calling ``joblib.load``.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import tempfile
from pathlib import Path

HMAC_SECRET_MIN_BYTES = 32
DEFAULT_SECRET_FILE = Path("~/.config/dds-monitor/alert_secret").expanduser()


class ArtifactIntegrityError(RuntimeError):
    """The model cannot be authenticated and must not be deserialized."""


def signature_path(path: str | Path) -> Path:
    p = Path(path)
    return p.with_suffix(p.suffix + ".sha256.hmac")


def load_hmac_secret(path: str | Path = DEFAULT_SECRET_FILE) -> bytes:
    """Load the shared file-only HMAC key with strict POSIX permissions."""
    secret_path = Path(path).expanduser()
    try:
        mode = secret_path.stat().st_mode & 0o777
        if mode != 0o600:
            raise ArtifactIntegrityError(
                f"{secret_path} 權限必須是 0600，目前為 {oct(mode)}"
            )
        secret = secret_path.read_bytes().strip()
    except FileNotFoundError as exc:
        raise ArtifactIntegrityError(
            f"找不到模型驗章金鑰：{secret_path}"
        ) from exc
    except OSError as exc:
        raise ArtifactIntegrityError(
            f"無法讀取模型驗章金鑰：{secret_path}: {exc}"
        ) from exc
    if len(secret) < HMAC_SECRET_MIN_BYTES:
        raise ArtifactIntegrityError(
            f"{secret_path} 至少需要 {HMAC_SECRET_MIN_BYTES} bytes"
        )
    return secret


def _validate_secret(secret: bytes) -> None:
    if not isinstance(secret, bytes) or len(secret) < HMAC_SECRET_MIN_BYTES:
        raise ValueError(
            f"secret 必須是至少 {HMAC_SECRET_MIN_BYTES} bytes 的 bytes"
        )


def _file_hmac(path: Path, secret: bytes) -> str:
    mac = hmac.new(secret, digestmod=hashlib.sha256)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            mac.update(chunk)
    return mac.hexdigest()


def sign_artifact(path: str | Path, secret: bytes) -> Path:
    """Write the canonical sidecar used by the ROS security package."""
    _validate_secret(secret)
    artifact = Path(path)
    digest = _file_hmac(artifact, secret)
    sidecar = signature_path(artifact)
    sidecar.write_text(digest, encoding="ascii")
    return sidecar


def verify_artifact(path: str | Path, secret: bytes) -> bool:
    """Return True only for an existing artifact with a valid HMAC sidecar."""
    try:
        _validate_secret(secret)
        artifact = Path(path)
        sidecar = signature_path(artifact)
        if not artifact.is_file() or not sidecar.is_file():
            return False
        expected = sidecar.read_text(encoding="ascii").strip()
        if len(expected) != hashlib.sha256().digest_size * 2:
            return False
        return hmac.compare_digest(expected, _file_hmac(artifact, secret))
    except (OSError, UnicodeError, TypeError, ValueError):
        return False


def atomic_joblib_dump(
    value,
    destination: str | Path,
    *,
    secret: bytes | None = None,
) -> Path:
    """Atomically persist one joblib bundle and its matching HMAC sidecar."""
    import joblib

    signing_secret = load_hmac_secret() if secret is None else secret
    _validate_secret(signing_secret)
    final = Path(destination)
    final.parent.mkdir(parents=True, exist_ok=True)
    tmp = final.with_name(
        f".{final.stem}.{secrets.token_hex(8)}.tmp{final.suffix}"
    )
    tmp_sig = signature_path(tmp)
    final_sig = signature_path(final)
    try:
        joblib.dump(value, tmp)
        if not tmp.is_file():
            raise FileNotFoundError(f"joblib did not create {tmp}")
        sign_artifact(tmp, signing_secret)
        if not tmp_sig.is_file():
            raise FileNotFoundError(f"signature writer did not create {tmp_sig}")
        os.replace(tmp, final)
        os.replace(tmp_sig, final_sig)
    finally:
        tmp.unlink(missing_ok=True)
        tmp_sig.unlink(missing_ok=True)
    return final


def verified_joblib_load(
    source: str | Path,
    *,
    secret: bytes | None = None,
):
    """Authenticate and deserialize the exact same immutable byte snapshot."""
    import joblib

    artifact = Path(source)
    signing_secret = load_hmac_secret() if secret is None else secret
    _validate_secret(signing_secret)
    sidecar = signature_path(artifact)
    if (
        not artifact.is_file()
        or artifact.is_symlink()
        or not sidecar.is_file()
        or sidecar.is_symlink()
    ):
        raise ArtifactIntegrityError(
            f"模型缺少有效 HMAC，拒絕 joblib.load：{artifact}"
        )
    try:
        expected = sidecar.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise ArtifactIntegrityError(
            f"模型 HMAC sidecar 無法讀取：{sidecar}"
        ) from exc
    if (
        len(expected) != hashlib.sha256().digest_size * 2
        or any(ch not in "0123456789abcdef" for ch in expected)
    ):
        raise ArtifactIntegrityError(
            f"模型 HMAC sidecar 格式錯誤：{sidecar}"
        )

    snapshot = tempfile.SpooledTemporaryFile(
        max_size=64 * 1024 * 1024,
        mode="w+b",
    )
    digest = hmac.new(signing_secret, digestmod=hashlib.sha256)
    try:
        with artifact.open("rb") as source_handle:
            for chunk in iter(lambda: source_handle.read(1024 * 1024), b""):
                digest.update(chunk)
                snapshot.write(chunk)
        if not hmac.compare_digest(expected, digest.hexdigest()):
            raise ArtifactIntegrityError(
                f"模型缺少有效 HMAC，拒絕 joblib.load：{artifact}"
            )
        snapshot.seek(0)
        return joblib.load(snapshot)
    finally:
        snapshot.close()
