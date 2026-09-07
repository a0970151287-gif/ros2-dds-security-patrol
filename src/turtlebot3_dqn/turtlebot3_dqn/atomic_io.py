"""Small, dependency-free helpers for crash-safe training artifacts.

Stable-Baselines3 appends ``.zip`` when a model save path does not already end
in that suffix.  A temporary path such as ``tqc_latest.zip.tmp`` therefore
silently becomes ``tqc_latest.zip.tmp.zip``.  Keeping the *real* suffix at the
end of the temporary name avoids that behaviour and also makes this helper
usable for replay buffers.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import tempfile
from contextlib import contextmanager
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO, Iterator

HMAC_SECRET_MIN_BYTES = 32


class ArtifactIntegrityError(RuntimeError):
    """A model/replay artifact is unsigned or has a bad authentication tag."""


def signature_path(path: str | Path) -> Path:
    """Return the sidecar path used by ``monitor_node.sign_file``."""
    p = Path(path)
    return p.with_suffix(p.suffix + ".sha256.hmac")


def atomic_save(
    write_fn: Callable[[str], object],
    final_path: str | Path,
    *,
    sign_fn: Callable[[str | Path, bytes], object] | None = None,
    secret: bytes = b"",
) -> None:
    """Write one model/buffer and optional HMAC sidecar without partial files.

    The artifact is first written beside the destination and then installed
    with ``os.replace``.  If signing is enabled, the newly written temporary
    artifact is signed before either destination is touched.  Replacing two
    files cannot be one filesystem transaction, so the artifact is installed
    before its signature; a crash in that tiny window is fail-closed because
    verification sees a mismatched/absent sidecar.
    """
    final = Path(final_path)
    final.parent.mkdir(parents=True, exist_ok=True)

    token = secrets.token_hex(8)
    # Crucial: end in final.suffix, e.g. ".tqc_latest.<id>.tmp.zip".
    tmp = final.with_name(f".{final.stem}.{token}.tmp{final.suffix}")
    tmp_sig = signature_path(tmp)
    final_sig = signature_path(final)
    signed = sign_fn is not None and bool(secret)

    try:
        write_fn(str(tmp))
        if not tmp.is_file():
            raise FileNotFoundError(
                f"save callback did not create the requested file: {tmp}"
            )

        if signed:
            sign_fn(tmp, secret)
            if not tmp_sig.is_file():
                raise FileNotFoundError(
                    f"sign callback did not create the expected sidecar: {tmp_sig}"
                )

        os.replace(tmp, final)
        if signed:
            os.replace(tmp_sig, final_sig)
        else:
            # Never leave a valid-looking signature for newly saved unsigned
            # content.  A later verified load must treat it as unsigned.
            final_sig.unlink(missing_ok=True)
    finally:
        tmp.unlink(missing_ok=True)
        tmp_sig.unlink(missing_ok=True)


@contextmanager
def open_verified_snapshot(
    path: str | Path,
    *,
    secret: bytes,
    label: str = "artifact",
    memory_limit: int = 64 * 1024 * 1024,
) -> Iterator[BinaryIO]:
    """Yield the exact authenticated bytes from a private read-only snapshot.

    Verifying ``path`` and then asking SB3/joblib to reopen that path leaves a
    time-of-check/time-of-use window in which another process can replace the
    file.  This helper copies and authenticates one opened file into a spooled
    temporary file, then hands *that same byte sequence* to the deserializer.
    Large replay buffers spill to an unlinked temporary file instead of being
    duplicated entirely in RAM.
    """
    artifact = Path(path)
    if not artifact.is_file():
        raise FileNotFoundError(artifact)
    if artifact.is_symlink():
        raise ArtifactIntegrityError(f"{label} 不可為符號連結：{artifact}")
    if not isinstance(secret, bytes) or len(secret) < HMAC_SECRET_MIN_BYTES:
        raise ArtifactIntegrityError(
            f"{label} 無法驗章：HMAC key 缺失或短於 {HMAC_SECRET_MIN_BYTES} bytes"
        )

    sidecar = signature_path(artifact)
    if not sidecar.is_file():
        raise ArtifactIntegrityError(
            f"{label} 缺少 HMAC sidecar，拒絕載入：{sidecar}"
        )
    if sidecar.is_symlink():
        raise ArtifactIntegrityError(f"{label} HMAC sidecar 不可為符號連結：{sidecar}")
    try:
        expected = sidecar.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise ArtifactIntegrityError(
            f"{label} HMAC sidecar 無法讀取：{sidecar}"
        ) from exc
    if (
        len(expected) != hashlib.sha256().digest_size * 2
        or any(ch not in "0123456789abcdef" for ch in expected)
    ):
        raise ArtifactIntegrityError(
            f"{label} HMAC sidecar 格式錯誤，拒絕載入：{sidecar}"
        )

    snapshot = tempfile.SpooledTemporaryFile(
        max_size=memory_limit,
        mode="w+b",
    )
    digest = hmac.new(secret, digestmod=hashlib.sha256)
    try:
        with artifact.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
                snapshot.write(chunk)
        if not hmac.compare_digest(expected, digest.hexdigest()):
            raise ArtifactIntegrityError(
                f"{label} HMAC 驗證失敗，拒絕載入：{artifact}"
            )
        snapshot.seek(0)
        yield snapshot
    finally:
        snapshot.close()
