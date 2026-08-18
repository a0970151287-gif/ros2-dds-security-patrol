from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "工具腳本" / "verify_reproducibility.py"
SPEC = importlib.util.spec_from_file_location("verify_reproducibility", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verify_reproducibility = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_reproducibility)


def test_atomic_publish_report_creates_exact_file_and_cleans_staging(tmp_path):
    destination = tmp_path / "audit.json"
    payload = b'{"overall_status":"verified"}\n'

    result = verify_reproducibility.atomic_publish_report(destination, payload)

    assert result == destination.resolve()
    assert destination.read_bytes() == payload
    assert not list(tmp_path.glob(".audit.json.*.tmp"))


def test_atomic_publish_report_refuses_existing_file_without_changing_it(tmp_path):
    destination = tmp_path / "audit.json"
    destination.write_bytes(b"original\n")

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        verify_reproducibility.atomic_publish_report(destination, b"replacement\n")

    assert destination.read_bytes() == b"original\n"
    assert not list(tmp_path.glob(".audit.json.*.tmp"))


def test_atomic_publish_report_refuses_existing_symlink(tmp_path):
    target = tmp_path / "target.json"
    target.write_bytes(b"target\n")
    destination = tmp_path / "audit.json"
    try:
        destination.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable on this platform")

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        verify_reproducibility.atomic_publish_report(destination, b"replacement\n")

    assert target.read_bytes() == b"target\n"


def test_atomic_publish_report_rejects_missing_or_symlink_parent(tmp_path):
    with pytest.raises(ValueError, match="parent"):
        verify_reproducibility.atomic_publish_report(
            tmp_path / "missing" / "audit.json", b"payload\n"
        )

    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable on this platform")
    with pytest.raises(ValueError, match="parent"):
        verify_reproducibility.atomic_publish_report(
            linked_parent / "audit.json", b"payload\n"
        )


def test_main_writes_json_and_refuses_a_second_publish(tmp_path, monkeypatch, capsys):
    report = {
        "schema_version": verify_reproducibility.AUDIT_SCHEMA,
        "overall_status": "verified",
        "checks": [],
    }
    monkeypatch.setattr(
        verify_reproducibility,
        "audit_reproducibility",
        lambda *args, **kwargs: report,
    )
    destination = tmp_path / "audit.json"

    assert (
        verify_reproducibility.main(
            ["--repo-root", str(tmp_path), "--pretty", "--output", str(destination)]
        )
        == 0
    )
    assert json.loads(destination.read_text(encoding="utf-8")) == report
    original = destination.read_bytes()

    assert (
        verify_reproducibility.main(
            ["--repo-root", str(tmp_path), "--output", str(destination)]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert "refusing to overwrite" in captured.err
    assert destination.read_bytes() == original
