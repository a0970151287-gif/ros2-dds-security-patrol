from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import firewall_lab.project_evidence as project_evidence
from firewall_lab.project_evidence import (
    CLAIM_SPEC_SCHEMA,
    LEDGER_JSON_NAME,
    LEDGER_MARKDOWN_NAME,
    ProjectEvidenceError,
    generate_evidence_ledger,
    normalize_claim_spec,
    verify_evidence_ledger,
)


def _reference(root: Path, relative: str, payload: bytes = b"verified evidence\n") -> dict:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return {
        "path": relative,
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "description": "test artifact",
    }


def _spec(evidence: list[dict], *, status: str = "verified", blockers=None) -> dict:
    return {
        "schema_version": CLAIM_SPEC_SCHEMA,
        "project_id": "sros2_room_firewall",
        "project_revision": "test-revision",
        "claims": [
            {
                "claim_id": "offline_regression",
                "title": "Offline regression",
                "statement": "The cited offline regression artifact is present.",
                "status": status,
                "evidence": evidence,
                "blockers": [] if blockers is None else blockers,
                "limitations": ["This is not a live firewall outcome."],
            }
        ],
    }


def test_generate_and_verify_portable_fail_closed_ledger(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    evidence = _reference(repo, "evidence/result.txt")
    output = tmp_path / "ledger"

    result = generate_evidence_ledger(_spec([evidence]), repo, output)
    assert result["summary"] == {
        "total": 1,
        "verified": 1,
        "provisional": 0,
        "blocked": 0,
        "all_claims_verified": True,
    }
    ledger = json.loads((output / LEDGER_JSON_NAME).read_text(encoding="utf-8"))
    assert ledger["claims"][0]["evidence"][0]["path"] == "evidence/result.txt"
    assert str(repo) not in json.dumps(ledger)
    assert ledger["safety"] == {
        "evidence_inventory_only": True,
        "deployment_eligible": False,
        "autonomous_ip_block_ready": False,
        "runtime_authorization": False,
    }
    verified = verify_evidence_ledger(output / LEDGER_JSON_NAME, repo)
    assert verified["valid"] is True
    assert verified["deployment_eligible"] is False


def test_markdown_keeps_all_summary_rows_inside_one_table(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    first = _reference(repo, "evidence/first.txt", b"first\n")
    second = _reference(repo, "evidence/second.txt", b"second\n")
    spec = _spec([first])
    spec["claims"].append(
        {
            "claim_id": "second_claim",
            "title": "Second claim",
            "statement": "The second cited artifact is present.",
            "status": "verified",
            "evidence": [second],
            "blockers": [],
            "limitations": ["This is also an offline artifact."],
        }
    )
    output = tmp_path / "ledger"

    generate_evidence_ledger(spec, repo, output)
    markdown = (output / LEDGER_MARKDOWN_NAME).read_text(encoding="utf-8")

    first_row = markdown.index("| Offline regression | verified |")
    second_row = markdown.index("| Second claim | verified |")
    details = markdown.index("## Claim details")
    assert first_row < second_row < details
    assert "### Evidence for `offline_regression`" in markdown
    assert "### Evidence for `second_claim`" in markdown


@pytest.mark.parametrize(
    "unsafe",
    [
        "../outside.txt",
        "evidence/../../outside.txt",
        "/etc/passwd",
        "C:/Windows/System32/drivers/etc/hosts",
        r"evidence\..\outside.txt",
    ],
)
def test_repo_relative_path_rejects_traversal_and_platform_ambiguity(tmp_path, unsafe):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside")
    entry = {
        "path": unsafe,
        "bytes": len(b"outside"),
        "sha256": hashlib.sha256(b"outside").hexdigest(),
        "description": "must not escape",
    }
    with pytest.raises(ProjectEvidenceError, match="repo-relative|inside the repository"):
        normalize_claim_spec(_spec([entry]), repo)


def test_symlink_evidence_is_rejected(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "target.txt"
    target.write_bytes(b"target")
    link = repo / "link.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this platform")
    entry = {
        "path": "link.txt",
        "bytes": len(b"target"),
        "sha256": hashlib.sha256(b"target").hexdigest(),
    }
    with pytest.raises(ProjectEvidenceError, match="symlink"):
        normalize_claim_spec(_spec([entry]), repo)


def test_tampered_evidence_is_detected_on_generation_and_reverification(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    evidence = _reference(repo, "evidence/result.txt")

    bad = dict(evidence)
    bad["sha256"] = "0" * 64
    with pytest.raises(ProjectEvidenceError, match="SHA-256 mismatch"):
        generate_evidence_ledger(_spec([bad]), repo, tmp_path / "bad-ledger")

    output = tmp_path / "ledger"
    generate_evidence_ledger(_spec([evidence]), repo, output)
    (repo / evidence["path"]).write_bytes(b"tampered evidence with another size\n")
    with pytest.raises(ProjectEvidenceError, match="size mismatch"):
        verify_evidence_ledger(output / LEDGER_JSON_NAME, repo)


def test_empty_evidence_and_zero_byte_artifact_are_rejected(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(ProjectEvidenceError, match="must cite non-empty evidence"):
        normalize_claim_spec(_spec([]), repo)

    empty = repo / "empty.txt"
    empty.write_bytes(b"")
    entry = {
        "path": "empty.txt",
        "bytes": 0,
        "sha256": hashlib.sha256(b"").hexdigest(),
    }
    with pytest.raises(ProjectEvidenceError, match="positive integer"):
        normalize_claim_spec(_spec([entry]), repo)


def test_overclaims_and_contradictory_statuses_fail_closed(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    evidence = _reference(repo, "result.txt")

    overclaim = _spec([evidence])
    overclaim["deployment_ready"] = True
    with pytest.raises(ProjectEvidenceError, match="unsupported fields"):
        normalize_claim_spec(overclaim, repo)

    with pytest.raises(ProjectEvidenceError, match="may not retain blockers"):
        normalize_claim_spec(_spec([evidence], blockers=["live test missing"]), repo)

    with pytest.raises(ProjectEvidenceError, match="must state at least one blocker"):
        normalize_claim_spec(_spec([], status="blocked", blockers=[]), repo)


def test_blocked_and_provisional_claims_remain_explicit(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    raw = _spec([], status="blocked", blockers=["Raspberry Pi evidence missing"])
    raw["claims"].append(
        {
            "claim_id": "cross_host_trial",
            "title": "Cross-host trial",
            "statement": "The design exists but the live result is pending.",
            "status": "provisional",
            "evidence": [],
            "blockers": [],
            "limitations": ["No isolated two-host execution yet."],
        }
    )
    output = tmp_path / "ledger"
    generate_evidence_ledger(raw, repo, output)
    ledger = json.loads((output / LEDGER_JSON_NAME).read_text(encoding="utf-8"))
    assert ledger["summary"]["blocked"] == 1
    assert ledger["summary"]["provisional"] == 1
    assert ledger["summary"]["all_claims_verified"] is False


def test_markdown_tamper_is_detected(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    evidence = _reference(repo, "result.txt")
    output = tmp_path / "ledger"
    generate_evidence_ledger(_spec([evidence]), repo, output)
    (output / LEDGER_MARKDOWN_NAME).write_text("altered\n", encoding="utf-8")
    with pytest.raises(ProjectEvidenceError, match="Markdown SHA-256 mismatch"):
        verify_evidence_ledger(output / LEDGER_JSON_NAME, repo)


def test_atomic_publish_leaves_no_partial_destination_and_refuses_overwrite(
    tmp_path, monkeypatch
):
    repo = tmp_path / "repo"
    repo.mkdir()
    evidence = _reference(repo, "result.txt")
    output = tmp_path / "ledger"
    original = project_evidence._write_bytes_fsync
    calls = 0

    def fail_second_write(path, payload):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected write failure")
        return original(path, payload)

    monkeypatch.setattr(project_evidence, "_write_bytes_fsync", fail_second_write)
    with pytest.raises(OSError, match="injected"):
        generate_evidence_ledger(_spec([evidence]), repo, output)
    assert not output.exists()
    assert not list(tmp_path.glob(".ledger.*.tmp"))

    monkeypatch.setattr(project_evidence, "_write_bytes_fsync", original)
    generate_evidence_ledger(_spec([evidence]), repo, output)
    before = (output / LEDGER_JSON_NAME).read_bytes()
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        generate_evidence_ledger(_spec([evidence]), repo, output)
    assert (output / LEDGER_JSON_NAME).read_bytes() == before


def test_duplicate_claim_ids_and_evidence_paths_are_rejected(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    evidence = _reference(repo, "result.txt")
    duplicate_path = _spec([evidence, evidence])
    with pytest.raises(ProjectEvidenceError, match="duplicate paths"):
        normalize_claim_spec(duplicate_path, repo)

    duplicate_claim = _spec([evidence])
    duplicate_claim["claims"].append(dict(duplicate_claim["claims"][0]))
    with pytest.raises(ProjectEvidenceError, match="duplicate claim_id"):
        normalize_claim_spec(duplicate_claim, repo)
