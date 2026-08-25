"""Fail-closed project claim ledger and evidence verification.

This module turns a small claim specification into a portable JSON ledger and
human-readable Markdown report.  It never infers that a claim passed merely
because a file exists: every ``verified`` claim must cite at least one
non-empty, repository-relative artifact with an exact byte count and SHA-256.

The ledger is an integrity aid, not a signature or an authorization token.
It deliberately records that it cannot enable deployment or a live response.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .schema import sha256_file, utc_now


CLAIM_SPEC_SCHEMA = "sros2-firewall-project-claim-spec/v1"
EVIDENCE_LEDGER_SCHEMA = "sros2-firewall-project-evidence-ledger/v1"
CLAIM_STATUSES = frozenset({"verified", "provisional", "blocked"})
LEDGER_JSON_NAME = "evidence_ledger.json"
LEDGER_MARKDOWN_NAME = "evidence_ledger.md"

_CLAIM_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_TEXT = 4096
_SPEC_KEYS = frozenset(
    {"schema_version", "project_id", "project_revision", "claims"}
)
_CLAIM_KEYS = frozenset(
    {"claim_id", "title", "statement", "status", "evidence", "blockers", "limitations"}
)
_EVIDENCE_KEYS = frozenset({"path", "bytes", "sha256", "description"})
_LEDGER_KEYS = frozenset(
    {
        "schema_version",
        "created_utc",
        "project_id",
        "project_revision",
        "source_spec_sha256",
        "claims",
        "summary",
        "safety",
        "markdown_sha256",
        "ledger_sha256",
    }
)


class ProjectEvidenceError(ValueError):
    """A claim, artifact reference, or generated ledger is unsafe or invalid."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _text(value: Any, field: str, *, maximum: int = _MAX_TEXT) -> str:
    if not isinstance(value, str):
        raise ProjectEvidenceError(f"{field} must be text")
    result = value.strip()
    if not result or len(result) > maximum:
        raise ProjectEvidenceError(f"{field} must be 1..{maximum} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in result):
        raise ProjectEvidenceError(f"{field} contains control characters")
    return result


def _text_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list):
        raise ProjectEvidenceError(f"{field} must be a list")
    result = [_text(item, f"{field}[{index}]") for index, item in enumerate(value)]
    if len(result) != len(set(result)):
        raise ProjectEvidenceError(f"{field} contains duplicates")
    return result


def _exact_keys(value: Mapping[str, Any], allowed: frozenset[str], field: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ProjectEvidenceError(f"{field} has unsupported fields: {sorted(unknown)}")


def _read_json_object(path: str | Path, field: str) -> dict[str, Any]:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise ProjectEvidenceError(f"{field} must be a regular non-symlink file")
    if source.stat().st_size <= 0 or source.stat().st_size > 8 * 1024 * 1024:
        raise ProjectEvidenceError(f"{field} must be non-empty and at most 8 MiB")
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProjectEvidenceError(f"cannot read {field}: {exc}") from exc
    if not isinstance(value, dict):
        raise ProjectEvidenceError(f"{field} root must be an object")
    return value


def _repo_root(path: str | Path) -> Path:
    root = Path(path)
    if root.is_symlink() or not root.is_dir():
        raise ProjectEvidenceError("repository root must be a real directory")
    return root.resolve(strict=True)


def _safe_repo_file(root: Path, raw_path: Any) -> tuple[str, Path]:
    relative = _text(raw_path, "evidence.path", maximum=512)
    if "\\" in relative or ":" in relative or "\x00" in relative:
        raise ProjectEvidenceError("evidence.path must use safe POSIX repo-relative syntax")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise ProjectEvidenceError("evidence.path must stay inside the repository")

    candidate = root.joinpath(*pure.parts)
    current = root
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            raise ProjectEvidenceError(f"evidence path may not contain symlinks: {relative}")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ProjectEvidenceError(f"evidence file does not exist: {relative}") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ProjectEvidenceError("evidence.path escaped the repository") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise ProjectEvidenceError(f"evidence must be a regular file: {relative}")
    return pure.as_posix(), resolved


def _normalize_evidence(value: Any, root: Path, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProjectEvidenceError(f"{field} must be an object")
    _exact_keys(value, _EVIDENCE_KEYS, field)
    required = {"path", "bytes", "sha256"}
    missing = required - set(value)
    if missing:
        raise ProjectEvidenceError(f"{field} is missing fields: {sorted(missing)}")

    relative, resolved = _safe_repo_file(root, value["path"])
    expected_bytes = value["bytes"]
    if isinstance(expected_bytes, bool) or not isinstance(expected_bytes, int) or expected_bytes <= 0:
        raise ProjectEvidenceError(f"{field}.bytes must be a positive integer")
    expected_sha = value["sha256"]
    if not isinstance(expected_sha, str) or not _SHA256_RE.fullmatch(expected_sha):
        raise ProjectEvidenceError(f"{field}.sha256 must be lowercase SHA-256 hex")

    actual_bytes = resolved.stat().st_size
    if actual_bytes <= 0:
        raise ProjectEvidenceError(f"evidence file is empty: {relative}")
    if actual_bytes != expected_bytes:
        raise ProjectEvidenceError(
            f"evidence size mismatch for {relative}: expected {expected_bytes}, got {actual_bytes}"
        )
    actual_sha = sha256_file(resolved)
    if actual_sha != expected_sha:
        raise ProjectEvidenceError(f"evidence SHA-256 mismatch for {relative}")

    result = {
        "path": relative,
        "bytes": actual_bytes,
        "sha256": actual_sha,
    }
    if "description" in value:
        result["description"] = _text(value["description"], f"{field}.description", maximum=512)
    return result


def normalize_claim_spec(
    spec: Mapping[str, Any], repo_root: str | Path
) -> dict[str, Any]:
    """Validate a claim specification and verify every cited artifact.

    Unknown fields are rejected.  This prevents a caller from adding a loose
    ``deployment_ready=true`` flag that the ledger generator does not know how
    to substantiate.
    """

    if not isinstance(spec, Mapping):
        raise ProjectEvidenceError("claim spec must be an object")
    _exact_keys(spec, _SPEC_KEYS, "claim spec")
    if set(spec) != _SPEC_KEYS:
        raise ProjectEvidenceError(
            f"claim spec fields must be exactly {sorted(_SPEC_KEYS)}"
        )
    if spec.get("schema_version") != CLAIM_SPEC_SCHEMA:
        raise ProjectEvidenceError("unsupported claim spec schema_version")
    project_id = _text(spec.get("project_id"), "project_id", maximum=128)
    project_revision = _text(spec.get("project_revision"), "project_revision", maximum=128)
    claims = spec.get("claims")
    if not isinstance(claims, list) or not claims:
        raise ProjectEvidenceError("claims must be a non-empty list")

    root = _repo_root(repo_root)
    normalized_claims: list[dict[str, Any]] = []
    seen_claims: set[str] = set()
    for index, raw_claim in enumerate(claims):
        field = f"claims[{index}]"
        if not isinstance(raw_claim, Mapping):
            raise ProjectEvidenceError(f"{field} must be an object")
        _exact_keys(raw_claim, _CLAIM_KEYS, field)
        if set(raw_claim) != _CLAIM_KEYS:
            raise ProjectEvidenceError(
                f"{field} fields must be exactly {sorted(_CLAIM_KEYS)}"
            )
        claim_id = raw_claim.get("claim_id")
        if not isinstance(claim_id, str) or not _CLAIM_ID_RE.fullmatch(claim_id):
            raise ProjectEvidenceError(f"{field}.claim_id has invalid syntax")
        if claim_id in seen_claims:
            raise ProjectEvidenceError(f"duplicate claim_id: {claim_id}")
        seen_claims.add(claim_id)

        status = raw_claim.get("status")
        if status not in CLAIM_STATUSES:
            raise ProjectEvidenceError(f"{field}.status is unsupported")
        evidence = raw_claim.get("evidence")
        if not isinstance(evidence, list):
            raise ProjectEvidenceError(f"{field}.evidence must be a list")
        normalized_evidence = [
            _normalize_evidence(item, root, f"{field}.evidence[{evidence_index}]")
            for evidence_index, item in enumerate(evidence)
        ]
        paths = [item["path"] for item in normalized_evidence]
        if len(paths) != len(set(paths)):
            raise ProjectEvidenceError(f"{field}.evidence contains duplicate paths")

        blockers = _text_list(raw_claim.get("blockers"), f"{field}.blockers")
        limitations = _text_list(raw_claim.get("limitations"), f"{field}.limitations")
        if status == "verified" and not normalized_evidence:
            raise ProjectEvidenceError(
                f"verified claim {claim_id} must cite non-empty evidence"
            )
        if status == "verified" and blockers:
            raise ProjectEvidenceError(
                f"verified claim {claim_id} may not retain blockers"
            )
        if status == "blocked" and not blockers:
            raise ProjectEvidenceError(
                f"blocked claim {claim_id} must state at least one blocker"
            )

        normalized_claims.append(
            {
                "claim_id": claim_id,
                "title": _text(raw_claim.get("title"), f"{field}.title", maximum=256),
                "statement": _text(raw_claim.get("statement"), f"{field}.statement"),
                "status": status,
                "evidence": normalized_evidence,
                "blockers": blockers,
                "limitations": limitations,
            }
        )

    return {
        "schema_version": CLAIM_SPEC_SCHEMA,
        "project_id": project_id,
        "project_revision": project_revision,
        "claims": normalized_claims,
    }


def load_claim_spec(path: str | Path, repo_root: str | Path) -> dict[str, Any]:
    return normalize_claim_spec(_read_json_object(path, "claim spec"), repo_root)


def _escape_markdown(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _render_markdown(ledger: Mapping[str, Any]) -> str:
    summary = ledger["summary"]
    lines = [
        "# Project evidence ledger",
        "",
        f"- Project: `{_escape_markdown(ledger['project_id'])}`",
        f"- Revision: `{_escape_markdown(ledger['project_revision'])}`",
        f"- Generated (UTC): `{ledger['created_utc']}`",
        f"- Claims: verified {summary['verified']}, provisional {summary['provisional']}, blocked {summary['blocked']}",
        "- This ledger cannot authorize deployment, an adapter, or an autonomous IP block.",
        "",
        "| Claim | Status | Statement | Evidence | Blockers |",
        "|---|---|---|---:|---|",
    ]
    for claim in ledger["claims"]:
        blockers = "; ".join(claim["blockers"]) if claim["blockers"] else "—"
        lines.append(
            "| {claim} | {status} | {statement} | {evidence} | {blockers} |".format(
                claim=_escape_markdown(claim["title"]),
                status=claim["status"],
                statement=_escape_markdown(claim["statement"]),
                evidence=len(claim["evidence"]),
                blockers=_escape_markdown(blockers),
            )
        )
    lines.extend(["", "## Claim details", ""])
    for claim in ledger["claims"]:
        if claim["evidence"]:
            lines.extend([f"### Evidence for `{claim['claim_id']}`", ""])
            for evidence in claim["evidence"]:
                description = evidence.get("description", "artifact")
                lines.append(
                    f"- `{evidence['path']}` — {evidence['bytes']} bytes, "
                    f"SHA-256 `{evidence['sha256']}` ({description})"
                )
            lines.append("")
        if claim["limitations"]:
            lines.extend([f"### Limitations for `{claim['claim_id']}`", ""])
            lines.extend(f"- {item}" for item in claim["limitations"])
            lines.append("")
    lines.extend(
        [
            "",
            "## Safety boundary",
            "",
            "This is an evidence inventory, not a cryptographic signature or live-test authorization.",
            "A valid ledger proves only that the cited repository files matched the recorded size and hash at verification time.",
            "",
        ]
    )
    return "\n".join(lines)


def _write_bytes_fsync(path: Path, payload: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _atomic_publish_directory(destination: Path, files: Mapping[str, bytes]) -> None:
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"refusing to overwrite evidence ledger: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
        )
    )
    try:
        for name, payload in files.items():
            if PurePosixPath(name).name != name:
                raise ProjectEvidenceError("ledger output name must be a basename")
            _write_bytes_fsync(staging / name, payload)
        if destination.exists() or destination.is_symlink():
            raise FileExistsError(f"refusing to overwrite evidence ledger: {destination}")
        os.replace(staging, destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def generate_evidence_ledger(
    spec: Mapping[str, Any] | str | Path,
    repo_root: str | Path,
    output_dir: str | Path,
) -> dict[str, Any]:
    """Verify ``spec`` and atomically publish JSON plus Markdown.

    The output directory must not already exist.  Both files are prepared in a
    sibling staging directory and become visible together via one rename.
    """

    normalized = (
        load_claim_spec(spec, repo_root)
        if isinstance(spec, (str, Path))
        else normalize_claim_spec(spec, repo_root)
    )
    counts = Counter(claim["status"] for claim in normalized["claims"])
    ledger: dict[str, Any] = {
        "schema_version": EVIDENCE_LEDGER_SCHEMA,
        "created_utc": utc_now(),
        "project_id": normalized["project_id"],
        "project_revision": normalized["project_revision"],
        "source_spec_sha256": _sha256_bytes(_canonical_bytes(normalized)),
        "claims": normalized["claims"],
        "summary": {
            "total": len(normalized["claims"]),
            "verified": counts["verified"],
            "provisional": counts["provisional"],
            "blocked": counts["blocked"],
            "all_claims_verified": counts["verified"] == len(normalized["claims"]),
        },
        "safety": {
            "evidence_inventory_only": True,
            "deployment_eligible": False,
            "autonomous_ip_block_ready": False,
            "runtime_authorization": False,
        },
    }
    markdown = _render_markdown(ledger).encode("utf-8")
    ledger["markdown_sha256"] = _sha256_bytes(markdown)
    ledger["ledger_sha256"] = _sha256_bytes(_canonical_bytes(ledger))
    json_payload = json.dumps(
        ledger,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
        allow_nan=False,
    ).encode("utf-8") + b"\n"
    _atomic_publish_directory(
        Path(output_dir),
        {LEDGER_JSON_NAME: json_payload, LEDGER_MARKDOWN_NAME: markdown},
    )
    return {
        "output_dir": str(Path(output_dir)),
        "json": str(Path(output_dir) / LEDGER_JSON_NAME),
        "markdown": str(Path(output_dir) / LEDGER_MARKDOWN_NAME),
        "ledger_sha256": ledger["ledger_sha256"],
        "summary": ledger["summary"],
        "deployment_eligible": False,
        "runtime_authorization": False,
    }


def verify_evidence_ledger(
    ledger_path: str | Path,
    repo_root: str | Path,
    markdown_path: str | Path | None = None,
) -> dict[str, Any]:
    """Recheck a generated ledger, its Markdown, and every cited artifact."""

    ledger_file = Path(ledger_path)
    ledger = _read_json_object(ledger_file, "evidence ledger")
    _exact_keys(ledger, _LEDGER_KEYS, "evidence ledger")
    if set(ledger) != _LEDGER_KEYS:
        raise ProjectEvidenceError(
            f"evidence ledger fields must be exactly {sorted(_LEDGER_KEYS)}"
        )
    if ledger.get("schema_version") != EVIDENCE_LEDGER_SCHEMA:
        raise ProjectEvidenceError("unsupported evidence ledger schema_version")
    claimed_ledger_sha = ledger.get("ledger_sha256")
    if not isinstance(claimed_ledger_sha, str) or not _SHA256_RE.fullmatch(claimed_ledger_sha):
        raise ProjectEvidenceError("invalid ledger_sha256")
    unsigned = dict(ledger)
    del unsigned["ledger_sha256"]
    if _sha256_bytes(_canonical_bytes(unsigned)) != claimed_ledger_sha:
        raise ProjectEvidenceError("ledger content SHA-256 mismatch")

    safety = ledger.get("safety")
    if safety != {
        "evidence_inventory_only": True,
        "deployment_eligible": False,
        "autonomous_ip_block_ready": False,
        "runtime_authorization": False,
    }:
        raise ProjectEvidenceError("ledger safety boundary is missing or overclaims readiness")

    created_utc = ledger.get("created_utc")
    if not isinstance(created_utc, str):
        raise ProjectEvidenceError("ledger created_utc is invalid")
    try:
        parsed = datetime.fromisoformat(created_utc)
    except ValueError as exc:
        raise ProjectEvidenceError("ledger created_utc is invalid") from exc
    if parsed.tzinfo is None:
        raise ProjectEvidenceError("ledger created_utc must include a timezone")

    normalized = normalize_claim_spec(
        {
            "schema_version": CLAIM_SPEC_SCHEMA,
            "project_id": ledger.get("project_id"),
            "project_revision": ledger.get("project_revision"),
            "claims": ledger.get("claims"),
        },
        repo_root,
    )
    if _sha256_bytes(_canonical_bytes(normalized)) != ledger.get("source_spec_sha256"):
        raise ProjectEvidenceError("source claim specification SHA-256 mismatch")

    counts = Counter(claim["status"] for claim in normalized["claims"])
    expected_summary = {
        "total": len(normalized["claims"]),
        "verified": counts["verified"],
        "provisional": counts["provisional"],
        "blocked": counts["blocked"],
        "all_claims_verified": counts["verified"] == len(normalized["claims"]),
    }
    if ledger.get("summary") != expected_summary:
        raise ProjectEvidenceError("ledger claim summary is inconsistent")

    markdown_file = Path(markdown_path) if markdown_path is not None else ledger_file.with_name(LEDGER_MARKDOWN_NAME)
    if markdown_file.is_symlink() or not markdown_file.is_file():
        raise ProjectEvidenceError("ledger Markdown is missing or symlinked")
    markdown_bytes = markdown_file.read_bytes()
    if not markdown_bytes or _sha256_bytes(markdown_bytes) != ledger.get("markdown_sha256"):
        raise ProjectEvidenceError("ledger Markdown SHA-256 mismatch")
    if markdown_bytes != _render_markdown(ledger).encode("utf-8"):
        raise ProjectEvidenceError("ledger Markdown content is inconsistent")

    return {
        "valid": True,
        "ledger_sha256": claimed_ledger_sha,
        "summary": expected_summary,
        "deployment_eligible": False,
        "runtime_authorization": False,
    }


__all__ = [
    "CLAIM_SPEC_SCHEMA",
    "CLAIM_STATUSES",
    "EVIDENCE_LEDGER_SCHEMA",
    "LEDGER_JSON_NAME",
    "LEDGER_MARKDOWN_NAME",
    "ProjectEvidenceError",
    "generate_evidence_ledger",
    "load_claim_spec",
    "normalize_claim_spec",
    "verify_evidence_ledger",
]
