#!/usr/bin/env python3
"""Move legacy secret assignments into dedicated mode-0600 files.

Secret values are never printed.  The migration refuses symlinks, duplicate
conflicts, unsafe permissions, shell expansions, and overwriting a different
existing secret.
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import stat
import tempfile
from pathlib import Path


ASSIGNMENT_RE = re.compile(
    r"^\s*(?:export\s+)?"
    r"(DDS_ALERT_SECRET|LINE_CHANNEL_TOKEN)\s*=(.*)$"
)
SECRET_NAMES = ("DDS_ALERT_SECRET", "LINE_CHANNEL_TOKEN")


def _safe_file(path: Path, *, optional: bool) -> None:
    if not path.exists():
        if optional:
            return
        raise ValueError(f"missing file: {path}")
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"refusing non-regular file: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise ValueError(f"secret/config file permissions exceed 0600: {path}")


def _parse_secret(raw: str, name: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError(f"{name} is empty")
    if value[0] in {"'", '"'}:
        try:
            parsed = ast.literal_eval(value)
        except (SyntaxError, ValueError) as exc:
            raise ValueError(f"{name} has invalid quoted value") from exc
        if not isinstance(parsed, str):
            raise ValueError(f"{name} must be a string")
        value = parsed
    elif any(character.isspace() for character in value):
        raise ValueError(f"{name} has unsafe unquoted whitespace")
    if not value or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError(f"{name} has invalid characters")
    if "$(" in value or "`" in value:
        raise ValueError(f"{name} contains forbidden shell expansion")
    return value


def _atomic_private_text(path: Path, value: str) -> None:
    if path.exists() and path.is_symlink():
        raise ValueError(f"refusing symlink: {path}")
    temporary: Path | None = None
    try:
        descriptor, raw_path = tempfile.mkstemp(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        )
        temporary = Path(raw_path)
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
            if not value.endswith("\n"):
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def migrate(config_dir: Path, *, check_only: bool) -> dict[str, object]:
    config_dir = config_dir.expanduser()
    if (
        not config_dir.is_dir()
        or config_dir.is_symlink()
        or stat.S_IMODE(config_dir.stat().st_mode) & 0o077
    ):
        raise ValueError(
            "config directory must be a real directory with mode 0700"
        )
    credentials = config_dir / "credentials"
    _safe_file(credentials, optional=False)
    lines = credentials.read_text(encoding="utf-8").splitlines()
    found: dict[str, str] = {}
    remaining = []
    removed_lines = 0
    for line in lines:
        match = ASSIGNMENT_RE.match(line)
        if match:
            name = match.group(1)
            value = _parse_secret(match.group(2), name)
            if name in found and found[name] != value:
                raise ValueError(f"conflicting duplicate {name}")
            found[name] = value
            removed_lines += 1
            continue
        if any(name in line for name in SECRET_NAMES):
            # Loader deliberately rejects even historical secret-name comments.
            removed_lines += 1
            continue
        remaining.append(line)

    destinations = {
        "DDS_ALERT_SECRET": config_dir / "alert_secret",
        "LINE_CHANNEL_TOKEN": config_dir / "line_token",
    }
    resolved: dict[str, str] = {}
    for name, destination in destinations.items():
        _safe_file(destination, optional=True)
        existing = (
            destination.read_text(encoding="utf-8").rstrip("\r\n")
            if destination.exists()
            else None
        )
        legacy = found.get(name)
        if existing is not None and legacy is not None and existing != legacy:
            raise ValueError(
                f"existing {destination.name} differs from legacy {name}"
            )
        if existing is not None:
            resolved[name] = existing
        elif legacy is not None:
            resolved[name] = legacy

    if "DDS_ALERT_SECRET" not in resolved:
        raise ValueError("no alert secret found in legacy or dedicated file")
    result = {
        "migration_needed": removed_lines > 0,
        "removed_legacy_lines": removed_lines,
        "alert_secret_ready": "DDS_ALERT_SECRET" in resolved,
        "line_token_ready": "LINE_CHANNEL_TOKEN" in resolved,
    }
    if check_only:
        return result

    for name, value in resolved.items():
        destination = destinations[name]
        if not destination.exists():
            _atomic_private_text(destination, value)
    _atomic_private_text(
        credentials,
        "\n".join(remaining).rstrip("\n"),
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safely migrate legacy DDS monitor secret assignments"
    )
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=Path.home() / ".config" / "dds-monitor",
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = migrate(args.config_dir, check_only=args.check)
    print(
        "migration_needed="
        f"{str(result['migration_needed']).lower()} "
        f"removed_legacy_lines={result['removed_legacy_lines']} "
        f"alert_secret_ready={str(result['alert_secret_ready']).lower()} "
        f"line_token_ready={str(result['line_token_ready']).lower()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
