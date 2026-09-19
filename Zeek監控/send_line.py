#!/usr/bin/env python3
"""LINE Messaging API helper for Zeek ``dds_monitor.zeek``.

The channel token is read only from
``~/.config/dds-monitor/line_token``.  Keeping it out of the process
environment removes passive inheritance and ``/proc/<pid>/environ`` exposure.
Mode 0600 does not protect against arbitrary file reads by a process already
running as the same Unix UID; that requires service-account or OS secret-store
isolation. ``LINE_USER_ID`` is not a secret and remains an optional
compatibility fallback when ``line_user_id`` is absent.

When Zeek runs through ``sudo``, ``SUDO_USER`` selects the invoking user's
home so the helper does not accidentally look under ``/root``.
"""
import json
import os
import pwd
import stat
import sys
import urllib.error
import urllib.request


def _config_home() -> str:
    """Home dir of the real user, even when running under sudo (root)."""
    sudo_user = os.environ.get('SUDO_USER')
    if sudo_user:
        try:
            return pwd.getpwnam(sudo_user).pw_dir
        except KeyError:
            pass
    return os.path.expanduser('~')


def load_file_cred(file_name: str, *, secret: bool) -> str:
    """Load a credential file; reject an overly permissive secret file."""
    path = os.path.join(_config_home(), '.config', 'dds-monitor', file_name)
    try:
        if secret:
            mode = stat.S_IMODE(os.stat(path).st_mode)
            if mode & 0o077:
                print(
                    f'ERROR: {path} permissions must be 600 or stricter '
                    f'(current {mode:o})',
                    file=sys.stderr,
                )
                return ''
        with open(path, encoding='utf-8') as f:
            return f.read().strip()
    except OSError:
        return ''


def main() -> int:
    token = load_file_cred('line_token', secret=True)
    user_id = (
        load_file_cred('line_user_id', secret=False)
        or os.environ.get('LINE_USER_ID', '').strip()
    )
    message = sys.stdin.read().strip()

    if not token or not user_id:
        print(
            'ERROR: configure ~/.config/dds-monitor/line_token (chmod 600) '
            'and line_user_id (or LINE_USER_ID)',
            file=sys.stderr,
        )
        return 1
    if not message:
        print('ERROR: empty message on stdin', file=sys.stderr)
        return 1

    payload = json.dumps({
        'to': user_id,
        'messages': [{'type': 'text', 'text': message}],
    }).encode('utf-8')

    req = urllib.request.Request(
        'https://api.line.me/v2/bot/message/push',
        data=payload,
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}',
        },
        method='POST',
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                return 0
            print(f'ERROR: HTTP {resp.status}', file=sys.stderr)
            return 1
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors='replace')
        print(f'ERROR: HTTP {e.code} — {body}', file=sys.stderr)
        return 1
    except Exception as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
