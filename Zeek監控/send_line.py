#!/usr/bin/env python3
"""LINE Messaging API helper for Zeek dds_monitor.zeek.

Reads the alert message from stdin and pushes it to LINE.
Credential resolution order (each independently):
  1. Env var (LINE_CHANNEL_TOKEN / LINE_USER_ID)
  2. Config file ~/.config/dds-monitor/{line_token,line_user_id}
When run under sudo (zeek -i needs root), '~' resolves to the invoking
user via SUDO_USER so jesse's config is found instead of /root.
"""
import json
import os
import pwd
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


def load_cred(env_name: str, file_name: str) -> str:
    val = os.environ.get(env_name, '').strip()
    if val:
        return val
    path = os.path.join(_config_home(), '.config', 'dds-monitor', file_name)
    try:
        with open(path, encoding='utf-8') as f:
            return f.read().strip()
    except OSError:
        return ''


def main() -> int:
    token = load_cred('LINE_CHANNEL_TOKEN', 'line_token')
    user_id = load_cred('LINE_USER_ID', 'line_user_id')
    message = sys.stdin.read().strip()

    if not token or not user_id:
        print('ERROR: LINE_CHANNEL_TOKEN and LINE_USER_ID must be set', file=sys.stderr)
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
