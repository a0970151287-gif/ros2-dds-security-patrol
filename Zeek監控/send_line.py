#!/usr/bin/env python3
"""LINE Messaging API helper for Zeek dds_monitor.zeek.

Reads the alert message from stdin and pushes it to LINE.
Required env vars:
  LINE_CHANNEL_TOKEN  — Channel access token
  LINE_USER_ID        — Recipient user/group ID
"""
import json
import os
import sys
import urllib.error
import urllib.request


def main() -> int:
    token = os.environ.get('LINE_CHANNEL_TOKEN', '').strip()
    user_id = os.environ.get('LINE_USER_ID', '').strip()
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
