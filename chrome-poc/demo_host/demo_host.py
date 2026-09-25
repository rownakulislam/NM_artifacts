#!/usr/bin/env python3
"""
SecureVault NM Host — lightweight bridge between Chrome extension and desktop app.

Protocol:
  Requests:
    Ext → Host:  {"action": "get_version"}
    Host → Ext:  {"version": "1.0"}

    Ext → Host:  {"action": "get_secret"}
    Host → Ext:  {"secret": "<value>"}

Security checks performed:
  1. Parent process must be Google Chrome
"""

import sys
import os
import json
import struct
import socket
import subprocess

HOST_NAME    = "com.demo.securevault"
SOCKET_PATH  = os.path.expanduser(
    "~/Library/Application Support/SecureVault/vault.sock"
)


# ── Native Messaging I/O ──────────────────────────────────────────────────────

def read_message():
    raw_len = sys.stdin.buffer.read(4)
    if len(raw_len) < 4:
        return None
    msg_len = struct.unpack('<I', raw_len)[0]
    raw_msg = sys.stdin.buffer.read(msg_len)
    if len(raw_msg) < msg_len:
        return None
    return json.loads(raw_msg.decode('utf-8'))


def send_message(msg):
    encoded = json.dumps(msg).encode('utf-8')
    sys.stdout.buffer.write(struct.pack('<I', len(encoded)))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


# ── Security checks ───────────────────────────────────────────────────────────

def check_parent_is_chrome():
    """Verify we were spawned by Google Chrome, not an arbitrary process."""
    try:
        ppid = os.getppid()
        result = subprocess.run(
            ['ps', '-p', str(ppid), '-o', 'comm='],
            capture_output=True, text=True
        )
        parent = result.stdout.strip()
        return 'Google Chrome' in parent or 'chrome' in parent.lower()
    except Exception:
        return False


# ── Desktop app IPC ───────────────────────────────────────────────────────────

def ask_desktop_app(request: dict) -> dict:
    """Send a JSON request to the desktop app over Unix socket, return response."""
    if not os.path.exists(SOCKET_PATH):
        return {"error": "SecureVault desktop app is not running. "
                         "Start it with: python desktop_app/securevault_app.py"}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect(SOCKET_PATH)
            s.sendall(json.dumps(request).encode('utf-8') + b'\n')
            data = b''
            while not data.endswith(b'\n'):
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return json.loads(data.strip())
    except socket.timeout:
        return {"error": "Desktop app did not respond in time"}
    except Exception as e:
        return {"error": f"IPC error: {e}"}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # Defense: parent process check
    if not check_parent_is_chrome():
        sys.exit(1)

    while True:
        msg = read_message()
        if msg is None:
            break

        action = msg.get("action")

        if action == "get_version":
            send_message({"version": "1.0"})

        elif action == "get_secret":
            response = ask_desktop_app({"request": "get_secret"})
            send_message(response)

        else:
            send_message({"error": f"unknown action: {action}"})


if __name__ == "__main__":
    main()
