#!/usr/bin/env python3
"""
SecureVault Desktop App — menu bar app that holds the secret in macOS Keychain.

Architecture:
  Chrome Extension
      ↕  Native Messaging (stdio)
  NM Host (demo_host.py)
      ↕  Unix domain socket  ←── this process listens here
  SecureVault Desktop App
      ↕  vault-helper binary (compiled Swift)
  macOS Data Protection Keychain  (biometric / user-presence ACL)

The secret is stored with kSecAccessControlBiometryAny (Touch ID) if the
device has biometry enrolled, otherwise kSecAccessControlUserPresence
(password dialog).  Any other process that tries to read the same Keychain
item directly will also trigger the auth prompt — no silent extraction via
`security find-generic-password` is possible.

The socket path is:
  ~/Library/Application Support/SecureVault/vault.sock

Protocol (newline-delimited JSON):
  Client → Server:  {"request": "get_secret", "session_id": "<uuid>"}
  Server → Client:  {"secret": "<value>",     "session_id": "<uuid>"}

  Client → Server:  {"request": "get_status"}
  Server → Client:  {"status": "running", "keychain_ok": true}
"""

import os
import sys
import json
import socket
import threading
import subprocess

try:
    import rumps
    HAS_RUMPS = True
except ImportError:
    HAS_RUMPS = False

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
VAULT_HELPER = os.path.join(SCRIPT_DIR, "vault-helper")

SOCKET_DIR  = os.path.expanduser("~/Library/Application Support/SecureVault")
SOCKET_PATH = os.path.join(SOCKET_DIR, "vault.sock")


# ── Keychain access via vault-helper ─────────────────────────────────────────

def keychain_get() -> str | None:
    """Read the secret via vault-helper (triggers Touch ID / password prompt)."""
    if not os.path.exists(VAULT_HELPER):
        print(f"[SecureVault] ERROR: vault-helper not found at {VAULT_HELPER}",
              file=sys.stderr)
        return None
    try:
        result = subprocess.run(
            [VAULT_HELPER, "read"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return result.stdout.strip()
        print(f"[SecureVault] vault-helper read failed: {result.stderr.strip()}",
              file=sys.stderr)
        return None
    except Exception as e:
        print(f"[SecureVault] vault-helper error: {e}", file=sys.stderr)
        return None


def keychain_ok() -> bool:
    """Check the vault-helper binary exists (item presence inferred from install)."""
    return os.path.exists(VAULT_HELPER)


# ── Socket server ─────────────────────────────────────────────────────────────

def handle_client(conn: socket.socket):
    try:
        data = b''
        while not data.endswith(b'\n'):
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk

        if not data:
            return

        request = json.loads(data.strip())
        req_type = request.get("request")

        if req_type == "get_secret":
            secret = keychain_get()
            if secret is not None:
                response = {"secret": secret,
                            "session_id": request.get("session_id")}
            else:
                response = {"error": "Secret not found or auth denied. "
                                     "Run demo_host/install.sh to seed it.",
                            "session_id": request.get("session_id")}

        elif req_type == "get_status":
            response = {"status": "running", "keychain_ok": keychain_ok()}

        else:
            response = {"error": f"unknown request: {req_type}"}

        conn.sendall(json.dumps(response).encode('utf-8') + b'\n')

    except json.JSONDecodeError:
        conn.sendall(json.dumps({"error": "invalid JSON"}).encode() + b'\n')
    except Exception as e:
        conn.sendall(json.dumps({"error": str(e)}).encode() + b'\n')
    finally:
        conn.close()


def run_socket_server():
    os.makedirs(SOCKET_DIR, exist_ok=True)
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    server.listen(10)
    print(f"[SecureVault] Listening on {SOCKET_PATH}", flush=True)

    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


# ── Menu bar app (rumps) ──────────────────────────────────────────────────────

if HAS_RUMPS:
    class SecureVaultApp(rumps.App):
        def __init__(self):
            super().__init__("🔐", quit_button="Quit SecureVault")
            self.menu = [
                rumps.MenuItem("SecureVault", callback=None),
                None,
                rumps.MenuItem("Status: starting...", callback=None),
                None,
            ]
            threading.Thread(target=self.start_server, daemon=True).start()

        def start_server(self):
            ok = keychain_ok()
            status = "Keychain: OK ✓" if ok else "Keychain: NOT FOUND ✗"
            self.menu["Status: starting..."].title = status
            run_socket_server()


# ── Fallback: headless server (no rumps) ─────────────────────────────────────

def run_headless():
    print("[SecureVault] rumps not installed — running as headless daemon.")
    print(f"[SecureVault] Keychain item: {'found' if keychain_ok() else 'NOT FOUND'}")
    print("[SecureVault] Press Ctrl+C to stop.")
    try:
        run_socket_server()
    except KeyboardInterrupt:
        print("\n[SecureVault] Stopped.")
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if HAS_RUMPS:
        SecureVaultApp().run()
    else:
        run_headless()
