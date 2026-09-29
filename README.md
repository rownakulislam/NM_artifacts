# Native Messaging Security — Demo Artifact

Proof-of-concept artifact accompanying the paper *The Native Menace: Host-to-Browser Cross-Boundary Attacks via Native Messaging*. Demonstrates three attacks against
the Native Messaging (NM) channel on **Chrome** and **Firefox** (macOS).

---

## Demo System

A minimal demo system was developed consisting of an application and extension which is the target, where the extension requests for a secret over *Native Messaging API* which was stored in the macOS keychain by the application:

```
Browser Extension  (popup: Get Secret / Get Version)
      ↕  Native Messaging  (stdio, length-prefixed JSON)
NM Host  demo_host/demo_host.py
      ↕  Unix socket  ~/Library/Application Support/SecureVault/vault.sock
Desktop App  desktop_app/securevault_app.py
      ↕  vault-helper binary  (compiled Swift)
macOS Login Keychain  (ACL: only vault-helper trusted; Touch ID on read)
```

The extension sends `{"action": "get_secret"}`. The NM host fetches the secret from
the desktop app over a Unix socket and returns it.

The secret is protected by a Keychain ACL that trusts only the `vault-helper` binary.
Any other process attempting to read it receives a Keychain confirmation dialog. Reading
triggers a Touch ID (or password) prompt via `LocalAuthentication` before the Keychain
is queried.

### Controls and Constraints in place

Three existing controls and constraints which reflects the in-place safe-guard for a default target, are layered into the demo system. All three attacks must work around them.

| # | Controls and Constraints | Implementation |
|---|---------|----------------|
| D1 | NM manifest installed at **system level** (root-owned, not user-writable) | `sudo` step in `install.sh` writes to `/Library/.../NativeMessagingHosts/` |
| D2 | NM host verifies its **parent process is the browser** before responding | `check_parent_is_chrome()` / `check_parent_is_firefox()` in `demo_host.py` |
| D3 | `allowed_origins` / `allowed_extensions` in Host manifest — only the specific victim extension may connect | Hard-coded extension ID / gecko ID in the manifest JSON |

---

## Repository Layout

The scripts in this repository represents a realistic delivery vehicle. This can be packaged in a into a macOS `.app` bundle or a Windows 
installer using standard tools.

```
NM_artifacts/
├── README.md                                     # Setup guide and attack documentation
├── chrome-poc/                                   # Chrome attack suite
│   ├── demo_extension/                           # Victim Chrome extension (MV3)
│   │   ├── manifest.json
│   │   ├── background.js
│   │   ├── popup.html
│   │   └── popup.js
│   ├── demo_host/                                # NM host + installer
│   │   ├── demo_host.py                          # NM host (parent-process check)
│   │   └── install.sh                            # Compiles vault-helper, seeds Keychain, installs manifest
│   ├── desktop_app/                              # Menu-bar app holding the secret
│   │   ├── securevault_app.py
│   │   └── vault-helper.swift                    # Compiled by install.sh → vault-helper binary
│   └── attacks/
│       ├── attack1_bidirectional_mitm.py         # Bidirectional MITM
│       ├── attack2_host_imitation.py             # Host imitation
│       ├── attack3_extension_imitation.py        # Extension imitation
│       ├── passthrough_extension/                # Attacker extension for attack 1
│       │   ├── manifest.json
│       │   └── background.js
│       └── fake_extension/                       # Attacker extension for attack 3
│           ├── manifest.json
│           └── background.js
└── firefox-poc/                                  # Firefox attack suite
    ├── demo_extension/                           # Victim Firefox extension (MV2)
    │   ├── manifest.json
    │   ├── background.js
    │   ├── popup.html
    │   └── popup.js
    ├── demo_host/                                # NM host + installer
    │   ├── demo_host.py                          # NM host (parent-process check)
    │   └── install.sh                            # Compiles vault-helper, seeds Keychain, installs manifest, geckodriver
    ├── desktop_app/                              # Menu-bar app holding the secret
    │   ├── securevault_app.py
    │   └── vault-helper.swift                    # Compiled by install.sh → vault-helper binary
    └── attacks/
        ├── attack1_bidirectional_mitm.py         # Bidirectional MITM
        ├── attack2_host_imitation.py             # Host imitation
        ├── attack3_extension_imitation.py        # Extension imitation
        ├── passthrough_extension/                # Attacker extension for attack 1
        │   ├── manifest.json
        │   └── background.js
        └── fake_extension/                       # Attacker extension for attack 3
            ├── manifest.json
            └── background.js
```

---

## Setup of the Demo System

### Prerequisites

- macOS (Keychain + Unix socket paths are macOS-specific)
- Python 3.9+
- Google Chrome and/or Firefox installed at default paths
- **Xcode Command Line Tools** — required to compile `vault-helper`
  ```bash
  xcode-select --install
  ```
- **Touch ID enrolled or a login password set** — Touch ID fires on each secret read; falls back to password prompt if biometry is unavailable

### Chrome

**1. Install Python dependencies, compile vault-helper, seed Keychain, install NM manifest**

```bash
bash chrome-poc/demo_host/install.sh
```

This:
- Installs `websockets` and `rumps` Python packages
- Compiles `desktop_app/vault-helper.swift` → `desktop_app/vault-helper` binary
- Seeds the Keychain with the demo secret under a Keychain ACL that trusts only the `vault-helper` binary
- Creates `run_host.sh` wrapper (hardcodes the Python interpreter path for Chrome's stripped PATH)
- Writes the NM manifest to `/Library/Google/Chrome/NativeMessagingHosts/com.demo.securevault.json` (requires sudo)

**2. Load the victim extension**

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. **Load unpacked** → select `chrome-poc/demo_extension/`

The extension ID is fixed (derived from the hardcoded `key` in `manifest.json`) — it does
not change between loads.

**3. Start the desktop app**

```bash
python chrome-poc/desktop_app/securevault_app.py
```

A 🔐 icon appears in the menu bar. Keep it running during all tests.

**4. Verify baseline**

Click the SecureVault toolbar icon → **Get Secret**.

A **Touch ID prompt** (or password dialog) fires — this is expected. Approve it.

Expected result: `vault_token_eyJhbGciOiJSUzI1NiJ9.demo_secret_42`

### Firefox

**1. Install Python dependencies, compile vault-helper, geckodriver, seed Keychain, install NM manifest**

```bash
bash firefox-poc/demo_host/install.sh
```

Same as Chrome but writes to `/Library/Application Support/Mozilla/NativeMessagingHosts/`.
Also installs geckodriver via Homebrew if not already present.

**2. Load the victim extension**

1. Open `about:debugging` → **This Firefox**
2. **Load Temporary Add-on** → select `firefox-poc/demo_extension/manifest.json`

The gecko ID is the fixed string `securevault@demo` declared in `manifest.json`.

**3. Start the desktop app** (if not already running)

```bash
python firefox-poc/desktop_app/securevault_app.py
```

**4. Verify baseline**

Click the SecureVault toolbar icon → **Get Secret**.

A **Touch ID prompt** (or password dialog) fires — this is expected. Approve it.

Expected result: `vault_token_eyJhbGciOiJSUzI1NiJ9.demo_secret_42`

---

## Attacks

### How the mechanisms are bypassed

All three attacks exploit the same two structural weaknesses before doing anything
attack-specific:

**Bypassing D1 : shadow manifest**
The NM manifest at the system level is root-owned, which can't be modified or replaced, but the browser checks a
*user-level* NM directory first that any process can write to without elevated privileges:

| Browser | User-level path |
|---------|----------------|
| Chrome  | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` |
| Firefox | `~/Library/Application Support/Mozilla/NativeMessagingHosts/` |

A file placed there with the same host name silently overrides the system entry. No
root required.

**Bypassing D2 : genuine browser as parent**
The real NM host requires that its parent process is a browser instance. In attacks 1
and 3 the real host is spawned by an attacker-controlled headless browser with an
integrated attacker extension — the parent really is a browser binary and
parent check passes without any process spoofing. In attack 2 the attacker
script itself acts as the NM host, so the check is never reached.

**Bypassing D3 : matching the extension identity**
When an extension calls `connectNative()`, the browser checks the calling extension's
ID against the `allowed_origins` / `allowed_extensions` list in the NM manifest. Only
a matching ID is permitted to open the channel. The attacker's extension (passthrough
or fake) must therefore present the same ID as the victim extension.

*Acquiring the ID:*
- *Chrome:* The extension ID is deterministically derived from the extension's public
  key (SHA-256 of the DER-encoded key → first 32 nibbles mapped to `a–p`). The key is
  in `manifest.json` and also stored in plaintext in Chrome's `Default/Preferences`
  and `Default/Secure Preferences` (`extensions.settings.<id>.manifest.key`).
  Embedding the same public key into the attacker extension's `manifest.json` causes
  Chrome to assign it the identical ID — the `allowed_origins` check passes.
- *Firefox:* The gecko ID is a plain human-readable string declared in
  `browser_specific_settings.gecko.id`. Copying that string into the attacker
  extension's manifest is sufficient — no cryptography involved.

*Loading the unsigned attacker extension:*
Attacker extensions are unpacked and unsigned — not published through the Chrome Web
Store or Mozilla AMO. Browsers block such extensions by default.

- *Chrome:* The attacker launches a headless Chrome instance with
  `--remote-debugging-port` and loads the extension via the CDP
  `Extensions.loadUnpacked` command — injected programmatically through the debug
  interface without any Developer mode requirement.
- *Firefox:* The extension is loaded via geckodriver's `moz/addon/install` WebDriver
  endpoint with `"temporary": true`. Temporary extensions bypass AMO signature
  enforcement on all Firefox channels, exactly as `about:debugging` would load them.

---

### Attack 1 — Bidirectional MITM

**What it demonstrates:** Every message on the NM channel is intercepted, logged and modified if necessary
in both directions, the extension and host are unaware. The desktop app reads the secret from the Keychain
(Touch ID fires), but the attacker intercepts the secret on the NM pipe before it reaches the extension.

**Flow:**

```
┌──────────────────────────────────────────────────────┐
│  Victim Extension                                    │
│  chrome-extension://<id>  |  gecko id                │
└─────────────────────────┬────────────────────────────┘
                          │ NM stdio
                          │ D1: shadow manifest overrides system entry
                          ▼
┌──────────────────────────────────────────────────────┐
│  MITM Wrapper  (attacker script, no parent check)    │
└─────────────────────────┬────────────────────────────┘
                          │ WebSocket :13501
                          ▼
┌──────────────────────────────────────────────────────┐
│  Relay  (setup mode — logs all traffic)              │
└─────────────────────────┬────────────────────────────┘
                          │ WebSocket :13500
                          ▼
┌──────────────────────────────────────────────────────┐
│  Passthrough Extension  (attacker headless browser)  │
│  same extension ID as victim → D3 passes             │
└─────────────────────────┬────────────────────────────┘
                          │ NM stdio  (_real manifest)
                          ▼
┌──────────────────────────────────────────────────────┐
│  Real NM Host                                        │
│ spawned by headless browser → parent check passes(D2)│
└──────────────────────────────────────────────────────┘
```

**Run:**

```bash
# Chrome
python chrome-poc/attacks/attack1_bidirectional_mitm.py --setup

# Firefox
python firefox-poc/attacks/attack1_bidirectional_mitm.py --setup
```

Follow the narrated steps. When prompted, click **Get Secret** in the victim extension.
Approve the Touch ID prompt — the secret travels through the relay and is intercepted.

**Expected output:** Intercepted messages printed to the terminal and written to
`attacks/mitm_intercept.log`. The secret appears in plaintext in the `HOST->EXT` line.

---

### Attack 2 — Host Imitation

**What it demonstrates:** The NM host is replaced entirely by a fake. The victim
extension receives a fabricated response; the real host is never contacted.

**Flow:**

```
┌──────────────────────────────────────────────────────┐
│  Victim Extension                                    │
│  chrome-extension://<id>  |  gecko id                │
└─────────────────────────┬────────────────────────────┘
                          │ NM stdio
                          │ D1: shadow manifest overrides system entry
                          ▼
┌──────────────────────────────────────────────────────┐
│  Fake NM Host                                        │
│  spawned by victim browser                           │
│  replies {"secret": "fake_secret_123"}               │
│  real host is never launched                         │
└──────────────────────────────────────────────────────┘
```

**Run:**

```bash
# Chrome
python chrome-poc/attacks/attack2_host_imitation.py --setup

# Firefox
python firefox-poc/attacks/attack2_host_imitation.py --setup
```

When prompted, click **Get Secret** in the victim extension.

**Expected output:** The extension popup displays `fake_secret_123`.

---

### Attack 3 — Extension Imitation

**What it demonstrates:** A fake extension assumes the victim extension's identity and
connects directly to the real NM host — without the victim extension being involved
at all.

**Flow:**

```
┌──────────────────────────────────────────────────────┐
│  Fake Extension  (attacker headless browser)         │
│  same extension ID as victim → D3 passes             │
└─────────────────────────┬────────────────────────────┘
                          │ NM stdio
                          │ D1: user-level manifest, no root needed
                          ▼
┌──────────────────────────────────────────────────────┐
│  Real NM Host                                        │
│ spawned by headless browser → parent check passes(D2)│
└──────────────────────────────────────────────────────┘
```

**Run:**

```bash
# Chrome
python chrome-poc/attacks/attack3_extension_imitation.py --setup

# Firefox
python firefox-poc/attacks/attack3_extension_imitation.py --setup
```

**Expected output:** The secret is printed to the terminal under
`Secret obtained by fake extension`. The victim extension is never clicked.

---
