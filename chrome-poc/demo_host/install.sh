#!/bin/bash
# install.sh — set up SecureVault NM host (system-level manifest)
#
# What this does:
#   1. Compiles vault-helper.swift → vault-helper binary
#   2. Seeds the Keychain with the demo secret (biometric ACL)
#   3. Creates a shell wrapper so Chrome can find the Python interpreter
#   4. Installs the NM manifest to /Library/Google/Chrome/NativeMessagingHosts/
#      (system-level — requires sudo for the copy step)
#
# Requirements:
#   - Xcode Command Line Tools  (xcode-select --install)
#   - macOS with Touch ID enrolled, or a login password set (for fallback)
#
# Usage:
#   bash install.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DESKTOP_DIR="$SCRIPT_DIR/../desktop_app"

# ── Preflight: Xcode Command Line Tools ───────────────────────────────────────
# swiftc (needed to compile vault-helper) ships with Xcode CLT.
# xcode-select --install opens a GUI dialog and returns immediately —
# we can't block-wait for it, so we exit and ask the user to re-run.

if ! xcode-select -p &>/dev/null; then
  echo "Xcode Command Line Tools not found — triggering installer..."
  xcode-select --install 2>/dev/null || true
  echo ""
  echo "A system dialog has opened to install Xcode Command Line Tools."
  echo "Once installation completes, re-run this script:"
  echo "  bash $0"
  exit 1
fi

# ── Step 0: Install Python dependencies ───────────────────────────────────────

echo "[0/6] Installing Python dependencies..."
PIP_CMD=""
if command -v pip3 &>/dev/null; then
  PIP_CMD="pip3"
elif command -v pip &>/dev/null; then
  PIP_CMD="pip"
else
  PIP_CMD="python3 -m pip"
fi
$PIP_CMD install websockets rumps --quiet --user --break-system-packages \
  && echo "      OK — websockets, rumps installed (via $PIP_CMD)" \
  || echo "      WARN — install failed; run manually: $PIP_CMD install websockets rumps --user"

HOST_SCRIPT="$SCRIPT_DIR/demo_host.py"
WRAPPER="$SCRIPT_DIR/run_host.sh"
SYSTEM_MANIFEST_DIR="/Library/Google/Chrome/NativeMessagingHosts"
HOST_NAME="com.demo.securevault"

# Extension ID is deterministic — derived from the RSA public key hardcoded in
# demo_extension/manifest.json. Recompute: SHA256(base64decode(key))[:32] mapped a-p.
EXT_ID="gomoepnfihidodbmflfbncchlembkcip"

# ── Step 1: Compile vault-helper ──────────────────────────────────────────────

echo "[1/6] Compiling vault-helper.swift..."
VAULT_HELPER="$DESKTOP_DIR/vault-helper"
VAULT_SWIFT="$DESKTOP_DIR/vault-helper.swift"

swiftc "$VAULT_SWIFT" -o "$VAULT_HELPER" \
  && echo "      OK — $VAULT_HELPER compiled" \
  || { echo "ERROR: swiftc failed"; exit 1; }

# ── Step 2: Seed Keychain (biometric ACL) ─────────────────────────────────────

echo "[2/6] Seeding Keychain with biometric access control..."
echo "      (Touch ID prompt may appear — this is expected)"
# Remove any stale item (e.g. created by security add-generic-password in a
# previous install run). The security CLI has ACL trust to delete it; our
# Swift binary may not.
security delete-generic-password -s "$HOST_NAME" -a "demo" 2>/dev/null || true
"$VAULT_HELPER" write "vault_token_eyJhbGciOiJSUzI1NiJ9.demo_secret_42" \
  && echo "      OK — secret stored in Keychain under service '$HOST_NAME'" \
  || { echo "ERROR: vault-helper write failed (is Touch ID / a password set?)"; exit 1; }

# ── Step 3: Create shell wrapper ──────────────────────────────────────────────
# Chrome spawns NM hosts with a stripped PATH — /usr/bin/env python3 may fail.
# The wrapper hardcodes the Python interpreter path found at install time.

echo "[3/6] Creating run_host.sh wrapper..."
PYTHON3_PATH="$(which python3)"
if [ -z "$PYTHON3_PATH" ]; then
  echo "ERROR: python3 not found in PATH"
  exit 1
fi

cat > "$WRAPPER" << EOF
#!/bin/bash
exec "$PYTHON3_PATH" "$HOST_SCRIPT" "\$@"
EOF
chmod +x "$WRAPPER"
echo "      OK — $WRAPPER (uses $PYTHON3_PATH)"

# ── Step 4: Write manifest JSON ───────────────────────────────────────────────

echo "[4/6] Writing manifest..."
MANIFEST_JSON=$(cat << EOF
{
  "name": "$HOST_NAME",
  "description": "SecureVault NM host — security research demo",
  "path": "$WRAPPER",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$EXT_ID/"
  ]
}
EOF
)

TMP_MANIFEST="$(mktemp /tmp/${HOST_NAME}.json.XXXXXX)"
echo "$MANIFEST_JSON" > "$TMP_MANIFEST"
echo "      Manifest contents:"
cat "$TMP_MANIFEST" | sed 's/^/        /'

# ── Step 5: Install manifest (needs sudo) ─────────────────────────────────────

echo "[5/6] Installing manifest to $SYSTEM_MANIFEST_DIR/$HOST_NAME.json"
echo "      This requires sudo (system-level path, root-owned)."

sudo mkdir -p "$SYSTEM_MANIFEST_DIR"
sudo cp "$TMP_MANIFEST" "$SYSTEM_MANIFEST_DIR/$HOST_NAME.json"
sudo chmod 644 "$SYSTEM_MANIFEST_DIR/$HOST_NAME.json"
rm "$TMP_MANIFEST"

echo ""
echo "[6/6] Done."
echo ""
echo "  vault-helper:   $VAULT_HELPER"
echo "  Keychain item:  service=com.demo.securevault  account=demo  (biometric ACL)"
echo "  NM manifest:    $SYSTEM_MANIFEST_DIR/$HOST_NAME.json"
echo ""
echo "Next:"
echo "  1. Start the desktop app:  python $DESKTOP_DIR/securevault_app.py"
echo "  2. Open Chrome, click the SecureVault extension popup"
echo "  3. Click 'Get Secret' — Touch ID (or password) prompt fires, then secret appears"
