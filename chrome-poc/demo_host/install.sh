#!/bin/bash
# install.sh — set up SecureVault NM host (system-level manifest)
#
# What this does:
#   1. Seeds the Keychain with the demo secret
#   2. Creates a shell wrapper so Chrome can find the Python interpreter
#   3. Installs the NM manifest to /Library/Google/Chrome/NativeMessagingHosts/
#      (system-level — requires sudo for the copy step)
#
# Usage:
#   bash install.sh
#
# The extension ID is derived from the hardcoded key in demo_extension/manifest.json
# and does not change between runs.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Step 0: Install Python dependencies ───────────────────────────────────────

echo "[0/5] Installing Python dependencies..."
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

# ── Step 1: Seed Keychain ─────────────────────────────────────────────────────

echo "[1/5] Seeding Keychain..."
security add-generic-password \
  -s "$HOST_NAME" \
  -a "demo" \
  -w "vault_token_eyJhbGciOiJSUzI1NiJ9.demo_secret_42" \
  -U 2>/dev/null \
  && echo "      OK — secret stored in Keychain under service '$HOST_NAME'" \
  || { echo "      WARN — Keychain seed failed (may need to allow access in popup)"; }

# ── Step 2: Create shell wrapper ──────────────────────────────────────────────
# Chrome spawns NM hosts with a stripped PATH — /usr/bin/env python3 may fail.
# The wrapper hardcodes the Python interpreter path found at install time.

echo "[2/5] Creating run_host.sh wrapper..."
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

# ── Step 3: Write manifest JSON ───────────────────────────────────────────────

echo "[3/5] Writing manifest..."
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

# ── Step 4: Install manifest (needs sudo) ─────────────────────────────────────

echo "[4/5] Installing manifest to $SYSTEM_MANIFEST_DIR/$HOST_NAME.json"
echo "      This requires sudo (system-level path, root-owned)."

sudo mkdir -p "$SYSTEM_MANIFEST_DIR"
sudo cp "$TMP_MANIFEST" "$SYSTEM_MANIFEST_DIR/$HOST_NAME.json"
sudo chmod 644 "$SYSTEM_MANIFEST_DIR/$HOST_NAME.json"
rm "$TMP_MANIFEST"

echo ""
echo "Done. To verify:"
echo "  cat $SYSTEM_MANIFEST_DIR/$HOST_NAME.json"
echo ""
echo "Next:"
echo "  1. Start the desktop app:  python $SCRIPT_DIR/../desktop_app/securevault_app.py"
echo "  2. Open Chrome, click the SecureVault extension popup"
echo "  3. Click 'Get Secret' — should return the vault token"
