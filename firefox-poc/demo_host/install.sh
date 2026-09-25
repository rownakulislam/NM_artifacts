#!/bin/bash
# install.sh — set up SecureVault NM host (system-level manifest) for Firefox
#
# What this does:
#   1. Seeds the Keychain with the demo secret
#   2. Creates a shell wrapper so Firefox can find the Python interpreter
#   3. Installs the NM manifest to /Library/Application Support/Mozilla/NativeMessagingHosts/
#      (system-level — requires sudo for the copy step)
#
# Usage:
#   bash install.sh
#
# Firefox uses allowed_extensions with the gecko ID from the extension manifest.
# The ID is the fixed string "securevault@demo" — no key derivation needed.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

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
SYSTEM_MANIFEST_DIR="/Library/Application Support/Mozilla/NativeMessagingHosts"
HOST_NAME="com.demo.securevault"

# Extension ID is the gecko ID string from demo_extension/manifest.json.
# No key derivation — Firefox uses the declared gecko.id directly.
GECKO_ID="securevault@demo"

# ── Step 1: Install geckodriver ───────────────────────────────────────────────
# Required by attacks 1 and 3 to load extensions into headless Firefox.

echo "[1/6] Installing geckodriver..."
if command -v geckodriver &>/dev/null; then
  echo "      OK — geckodriver already installed ($(geckodriver --version 2>&1 | head -1))"
elif command -v brew &>/dev/null; then
  brew install geckodriver \
    && echo "      OK — geckodriver installed via Homebrew" \
    || echo "      WARN — brew install geckodriver failed; install manually"
else
  echo "      WARN — Homebrew not found; install geckodriver manually: https://github.com/mozilla/geckodriver/releases"
fi

# ── Step 2: Seed Keychain ─────────────────────────────────────────────────────

echo "[2/6] Seeding Keychain..."
security add-generic-password \
  -s "$HOST_NAME" \
  -a "demo" \
  -w "vault_token_eyJhbGciOiJSUzI1NiJ9.demo_secret_42" \
  -U 2>/dev/null \
  && echo "      OK — secret stored in Keychain under service '$HOST_NAME'" \
  || { echo "      WARN — Keychain seed failed (may need to allow access in popup)"; }

# ── Step 2: Create shell wrapper ──────────────────────────────────────────────
# Firefox spawns NM hosts with a stripped PATH — /usr/bin/env python3 may fail.
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

# ── Step 3: Write manifest JSON ───────────────────────────────────────────────

echo "[4/6] Writing manifest..."
MANIFEST_JSON=$(cat << EOF
{
  "name": "$HOST_NAME",
  "description": "SecureVault NM host — security research demo",
  "path": "$WRAPPER",
  "type": "stdio",
  "allowed_extensions": [
    "$GECKO_ID"
  ]
}
EOF
)

TMP_MANIFEST="$(mktemp /tmp/${HOST_NAME}.json.XXXXXX)"
echo "$MANIFEST_JSON" > "$TMP_MANIFEST"
echo "      Manifest contents:"
cat "$TMP_MANIFEST" | sed 's/^/        /'

# ── Step 4: Install manifest (needs sudo) ─────────────────────────────────────

echo "[5/6] Installing manifest to $SYSTEM_MANIFEST_DIR/$HOST_NAME.json"
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
echo "  2. Open Firefox, click the SecureVault extension popup"
echo "  3. Click 'Get Secret' — should return the vault token"
