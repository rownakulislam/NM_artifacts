// background.js — service worker
// Handles native messaging on behalf of the popup.

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'get_secret') {
    handleGetSecret(sendResponse);
    return true;
  }
  if (message.action === 'get_version') {
    handleGetVersion(sendResponse);
    return true;
  }
});

function handleGetSecret(sendResponse) {
  let port;
  try {
    port = chrome.runtime.connectNative('com.demo.securevault');
  } catch (e) {
    sendResponse({ success: false, error: 'Failed to connect to native host: ' + e.message });
    return;
  }

  let responded = false;

  port.postMessage({ action: 'get_secret' });

  port.onMessage.addListener((msg) => {
    if (msg.secret !== undefined) {
      responded = true;
      sendResponse({ success: true, secret: msg.secret });
      port.disconnect();
    } else if (msg.error) {
      responded = true;
      sendResponse({ success: false, error: msg.error });
      port.disconnect();
    }
  });

  port.onDisconnect.addListener(() => {
    if (!responded) {
      const err = chrome.runtime.lastError
        ? chrome.runtime.lastError.message
        : 'Host disconnected unexpectedly';
      sendResponse({ success: false, error: err });
    }
  });
}

function handleGetVersion(sendResponse) {
  let port;
  try {
    port = chrome.runtime.connectNative('com.demo.securevault');
  } catch (e) {
    sendResponse({ success: false, error: e.message });
    return;
  }

  let responded = false;

  port.postMessage({ action: 'get_version' });

  port.onMessage.addListener((msg) => {
    if (msg.version !== undefined) {
      responded = true;
      sendResponse({ success: true, version: msg.version });
      port.disconnect();
    } else if (msg.error) {
      responded = true;
      sendResponse({ success: false, error: msg.error });
      port.disconnect();
    }
  });

  port.onDisconnect.addListener(() => {
    if (!responded) {
      sendResponse({ success: false, error: chrome.runtime.lastError?.message || 'disconnected' });
    }
  });
}
