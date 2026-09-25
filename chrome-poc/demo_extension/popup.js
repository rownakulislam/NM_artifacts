const result = document.getElementById('result');

function showResult(cls, text) {
  result.className = cls;
  result.textContent = text;
  result.style.display = 'block';
}

document.getElementById('btnSecret').addEventListener('click', () => {
  showResult('loading', 'Connecting to vault...');
  chrome.runtime.sendMessage({ action: 'get_secret' }, (response) => {
    if (chrome.runtime.lastError) {
      showResult('error', 'Runtime error: ' + chrome.runtime.lastError.message);
      return;
    }
    if (response.success) {
      showResult('success', 'secret: ' + response.secret);
    } else {
      showResult('error', 'Error: ' + response.error);
    }
  });
});

document.getElementById('btnVersion').addEventListener('click', () => {
  showResult('loading', 'Querying version...');
  chrome.runtime.sendMessage({ action: 'get_version' }, (response) => {
    if (chrome.runtime.lastError) {
      showResult('error', 'Runtime error: ' + chrome.runtime.lastError.message);
      return;
    }
    if (response.success) {
      showResult('success', 'version: ' + response.version);
    } else {
      showResult('error', 'Error: ' + response.error);
    }
  });
});
