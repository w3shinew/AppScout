// ================= CAPABILITY DETECTION =================

const findings = [];

if ("mediaDevices" in navigator) {
  findings.push("Camera / Microphone APIs available");
}

if ("geolocation" in navigator) {
  findings.push("Location API available");
}

if ("clipboard" in navigator) {
  findings.push("Clipboard API available");
}

if ("usb" in navigator) {
  findings.push("USB device API available");
}

if ("bluetooth" in navigator) {
  findings.push("Bluetooth API available");
}

if ("hid" in navigator) {
  findings.push("HID device API available");
}

chrome.runtime.sendMessage({
  type: "CAPABILITIES_DETECTED",
  findings
});

// ================= CLIPBOARD MONITORING =================

let clipboardMonitorEnabled = true;

// Get clipboard monitor status
chrome.runtime.sendMessage({ type: "GET_CLIPBOARD_STATUS" }, (response) => {
  if (response) {
    clipboardMonitorEnabled = response.enabled;
  }
});

// Monitor copy events
document.addEventListener('copy', async (e) => {
  if (!clipboardMonitorEnabled) return;
  
  try {
    // Small delay to ensure clipboard is populated
    setTimeout(async () => {
      try {
        const text = await navigator.clipboard.readText();
        
        if (text && text.length > 10) {
          // Send to background for analysis
          chrome.runtime.sendMessage({
            type: "CHECK_CLIPBOARD",
            content: text
          }, (response) => {
            if (response && response.malicious) {
              // Show immediate warning overlay
              showThreatWarning(response.threats);
            }
          });
        }
      } catch (err) {
        // Clipboard read might fail due to permissions
        console.log("Clipboard read failed:", err);
      }
    }, 100);
  } catch (err) {
    console.error("Clipboard monitoring error:", err);
  }
});

// Show threat warning overlay
function showThreatWarning(threats) {
  // Create warning overlay
  const overlay = document.createElement('div');
  overlay.id = 'appscout-threat-warning';
  overlay.innerHTML = `
    <div style="
      position: fixed;
      top: 20px;
      right: 20px;
      background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
      color: white;
      padding: 20px;
      border-radius: 12px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.3);
      z-index: 999999;
      max-width: 400px;
      font-family: system-ui, -apple-system, sans-serif;
      animation: slideIn 0.3s ease-out;
    ">
      <div style="display: flex; align-items: center; margin-bottom: 12px;">
        <span style="font-size: 24px; margin-right: 10px;">⚠️</span>
        <strong style="font-size: 18px;">Malicious Command Detected!</strong>
      </div>
      <div style="font-size: 14px; margin-bottom: 12px; line-height: 1.5;">
        <strong>${threats[0].threat}</strong><br>
        <span style="opacity: 0.9;">DO NOT paste this into your terminal or command prompt!</span>
      </div>
      <div style="display: flex; gap: 10px;">
        <button id="appscout-clear-clipboard" style="
          flex: 1;
          background: white;
          color: #ef4444;
          border: none;
          padding: 10px;
          border-radius: 6px;
          font-weight: bold;
          cursor: pointer;
          font-size: 13px;
        ">🗑️ Clear Clipboard</button>
        <button id="appscout-dismiss" style="
          flex: 1;
          background: rgba(255,255,255,0.2);
          color: white;
          border: 1px solid rgba(255,255,255,0.3);
          padding: 10px;
          border-radius: 6px;
          font-weight: bold;
          cursor: pointer;
          font-size: 13px;
        ">Dismiss</button>
      </div>
    </div>
  `;
  
  // Add animation
  const style = document.createElement('style');
  style.textContent = `
    @keyframes slideIn {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
  `;
  document.head.appendChild(style);
  
  document.body.appendChild(overlay);
  
  // Clear clipboard button
  document.getElementById('appscout-clear-clipboard').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText('');
      overlay.remove();
    } catch (err) {
      console.error('Failed to clear clipboard:', err);
    }
  });
  
  // Dismiss button
  document.getElementById('appscout-dismiss').addEventListener('click', () => {
    overlay.remove();
  });
  
  // Auto-dismiss after 10 seconds
  setTimeout(() => {
    if (overlay.parentNode) {
      overlay.remove();
    }
  }, 10000);
}

// Listen for clipboard monitor toggle
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "CLIPBOARD_MONITOR_TOGGLED") {
    clipboardMonitorEnabled = msg.enabled;
  }
});
