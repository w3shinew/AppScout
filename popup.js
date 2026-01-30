let detectedCapabilities = [];
let currentOrigin = "";
let currentTab = null;

/* ================= CAPABILITIES ================= */

chrome.runtime.onMessage.addListener(msg => {
  if (msg.type === "CAPABILITIES_DETECTED") {
    detectedCapabilities = msg.findings;

    const list = document.getElementById("capabilities");
    list.innerHTML = "";

    if (detectedCapabilities.length === 0) {
      const li = document.createElement("li");
      li.textContent = "No sensitive APIs detected";
      li.className = "low";
      list.appendChild(li);
    } else {
      detectedCapabilities.forEach(cap => {
        const li = document.createElement("li");
        li.textContent = "⚡ " + cap;
        list.appendChild(li);
      });
    }
  }
});

/* ================= PERMISSIONS MODEL ================= */

const PERMISSIONS = {
  automaticDownloads: {
    label: "Automatic Downloads",
    risk: 7,
    recommend: "block"
  },
  backgroundSync: {
    label: "Background Sync",
    risk: 6,
    recommend: "block"
  },
  usbDevices: {
    label: "USB Devices",
    risk: 9,
    recommend: "block"
  },
  popups: {
    label: "Pop-ups",
    risk: 4,
    recommend: "block"
  },
  cookies: {
    label: "Cookies",
    risk: 3,
    recommend: "allow"
  },
  javascript: {
    label: "JavaScript",
    risk: 1,
    recommend: "allow"
  }
};

const ADVISORIES = [
  "⚠️ Automatic downloads can silently drop malware",
  "⚠️ Background sync allows data transfer after tab close",
  "⚠️ USB access may expose physical devices",
  "⚠️ Pop-ups are commonly abused for phishing",
  "⚠️ Cookies enable cross-site tracking",
  "🛡️ ClickFix attacks trick users into running malicious commands",
  "🛡️ Never paste commands from untrusted websites into your terminal",
  "🛡️ Clipboard monitoring helps detect malicious PowerShell/bash commands"
];

/* ================= CLIPBOARD MONITOR TOGGLE ================= */

const clipboardToggle = document.getElementById("clipboard-toggle");

// Load clipboard monitor status
chrome.runtime.sendMessage({ type: "GET_CLIPBOARD_STATUS" }, (response) => {
  if (response) {
    clipboardToggle.checked = response.enabled;
  }
});

clipboardToggle.addEventListener("change", (e) => {
  const enabled = e.target.checked;
  chrome.runtime.sendMessage({
    type: "TOGGLE_CLIPBOARD_MONITOR",
    enabled: enabled
  }, (response) => {
    if (response && response.success) {
      // Notify all tabs
      chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
          chrome.tabs.sendMessage(tab.id, {
            type: "CLIPBOARD_MONITOR_TOGGLED",
            enabled: enabled
          }).catch(() => {}); // Ignore errors for tabs that can't receive messages
        });
      });
    }
  });
});

/* ================= THREAT HISTORY ================= */

function loadThreatHistory() {
  chrome.runtime.sendMessage({ type: "GET_THREAT_HISTORY" }, (response) => {
    if (response && response.history) {
      const threatList = document.getElementById("threat-list");
      const threatCount = document.getElementById("threat-count");
      
      threatCount.textContent = response.history.length;
      threatList.innerHTML = "";
      
      if (response.history.length === 0) {
        const li = document.createElement("li");
        li.textContent = "✅ No threats detected";
        li.className = "low";
        threatList.appendChild(li);
      } else {
        response.history.slice(0, 5).forEach(entry => {
          const li = document.createElement("li");
          const time = new Date(entry.timestamp).toLocaleTimeString();
          li.innerHTML = `<strong>${time}</strong> - ${entry.threats[0].threat}`;
          li.className = entry.threats[0].severity === "critical" ? "high" : "medium";
          threatList.appendChild(li);
        });
      }
    }
  });
}

// Clear threat history
document.getElementById("clear-threats-btn").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "CLEAR_THREAT_HISTORY" }, () => {
    loadThreatHistory();
  });
});

// Load threat history on popup open
loadThreatHistory();

/* ================= BLOCK ALL BUTTON ================= */

document.getElementById("block-all-btn").addEventListener("click", () => {
  if (!currentOrigin) return;
  
  let blockedCount = 0;
  Object.entries(PERMISSIONS).forEach(([perm, meta]) => {
    if (meta.recommend === "block") {
      const api = chrome.contentSettings[perm];
      if (api) {
        api.set({
          primaryPattern: currentOrigin + "/*",
          setting: "block"
        }, () => {
          blockedCount++;
          if (blockedCount === Object.values(PERMISSIONS).filter(m => m.recommend === "block").length) {
            // Reload the analysis
            location.reload();
          }
        });
      }
    }
  });
});

/* ================= SITE ANALYSIS ================= */

chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  currentTab = tab;
  
  if (!tab?.url || tab.url.startsWith("chrome://") || tab.url.startsWith("edge://")) {
    document.getElementById("site").innerText = "Unsupported page";
    document.getElementById("block-all-btn").disabled = true;
    return;
  }

  const url = new URL(tab.url);
  const origin = url.origin;
  currentOrigin = origin;

  document.getElementById("site").innerText = `Site: ${url.hostname}`;

  const settingsList = document.getElementById("settings");
  const adviceList = document.getElementById("advice");
  const scoreEl = document.getElementById("score");

  let totalRisk = 0;
  let processed = 0;
  const total = Object.keys(PERMISSIONS).length;

  Object.entries(PERMISSIONS).forEach(([perm, meta]) => {
    const api = chrome.contentSettings[perm];

    if (!api) {
      processed++;
      return;
    }

    api.get({ primaryUrl: origin }, details => {
      const setting = details.setting;
      const source = details.source === "preference" ? "site override" : "default";

      let icon = "✅";
      let suggestion = "";
      let actionButton = "";

      if (
        (setting === "allow" && meta.recommend === "block") ||
        (setting === "ask" && meta.recommend === "block")
      ) {
        icon = setting === "allow" ? "🚨" : "⚠";
        totalRisk += setting === "allow" ? meta.risk : Math.floor(meta.risk / 2);
        suggestion = " → Recommended: BLOCK";

        // Add one-click block button
        const buttonId = `block-${perm}`;
        actionButton = ` <button class="modify-btn" id="${buttonId}">🛡️ Block</button>`;
      }

      const li = document.createElement("li");
      li.innerHTML = `${icon} ${meta.label}: <strong>${setting}</strong> (${source})${suggestion}${actionButton}`;
      li.className = icon === "🚨" ? "high" : icon === "⚠" ? "medium" : "low";

      settingsList.appendChild(li);

      // Add click handler for block button
      if (actionButton) {
        setTimeout(() => {
          const btn = document.getElementById(`block-${perm}`);
          if (btn) {
            btn.addEventListener("click", () => {
              blockPermission(perm, meta.label, btn, li);
            });
          }
        }, 0);
      }

      processed++;

      if (processed === total) {
        ADVISORIES.forEach(text => {
          const li = document.createElement("li");
          li.textContent = text;
          adviceList.appendChild(li);
        });

        scoreEl.textContent = `Total Exposure Score: ${totalRisk}`;
        scoreEl.className =
          totalRisk >= 15 ? "high" :
          totalRisk >= 7 ? "medium" : "low";
      }
    });
  });
});

/* ================= ONE-CLICK BLOCK FUNCTION ================= */

function blockPermission(permission, label, button, listItem) {
  const api = chrome.contentSettings[permission];
  
  if (!api || !currentOrigin) return;
  
  // Block the permission
  api.set({
    primaryPattern: currentOrigin + "/*",
    setting: "block"
  }, () => {
    // Update UI
    button.textContent = "✅ Blocked";
    button.disabled = true;
    button.className = "modify-btn blocked";
    
    // Update list item
    listItem.innerHTML = `✅ ${label}: <strong>block</strong> (site override) <button class="modify-btn blocked" disabled>✅ Blocked</button>`;
    listItem.className = "low";
    
    // Recalculate score
    setTimeout(() => {
      location.reload();
    }, 500);
  });
}
