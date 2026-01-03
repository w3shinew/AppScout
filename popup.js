let detectedCapabilities = [];

/* ================= CAPABILITIES ================= */

chrome.runtime.onMessage.addListener(msg => {
  if (msg.type === "CAPABILITIES_DETECTED") {
    detectedCapabilities = msg.findings;

    const list = document.getElementById("capabilities");
    list.innerHTML = "";

    detectedCapabilities.forEach(cap => {
      const li = document.createElement("li");
      li.textContent = "⚡ " + cap;
      list.appendChild(li);
    });
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
  "Automatic downloads can silently drop malware",
  "Background sync allows data transfer after tab close",
  "USB access may expose physical devices",
  "Pop-ups are commonly abused for phishing",
  "Cookies enable cross-site tracking"
];

/* ================= SITE ANALYSIS ================= */

chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  if (!tab?.url || tab.url.startsWith("chrome://")) {
    document.getElementById("site").innerText = "Unsupported page";
    return;
  }

  const url = new URL(tab.url);
  const origin = url.origin;

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
      let manageLink = "";

      if (
        (setting === "allow" && meta.recommend === "block") ||
        (setting === "ask" && meta.recommend === "block")
      ) {
        icon = setting === "allow" ? "🚨" : "⚠";
        totalRisk += setting === "allow" ? meta.risk : Math.floor(meta.risk / 2);
        suggestion = " → Recommended: BLOCK";

        const encoded = encodeURIComponent(origin);
        manageLink = ` [<a href="chrome://settings/content/siteDetails?site=${encoded}" target="_blank">Manage</a>]`;
      }

      const li = document.createElement("li");
      li.innerHTML = `${icon} ${meta.label}: ${setting} (${source})${suggestion}${manageLink}`;
      li.className = icon === "🚨" ? "high" : icon === "⚠" ? "medium" : "low";

      settingsList.appendChild(li);
      processed++;

      if (processed === total) {
        ADVISORIES.forEach(text => {
          const li = document.createElement("li");
          li.textContent = "ℹ " + text;
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
