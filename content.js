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
