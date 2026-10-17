// Chrome MV3 extension: get a reduced, read-only policy from the local Agent.
const BRIDGE = "http://127.0.0.1:18765/rules";
const browserChannel = /Edg\//.test(navigator.userAgent) ? "edge" : "chrome";
async function sync() {
  try {
    const resp = await fetch(BRIDGE, {cache: "no-store"});
    if (!resp.ok) throw new Error("Agent HTTP " + resp.status);
    const data = await resp.json();
    if (!data.updated || !Array.isArray(data[browserChannel])) throw new Error("Policy not ready");
    await chrome.storage.local.set({webRules: data[browserChannel], lastSync: Date.now()});
  } catch (err) {
    // Never treat an inaccessible/unknown policy as a permissive empty policy.
    await chrome.storage.local.set({lastSync: 0});
    console.warn("DLP Agent policy unavailable:", err);
  }
}
chrome.runtime.onInstalled.addListener(() => { sync(); chrome.alarms.create("dlp-sync", {periodInMinutes: 0.5}); });
chrome.runtime.onStartup.addListener(() => { sync(); chrome.alarms.create("dlp-sync", {periodInMinutes: 0.5}); });
chrome.alarms.onAlarm.addListener(a => { if (a.name === "dlp-sync") sync(); });
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "GET_WEB_RULES") {
    chrome.storage.local.get(["webRules", "lastSync"]).then(sendResponse);
    return true;
  }
});
sync();
