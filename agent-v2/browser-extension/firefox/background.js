// Chrome MV3 extension: get a reduced, read-only policy from the local Agent.
const BRIDGE = "http://127.0.0.1:18765/rules";
async function sync() {
  try {
    const resp = await fetch(BRIDGE, {cache: "no-store"});
    if (!resp.ok) throw new Error("Agent HTTP " + resp.status);
    const data = await resp.json();
    if (!data.updated || !Array.isArray(data.web)) throw new Error("Policy not ready");
    await browser.storage.local.set({webRules: data.web, lastSync: Date.now()});
  } catch (err) {
    // Never treat an inaccessible/unknown policy as a permissive empty policy.
    await browser.storage.local.set({lastSync: 0});
    console.warn("DLP Agent policy unavailable:", err);
  }
}
browser.runtime.onInstalled.addListener(() => { sync(); browser.alarms.create("dlp-sync", {periodInMinutes: 0.5}); });
browser.runtime.onStartup.addListener(() => { sync(); browser.alarms.create("dlp-sync", {periodInMinutes: 0.5}); });
browser.alarms.onAlarm.addListener(a => { if (a.name === "dlp-sync") sync(); });
browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "GET_WEB_RULES") {
    browser.storage.local.get(["webRules", "lastSync"]).then(sendResponse);
    return true;
  }
});
sync();
