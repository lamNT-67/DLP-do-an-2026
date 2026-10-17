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
  if (msg?.type === "REPORT_BROWSER_BLOCK") {
    (async () => {
      // Only relay from a content script injected by this extension in a web tab.
      // The Agent independently validates the policy, extension and filename.
      const url = sender?.url || "";
      if (!/^https?:\\/\\//.test(url) || !sender.tab ||
          !Number.isInteger(msg.policy_id) ||
          typeof msg.file_name !== "string" || msg.file_name.length > 240) {
        sendResponse({ok: false, error: "invalid sender/event"});
        return;
      }
      const {webRules, lastSync} = await chrome.storage.local.get(["webRules", "lastSync"]);
      const ext = msg.file_name.split(".").pop().toLowerCase();
      if (!lastSync || Date.now() - lastSync > 120000 ||
          !webRules?.some(p => p.policy_id === msg.policy_id &&
            p.action === "BLOCK" && p.extensions?.includes(ext))) {
        sendResponse({ok: false, error: "policy mismatch"});
        return;
      }
      try {
        const destination = new URL(url).origin.slice(0, 255);
        const response = await fetch("http://127.0.0.1:18765/event", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({
            channel: browserChannel,
            policy_id: msg.policy_id,
            file_name: msg.file_name,
            destination
          })
        });
        sendResponse({ok: response.status === 202, status: response.status});
      } catch (error) {
        console.warn("[DLP] Cannot contact Agent event bridge", error);
        sendResponse({ok: false, error: String(error)});
      }
    })().catch(error => sendResponse({ok: false, error: String(error)}));
    return true;
  }
});
sync();
