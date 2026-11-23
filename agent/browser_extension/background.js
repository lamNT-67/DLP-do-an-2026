// Chrome MV3 extension: get a reduced, read-only policy from the local Agent.
const BRIDGE = "http://127.0.0.1:18765/rules";
const browserChannel = /Edg\//.test(navigator.userAgent) ? "edge" : "chrome";
const pickerApprovals = new Map();
const PICKER_APPROVAL_MS = 3000;
const MAX_PICKER_APPROVALS = 32;

async function approvalKey(sender, destination, msg) {
  if (!sender.documentId) return null;
  try {
    const bytes = new TextEncoder().encode(msg.content_base64);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    return JSON.stringify([sender.tab.id, sender.frameId, sender.documentId, destination, msg.name,
      Array.from(digest).join(",")]);
  } catch (_) { return null; }
}

function fetchDestination(value) {
  if (typeof value !== "string" || value.length > 512) return null;
  try {
    const target = new URL(value);
    return ["http:", "https:"].includes(target.protocol) && target.origin === value ? target.origin : null;
  } catch (_) { return null; }
}

async function sync() {
  try {
    const resp = await fetch(BRIDGE, {cache: "no-store"});
    if (!resp.ok) throw new Error("Agent HTTP " + resp.status);
    const data = await resp.json();
    if (!data.updated || !Array.isArray(data[browserChannel])) throw new Error("Policy not ready");
    await chrome.storage.local.set({webRules: data[browserChannel], lastSync: Date.now()});
  } catch (err) {
    // Never treat an inaccessible/unknown policy as a permissive empty policy.
    pickerApprovals.clear();
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
  if (msg?.type === "INSPECT_FILE_CONTENT" || msg?.type === "INSPECT_FETCH_FILE_CONTENT") {
    (async () => {
      const url = sender?.url || "";
      if ((!url.startsWith("http://") && !url.startsWith("https://")) ||
          !sender.tab || typeof msg.name !== "string" || !msg.name || msg.name.length > 240 ||
          typeof msg.content_base64 !== "string" || msg.content_base64.length > 2800000) {
        sendResponse({decision: "BLOCK", reason: "INVALID_INSPECTION_REQUEST"});
        return;
      }
      try {
        const fetchUpload = msg.type === "INSPECT_FETCH_FILE_CONTENT";
        const initiator = new URL(url).origin;
        let destination = initiator;
        if (fetchUpload) {
          // A MAIN-world claim is only a hint about the initial target. The
          // sender's frame URL comes from Chrome and is the only trusted origin.
          destination = fetchDestination(msg.destination);
          if (!destination) {
            sendResponse({decision: "BLOCK", reason: "INVALID_INSPECTION_DESTINATION"});
            return;
          }
        }
        // Same-document, same-origin picker approvals are short-lived and single-use.
        // Only a real agent verdict can seed this cache, even for DOM-originated requests.
        const key = destination === initiator ? await approvalKey(sender, destination, msg) : null;
        if (fetchUpload && key && pickerApprovals.has(key)) {
          const approval = pickerApprovals.get(key);
          pickerApprovals.delete(key);
          if (approval.expires > Date.now()) { sendResponse(approval.verdict); return; }
        }
        if (!fetchUpload && key) pickerApprovals.delete(key);
        const headers = {"Content-Type": "application/json", "X-DLP-Client": "BrowserContent"};
        // Keep the hint out of the policy destination field, including with older agents.
        if (!fetchUpload) headers["X-DLP-Destination"] = initiator.slice(0, 255);
        const response = await fetch("http://127.0.0.1:18765/inspect-content", {
          method: "POST",
          headers,
          body: JSON.stringify({
            channel: browserChannel,
            file_name: msg.name,
            content_base64: msg.content_base64,
            initial_destination_hint: fetchUpload ? destination.slice(0, 255) : undefined
          })
        });
        if (!response.ok) throw new Error("Agent HTTP " + response.status);
        const result = await response.json();
        if (!["ALLOW", "BLOCK", "REPORT_ONLY"].includes(result.decision))
          throw new Error("Unknown inspection verdict");
        if (!fetchUpload && key && result.reusable_for_page_fetch === true && result.decision !== "BLOCK") {
          pickerApprovals.delete(key);
          pickerApprovals.set(key, {verdict: result, expires: Date.now() + PICKER_APPROVAL_MS});
          if (pickerApprovals.size > MAX_PICKER_APPROVALS) pickerApprovals.delete(pickerApprovals.keys().next().value);
        }
        sendResponse(result);
      } catch (error) {
        console.warn("[DLP] Content inspection unavailable:", error);
        sendResponse({decision: "BLOCK", reason: "INSPECTION_UNAVAILABLE"});
      }
    })().catch(error => sendResponse({decision: "BLOCK", reason: String(error)}));
    return true;
  }
  if (msg?.type === "REPORT_BROWSER_BLOCK") {
    (async () => {
      // Only relay from a content script injected by this extension in a web tab.
      // The Agent independently validates the policy, extension and filename.
      const url = sender?.url || "";
      if (!(url.startsWith("http://") || url.startsWith("https://")) || !sender.tab ||
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
