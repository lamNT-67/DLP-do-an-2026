// Chrome/Edge MV3. The Python bridge is the only policy/inspection authority.
const BRIDGE = "http://127.0.0.1:18765";
const channel = /Edg\//.test(navigator.userAgent) ? "BROWSER_EDGE" : "BROWSER_CHROME";
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "DLP_INSPECT_FILE") return;
  (async () => {
    if (!sender.tab || !/^https?:\/\//.test(sender.url || "")) {
      return {decision: "BLOCK", reason: "INVALID_SENDER"};
    }
    const fileName = message.name;
    const payload = message.content_base64;
    if (typeof fileName !== "string" || !fileName || fileName.length > 240 ||
        typeof payload !== "string" || payload.length > 2800000) {
      return {decision: "BLOCK", reason: "INVALID_FILE"};
    }
    try {
      const response = await fetch(BRIDGE + "/inspect-content", {
        method: "POST",
        cache: "no-store",
        headers: {"Content-Type": "application/json", "X-DLP-Client": "BrowserExtension"},
        body: JSON.stringify({
          channel,
          file_name: fileName,
          content_base64: payload,
          too_large: message.too_large === true,
          destination: new URL(sender.url).origin
        })
      });
      if (!response.ok) throw new Error("bridge HTTP " + response.status);
      const result = await response.json();
      if (!["ALLOW", "BLOCK", "REPORT_ONLY"].includes(result.decision))
        throw new Error("invalid verdict");
      return result;
    } catch (e) {
      console.warn("[DLP] Python bridge unavailable:", e);
      // Lab fail-closed on inspection failures, not on policies with no browser rule.
      return {decision: "BLOCK", reason: "BRIDGE_UNAVAILABLE"};
    }
  })().then(sendResponse).catch(e => {
    console.warn("[DLP] inspection error", e);
    sendResponse({decision: "BLOCK", reason: "INSPECTION_ERROR"});
  });
  return true;
});
