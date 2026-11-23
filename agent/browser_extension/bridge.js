// Nhan yeu cau quet tu detached-guard.js (trang) va chuyen cho background.js.
(() => {
  window.addEventListener("dlp-lab-inspect", e => {
    const d = e.detail || {};
    // DOM messages can come from the page. Relay only validated fields.
    const {id, name, content_base64, destination} = d;
    if (typeof id !== "string" || !/^\d{1,10}(?:-\d{1,10}){3}$/.test(id)) return;
    const reply = ({decision, reason}) => window.dispatchEvent(new CustomEvent("dlp-lab-verdict", {
      detail: {id, decision, reason}
    }));
    if (typeof name !== "string" || !name || name.length > 240 ||
        typeof content_base64 !== "string" || content_base64.length > 2800000 ||
        (destination !== undefined && (typeof destination !== "string" || destination.length > 512))) {
      return reply({decision: "BLOCK", reason: "INVALID_INSPECTION_REQUEST"});
    }
    try {
      const type = destination === undefined ? "INSPECT_FILE_CONTENT" : "INSPECT_FETCH_FILE_CONTENT";
      chrome.runtime.sendMessage({type, name, content_base64, destination}, result => {
        if (chrome.runtime.lastError || !result) return reply({decision: "BLOCK", reason: "AGENT_UNAVAILABLE"});
        reply({decision: result.decision, reason: result.reason});
      });
    } catch (_) { reply({decision: "BLOCK", reason: "AGENT_UNAVAILABLE"}); }
  });
})();
