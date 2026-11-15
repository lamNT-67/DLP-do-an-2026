// Nhan yeu cau quet tu detached-guard.js (trang) va chuyen cho background.js.
(() => {
  window.addEventListener("dlp-lab-inspect", e => {
    const d = e.detail || {};
    const reply = r => window.dispatchEvent(new CustomEvent("dlp-lab-verdict", {detail: Object.assign({id: d.id}, r)}));
    try {
      chrome.runtime.sendMessage({type: "INSPECT_FILE_CONTENT", name: String(d.name || ""),
        content_base64: String(d.content_base64 || "")}, result => {
        if (chrome.runtime.lastError || !result) return reply({decision: "BLOCK", reason: "AGENT_UNAVAILABLE"});
        reply({decision: result.decision, reason: result.reason});
      });
    } catch (_) { reply({decision: "BLOCK", reason: "AGENT_UNAVAILABLE"}); }
  });
})();