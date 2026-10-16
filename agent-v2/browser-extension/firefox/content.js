// Best-effort in-page guard. Not a guaranteed web DLP barrier.
// Check the file input at CAPTURE phase. Preloaded rules make decisions synchronous.
(() => {
  let rules = [];
  let lastSync = 0;
  const MAX_AGE_MS = 120000;
  const ext = file => {
    const name = String(file.name || "");
    const i = name.lastIndexOf(".");
    return i < 0 ? "" : name.slice(i + 1).toLowerCase();
  };
  function decision(file) {
    const extension = ext(file);
    // Fail open when policy is unavailable: avoid blocking normal browsing silently.
    if (!lastSync || Date.now() - lastSync > MAX_AGE_MS) return null;
    const matched = rules.filter(r => Array.isArray(r.extensions) && r.extensions.includes(extension));
    return matched.find(r => r.action === "BLOCK") || matched[0] || null;
  }
  function refresh() {
    try {
      browser.runtime.sendMessage({type: "GET_WEB_RULES"}).then(response => {
        if (!response) { lastSync = 0; return; }
        rules = Array.isArray(response.webRules) ? response.webRules : [];
        lastSync = response.lastSync || 0;
      }).catch(() => { lastSync = 0; });
    } catch (_) { lastSync = 0; }
  }
  refresh();
  setInterval(refresh, 15000);
  function block(files) { return Array.from(files || []).some(f => decision(f)?.action === "BLOCK"); }
  function announce() { console.warn("[DLP] File Type blocked by NETWORK_WEB policy"); window.alert("DLP policy: file upload blocked"); }
  document.addEventListener("change", e => {
    const el = e.target;
    if (!(el instanceof HTMLInputElement) || el.type !== "file" || !el.files) return;
    if (block(el.files)) {
      e.preventDefault(); e.stopImmediatePropagation();
      el.value = "";
      announce();
    }
  }, true);
  // Also block drop events with files before the website's drop handler.
  document.addEventListener("drop", e => {
    if (!e.dataTransfer?.files?.length || !block(e.dataTransfer.files)) return;
    e.preventDefault(); e.stopImmediatePropagation(); announce();
  }, true);
  // A final check for ordinary HTML form submit; this does not intercept fetch/XHR.
  document.addEventListener("submit", e => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    for (const input of form.querySelectorAll('input[type="file"]')) {
      if (input.files && block(input.files)) {
        e.preventDefault(); e.stopImmediatePropagation(); announce(); return;
      }
    }
  }, true);
})();
