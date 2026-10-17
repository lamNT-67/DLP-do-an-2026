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
      chrome.runtime.sendMessage({type: "GET_WEB_RULES"}, response => {
        if (chrome.runtime.lastError || !response) { lastSync = 0; return; }
        rules = Array.isArray(response.webRules) ? response.webRules : [];
        lastSync = response.lastSync || 0;
        window.dispatchEvent(new CustomEvent("dlp-lab-rules", {
          detail: {rules, updatedAt: lastSync}
        }));
      });
    } catch (_) { lastSync = 0; }
  }
  refresh();
  setInterval(refresh, 15000);
  const sent = new Map();
  function report(file, policyId) {
    const name = String(file?.name || "").slice(0, 240);
    if (!name || !Number.isInteger(policyId)) return;
    const key = policyId + "|" + name + "|" + location.origin;
    const now = Date.now();
    if (now - (sent.get(key) || 0) < 3000) return;
    sent.set(key, now);
    if (sent.size > 100) {
      for (const [k, t] of sent) if (now - t > 10000) sent.delete(k);
    }
    try {
      chrome.runtime.sendMessage({
        type: "REPORT_BROWSER_BLOCK",
        policy_id: policyId,
        file_name: name,
        destination: location.origin
      }, reply => {
        if (chrome.runtime.lastError || !reply?.ok)
          console.warn("[DLP] Could not report block to Agent", chrome.runtime.lastError?.message, reply);
      });
    } catch (error) { console.warn("[DLP] Event report failed", error); }
  }
  function blocked(files) {
    const matched = Array.from(files || []).map(f => ({file: f, rule: decision(f)}))
      .filter(x => x.rule?.action === "BLOCK");
    for (const hit of matched) report(hit.file, hit.rule.policy_id);
    return matched.length > 0;
  }
  window.addEventListener("dlp-lab-blocked", e => {
    const name = String(e.detail?.name || "");
    const policyId = Number(e.detail?.policy_id);
    if (!name || !Number.isInteger(policyId)) return;
    const extension = name.includes(".") ? name.slice(name.lastIndexOf(".") + 1).toLowerCase() : "";
    if (!rules.some(r => r.action === "BLOCK" && r.policy_id === policyId && r.extensions?.includes(extension))) return;
    report({name}, policyId);
  });
  function announce() { console.warn("[DLP] File Type blocked by NETWORK_WEB policy"); window.alert("DLP policy: file upload blocked"); }
  // A file-picker change is cancellable only at DOM propagation level;
  // clearing the input prevents ordinary forms and handlers from obtaining the file.
  document.addEventListener("change", e => {
    const el = e.target;
    if (!(el instanceof HTMLInputElement) || el.type !== "file" || !el.files) return;
    if (blocked(el.files)) {
      e.preventDefault(); e.stopImmediatePropagation();
      el.value = "";
      announce();
    }
  }, true);
  document.addEventListener("input", e => {
    const el = e.target;
    if (el instanceof HTMLInputElement && el.type === "file" && el.files && blocked(el.files)) {
      e.preventDefault(); e.stopImmediatePropagation(); el.value = ""; announce();
    }
  }, true);
  // Also block drop events with files before the website's drop handler.
  document.addEventListener("drop", e => {
    if (!e.dataTransfer?.files?.length || !blocked(e.dataTransfer.files)) return;
    e.preventDefault(); e.stopImmediatePropagation(); announce();
  }, true);
  document.addEventListener("paste", e => {
    if (!e.clipboardData?.files?.length || !blocked(e.clipboardData.files)) return;
    e.preventDefault(); e.stopImmediatePropagation(); announce();
  }, true);
  // A final check for ordinary HTML form submit.
  document.addEventListener("submit", e => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    for (const input of form.querySelectorAll('input[type="file"]')) {
      if (input.files && blocked(input.files)) {
        e.preventDefault(); e.stopImmediatePropagation(); announce(); return;
      }
    }
  }, true);
})();
