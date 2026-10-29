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
  // A file input must be cleared synchronously before page handlers run.
  // After a positive verdict, reattach selected files and replay synthetic events.
  // This is best-effort: some sites reject synthetic/untrusted events.
  const replaying = new WeakSet();
  const pending = new WeakSet();
  const MAX_SCAN_BYTES = 2 * 1024 * 1024;
  function inspectFile(file) {
    return new Promise(resolve => {
      if (file.size > MAX_SCAN_BYTES) {
        resolve({decision: "BLOCK", reason: "FILE_TOO_LARGE"});
        return;
      }
      const reader = new FileReader();
      reader.onerror = () => resolve({decision: "BLOCK", reason: "READ_FAILED"});
      reader.onload = () => {
        const b64 = String(reader.result || "").split(",")[1];
        if (!b64) return resolve({decision: "BLOCK", reason: "ENCODING_FAILED"});
        try {
          chrome.runtime.sendMessage({
            type: "INSPECT_FILE_CONTENT",
            name: file.name,
            content_base64: b64
          }, result => {
            if (chrome.runtime.lastError || !result)
              return resolve({decision: "BLOCK", reason: "AGENT_UNAVAILABLE"});
            resolve(result);
          });
        } catch (_) { resolve({decision: "BLOCK", reason: "AGENT_UNAVAILABLE"}); }
      };
      reader.readAsDataURL(file);
    });
  }
  async function inspectAll(files) {
    for (const file of files) {
      const result = await inspectFile(file);
      if (result.decision === "BLOCK" || !["ALLOW", "REPORT_ONLY"].includes(result.decision))
        return {allowed: false, file, result};
    }
    return {allowed: true};
  }
  function announceContent(hit) {
    console.warn("[DLP] File upload denied:", hit?.file?.name, hit?.result?.reason);
    window.alert("DLP: file upload blocked (" + (hit?.result?.reason || "inspection failed") + ")");
  }
  function onFileSelection(e) {
    const el = e.target;
    if (!(el instanceof HTMLInputElement) || el.type !== "file" || !el.files?.length) return;
    if (replaying.has(el)) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    if (pending.has(el)) { el.value = ""; return; }
    const files = Array.from(el.files);
    // Clear immediately, before any website listener can access the selected bytes.
    el.value = "";
    pending.add(el);
    inspectAll(files).then(result => {
      if (!el.isConnected) return;
      if (!result.allowed) { announceContent(result); return; }
      const dt = new DataTransfer();
      for (const file of files) dt.items.add(file);
      el.files = dt.files;
      replaying.add(el);
      try {
        el.dispatchEvent(new Event("input", {bubbles: true}));
        el.dispatchEvent(new Event("change", {bubbles: true}));
      } finally { replaying.delete(el); }
    }).catch(error => {
      console.warn("[DLP] Content inspection error", error);
      window.alert("DLP: file inspection unavailable; upload refused");
    }).finally(() => pending.delete(el));
  }
  document.addEventListener("input", onFileSelection, true);
  document.addEventListener("change", onFileSelection, true);

  // Drop/paste file payloads are denied before page handlers. An allowed result
  // is replayed as a synthetic event; complex sites may ignore untrusted events.
  function onFileTransfer(e) {
    const files = Array.from(e.dataTransfer?.files || e.clipboardData?.files || []);
    if (!files.length) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    const target = e.target;
    const type = e.type;
    inspectAll(files).then(result => {
      if (!result.allowed) return announceContent(result);
      if (!target?.isConnected) return;
      try {
        const dt = new DataTransfer();
        files.forEach(file => dt.items.add(file));
        const event = type === "drop"
          ? new DragEvent("drop", {bubbles: true, cancelable: true, dataTransfer: dt})
          : new ClipboardEvent("paste", {bubbles: true, cancelable: true, clipboardData: dt});
        // Synthetic events won't pass through this guard twice.
        replayedEvents.add(event);
        target.dispatchEvent(event);
      } catch (error) { console.warn("[DLP] Cannot replay drop/paste after scan", error); }
    });
  }
  const replayedEvents = new WeakSet();
  for (const type of ["drop", "paste"]) {
    document.addEventListener(type, e => {
      if (replayedEvents.has(e)) return;
      onFileTransfer(e);
    }, true);
  }
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
