// Best-effort file selection/drop/paste guard. Not a kernel or network security boundary.
(() => {
  if (window.__dlpPythonUploadGuard) return;
  window.__dlpPythonUploadGuard = true;

  const MAX_BYTES = 2 * 1024 * 1024;
  const busy = new WeakSet();
  const replayed = new WeakSet();

  const notice = (name, reason) => {
    console.warn("[DLP] File upload blocked:", name, reason);
    alert("DLP: Upload blocked (" + (reason || "policy") + ")");
  };

  function inspect(file) {
    if (!file || file.size > MAX_BYTES) {
      // Large file is not silently allowed without being scanned.
      return Promise.resolve({decision: "BLOCK", reason: "FILE_TOO_LARGE"});
    }
    return new Promise(resolve => {
      const reader = new FileReader();
      reader.onerror = () => resolve({decision: "BLOCK", reason: "READ_FAILED"});
      reader.onload = () => {
        const base64 = String(reader.result || "").split(",")[1] || "";
        if (!base64) return resolve({decision: "BLOCK", reason: "ENCODE_FAILED"});
        try {
          chrome.runtime.sendMessage({
            type: "DLP_INSPECT_FILE",
            name: file.name,
            content_base64: base64
          }, response => {
            if (chrome.runtime.lastError || !response) {
              resolve({decision: "BLOCK", reason: "BRIDGE_UNAVAILABLE"});
            } else {
              resolve(response);
            }
          });
        } catch (_) { resolve({decision: "BLOCK", reason: "EXTENSION_ERROR"}); }
      };
      reader.readAsDataURL(file);
    });
  }

  async function checkAll(files) {
    for (const file of files) {
      const result = await inspect(file);
      if (!["ALLOW", "REPORT_ONLY"].includes(result?.decision)) {
        return {blocked: true, file, reason: result?.reason || "INSPECTION_ERROR"};
      }
    }
    return {blocked: false};
  }

  function replaceInput(input, files) {
    try {
      const dt = new DataTransfer();
      files.forEach(file => dt.items.add(file));
      input.files = dt.files;
      replayed.add(input);
      try {
        input.dispatchEvent(new Event("input", {bubbles: true}));
        input.dispatchEvent(new Event("change", {bubbles: true}));
      } finally { replayed.delete(input); }
    } catch (e) {
      console.warn("[DLP] Cannot replay safe file selection:", e);
      notice(files[0]?.name, "UPLOAD_REPLAY_FAILED");
    }
  }

  function onInput(event) {
    const input = event.target;
    if (!(input instanceof HTMLInputElement) || input.type !== "file" ||
        !input.files?.length || replayed.has(input)) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    if (busy.has(input)) { input.value = ""; return; }
    const files = Array.from(input.files);
    // Clear synchronously so subsequent page event listeners cannot read bytes.
    input.value = "";
    busy.add(input);
    checkAll(files).then(result => {
      if (!input.isConnected) return;
      if (result.blocked) return notice(result.file.name, result.reason);
      replaceInput(input, files);
    }).catch(() => notice(files[0]?.name, "INSPECTION_ERROR"))
      .finally(() => busy.delete(input));
  }
  document.addEventListener("input", onInput, true);
  document.addEventListener("change", onInput, true);

  async function onTransfer(event) {
    if (replayed.has(event)) return;
    const files = Array.from(event.dataTransfer?.files || event.clipboardData?.files || []);
    if (!files.length) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    const target = event.target;
    const kind = event.type;
    const result = await checkAll(files);
    if (result.blocked) return notice(result.file.name, result.reason);
    if (!target?.isConnected) return;
    try {
      const dt = new DataTransfer();
      files.forEach(file => dt.items.add(file));
      const synthetic = kind === "drop"
        ? new DragEvent("drop", {bubbles: true, cancelable: true, dataTransfer: dt})
        : new ClipboardEvent("paste", {bubbles: true, cancelable: true, clipboardData: dt});
      replayed.add(synthetic);
      target.dispatchEvent(synthetic);
    } catch (e) {
      console.warn("[DLP] Cannot replay safe drop/paste:", e);
    }
  }
  document.addEventListener("drop", e => { void onTransfer(e); }, true);
  document.addEventListener("paste", e => { void onTransfer(e); }, true);
})();
