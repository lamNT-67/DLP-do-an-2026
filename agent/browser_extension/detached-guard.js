// Chan o file tao bang code, khong gan vao trang (vi du nut dinh kem cua Zalo web).
// Best-effort: MAIN world khong phai ranh gioi bao mat, trang co the lam gia ket qua.
(() => {
  if (window.__dlpDetachedGuard) return;
  Object.defineProperty(window, "__dlpDetachedGuard", {value: true});
  const MAX = 2 * 1024 * 1024;
  const INSPECTION_TIMEOUT_MS = 15000;
  const nativeAlert = window.alert.bind(window);
  const encodeBase64 = window.btoa.bind(window);
  const nativeFetch = window.fetch;
  const NativeRequest = window.Request;
  const NativeFormData = window.FormData;
  const nativeEntries = NativeFormData.prototype.entries;
  const nativeAppend = NativeFormData.prototype.append;
  const nativeFileName = Object.getOwnPropertyDescriptor(File.prototype, "name").get;
  const nativeFileSize = Object.getOwnPropertyDescriptor(Blob.prototype, "size").get;
  const guarded = new WeakSet();
  const replaying = new WeakSet();
  const pending = new Map();
  window.addEventListener("dlp-lab-verdict", e => {
    const d = e.detail;
    const done = d && typeof d.id === "string" && pending.get(d.id);
    if (!done) return;
    // Correlate and validate replies, but DOM events in MAIN are page-accessible.
    const decision = d.decision;
    done(["ALLOW", "REPORT_ONLY", "BLOCK"].includes(decision)
      ? {decision, reason: typeof d.reason === "string" ? d.reason.slice(0, 120) : ""}
      : {decision: "BLOCK", reason: "INVALID_VERDICT"});
  });
  function encodeBytes(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
    }
    return encodeBase64(binary);
  }
  function inspect(file, destination, signal) {
    const size = nativeFileSize.call(file);
    if (size > MAX) return Promise.resolve({decision: "BLOCK", reason: "FILE_TOO_LARGE"});
    return new Promise((resolve, reject) => {
      signal?.throwIfAborted();
      const id = crypto.getRandomValues(new Uint32Array(4)).join("-");
      const reader = size ? new FileReader() : null;
      const timer = setTimeout(() => finish({decision: "BLOCK", reason: "BRIDGE_TIMEOUT"}), INSPECTION_TIMEOUT_MS);
      function cleanup() {
        pending.delete(id);
        clearTimeout(timer);
        signal?.removeEventListener("abort", abort);
        if (reader?.readyState === FileReader.LOADING) reader.abort();
      }
      function finish(result) { cleanup(); resolve(result); }
      function abort() { cleanup(); reject(signal.reason); }
      function send(content_base64) {
        pending.set(id, finish);
        window.dispatchEvent(new CustomEvent("dlp-lab-inspect", {
          detail: {id, name: nativeFileName.call(file), content_base64, destination}
        }));
      }
      signal?.addEventListener("abort", abort, {once: true});
      if (!reader) { send(""); return; }
      reader.onerror = () => finish({decision: "BLOCK", reason: "READ_FAILED"});
      reader.onload = () => {
        try {
          if (reader.result.byteLength !== size) throw new Error("Unexpected number of file bytes");
          send(encodeBytes(reader.result));
        } catch (_) { finish({decision: "BLOCK", reason: "ENCODING_FAILED"}); }
      };
      try { reader.readAsArrayBuffer(file); }
      catch (_) { finish({decision: "BLOCK", reason: "READ_FAILED"}); }
    });
  }
  async function checkFetch(request, files) {
    const signal = request.signal;
    signal.throwIfAborted();
    const scan = new AbortController();
    const abort = () => scan.abort(signal.reason);
    const timer = setTimeout(() => scan.abort(new DOMException("DLP inspection timed out", "NotAllowedError")),
      INSPECTION_TIMEOUT_MS);
    signal.addEventListener("abort", abort, {once: true});
    try {
      const destination = new URL(request.url).origin;
      for (const file of files) {
        const result = await inspect(file, destination, scan.signal);
        scan.signal.throwIfAborted();
        if (!["ALLOW", "REPORT_ONLY"].includes(result.decision)) {
          throw new DOMException("DLP blocked file upload (" + result.reason + ")", "NotAllowedError");
        }
      }
    } finally {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
    }
  }
  // Registered before main-guard.js, whose filename check wraps this content gate.
  window.fetch = function(input, init) {
    let entries;
    try { entries = nativeEntries.call(init?.body); }
    catch (_) { return nativeFetch.apply(this, arguments); }
    try {
      const fields = Array.from(entries);
      const files = new Set();
      for (const [, value] of fields) {
        // Forms with an unselected file input include an empty, unnamed File.
        if (typeof value !== "string" && (nativeFileName.call(value) || nativeFileSize.call(value))) files.add(value);
      }
      if (!files.size) return nativeFetch.apply(this, arguments);
      // Native FormData entries carry immutable File values and effective filenames.
      // Keep the copy private and let Request capture the body, URL and options now.
      const body = new NativeFormData();
      for (const [name, value] of fields) nativeAppend.call(body, name, value);
      const options = new Proxy({}, {get: (_, key) => key === "body" ? body : Reflect.get(init, key, init)});
      const request = new NativeRequest(input, options);
      return checkFetch(request, files).then(() => {
        request.signal.throwIfAborted();
        return nativeFetch.call(this, request);
      });
    } catch (error) { return Promise.reject(error); }
  };
  function onChange(e) {
    const el = e.currentTarget;
    if (el.type !== "file" || replaying.has(el) || !el.files || !el.files.length) return;
    e.stopImmediatePropagation();
    const files = Array.from(el.files);
    el.value = "";
    (async () => {
      for (const f of files) {
        const res = await inspect(f);
        if (!["ALLOW", "REPORT_ONLY"].includes(res.decision)) {
          console.warn("[DLP] File upload denied:", f.name, res.reason);
          nativeAlert("DLP: file upload blocked (" + (res.reason || "inspection failed") + ")");
          return;
        }
      }
      const dt = new DataTransfer();
      files.forEach(f => dt.items.add(f));
      el.files = dt.files;
      replaying.add(el);
      try {
        el.dispatchEvent(new Event("input", {bubbles: true}));
        el.dispatchEvent(new Event("change", {bubbles: true}));
      } finally { replaying.delete(el); }
    })().catch(() => nativeAlert("DLP: file inspection unavailable; upload refused"));
  }
  function guard(el) {
    if (!(el instanceof HTMLInputElement) || guarded.has(el)) return;
    guarded.add(el);
    el.addEventListener("input", onChange, true);
    el.addEventListener("change", onChange, true);
  }
  const nativeClick = HTMLInputElement.prototype.click;
  HTMLInputElement.prototype.click = function () { guard(this); return nativeClick.apply(this, arguments); };
  if (HTMLInputElement.prototype.showPicker) {
    const nativePicker = HTMLInputElement.prototype.showPicker;
    HTMLInputElement.prototype.showPicker = function () { guard(this); return nativePicker.apply(this, arguments); };
  }
  const nativeCreate = document.createElement;
  document.createElement = function (tag) {
    const el = nativeCreate.apply(this, arguments);
    if (String(tag).toLowerCase() === "input") guard(el);
    return el;
  };
})();
