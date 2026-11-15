// Chan o file tao bang code, khong gan vao trang (vi du nut dinh kem cua Zalo web).
// Best-effort: MAIN world khong phai ranh gioi bao mat, trang co the lam gia ket qua.
(() => {
  if (window.__dlpDetachedGuard) return;
  Object.defineProperty(window, "__dlpDetachedGuard", {value: true});
  const MAX = 2 * 1024 * 1024;
  const nativeAlert = window.alert.bind(window);
  const guarded = new WeakSet();
  const replaying = new WeakSet();
  const pending = new Map();
  let seq = 0;
  window.addEventListener("dlp-lab-verdict", e => {
    const d = e.detail;
    const done = d && pending.get(d.id);
    if (done) { pending.delete(d.id); done(d); }
  });
  function inspect(file) {
    return new Promise(resolve => {
      if (file.size > MAX) return resolve({decision: "BLOCK", reason: "FILE_TOO_LARGE"});
      const r = new FileReader();
      r.onerror = () => resolve({decision: "BLOCK", reason: "READ_FAILED"});
      r.onload = () => {
        const b64 = String(r.result || "").split(",")[1];
        if (!b64) return resolve({decision: "BLOCK", reason: "ENCODING_FAILED"});
        const id = ++seq;
        pending.set(id, resolve);
        setTimeout(() => { if (pending.delete(id)) resolve({decision: "BLOCK", reason: "BRIDGE_TIMEOUT"}); }, 15000);
        window.dispatchEvent(new CustomEvent("dlp-lab-inspect", {detail: {id, name: file.name, content_base64: b64}}));
      };
      r.readAsDataURL(file);
    });
  }
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
    })();
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