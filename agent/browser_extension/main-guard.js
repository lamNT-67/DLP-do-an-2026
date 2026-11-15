// Runs in the page MAIN world, before ordinary page scripts.
// Best-effort blocking of File objects passed via fetch/XHR/FormData.
// Websites can tamper with MAIN-world hooks: this is NOT a security boundary.
(() => {
  if (window.__dlpLabGuardV2) return;
  Object.defineProperty(window, "__dlpLabGuardV2", {value: true});
  let rules = [], updatedAt = 0;
  const MAX_AGE = 120000;
  const nativeAppend = FormData.prototype.append;
  const nativeSet = FormData.prototype.set;
  const nativeFetch = window.fetch;
  const nativeSend = XMLHttpRequest.prototype.send;
  const nativeBeacon = navigator.sendBeacon?.bind(navigator);

  function matching(file) {
    if (!(file instanceof File) || Date.now() - updatedAt > MAX_AGE || !updatedAt) return null;
    const name = file.name.toLowerCase();
    const ext = name.includes(".") ? name.slice(name.lastIndexOf(".") + 1) : "";
    return rules.find(p => p.action === "BLOCK" && Array.isArray(p.extensions) && p.extensions.includes(ext)) || null;
  }
  function inspect(formData) {
    if (!(formData instanceof FormData)) return null;
    for (const value of formData.values()) {
      const policy = matching(value);
      if (policy) return {policy, file: value};
    }
    return null;
  }
  function deny(hit) {
    console.warn("[DLP] Upload blocked", hit.file.name, "policy", hit.policy.policy_id);
    window.dispatchEvent(new CustomEvent("dlp-lab-blocked", {
      detail: {name: hit.file.name, policy_id: hit.policy.policy_id}
    }));
  }
  window.addEventListener("dlp-lab-rules", event => {
    // This page-world policy handoff is not tamper-proof. Use only for lab testing.
    const data = event.detail;
    if (!data || !Array.isArray(data.rules) || !Number.isFinite(data.updatedAt)) return;
    rules = data.rules;
    updatedAt = data.updatedAt;
  });

  FormData.prototype.append = function(name, value, filename) {
    const policy = matching(value);
    if (policy) {
      const hit = {policy, file: value};
      deny(hit);
      // Throw before the page can append a protected file to the body.
      throw new DOMException("DLP blocked file upload", "NotAllowedError");
    }
    return arguments.length > 2 ? nativeAppend.call(this, name, value, filename) :
      nativeAppend.call(this, name, value);
  };
  FormData.prototype.set = function(name, value, filename) {
    const policy = matching(value);
    if (policy) {
      deny({policy, file: value});
      throw new DOMException("DLP blocked file upload", "NotAllowedError");
    }
    return arguments.length > 2 ? nativeSet.call(this, name, value, filename) :
      nativeSet.call(this, name, value);
  };
  window.fetch = function(input, init) {
    const body = init?.body || (input instanceof Request ? input.body : null);
    const hit = inspect(body);
    if (hit) {
      deny(hit);
      return Promise.reject(new DOMException("DLP blocked file upload", "NotAllowedError"));
    }
    return nativeFetch.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function(body) {
    const hit = inspect(body);
    if (hit) {
      deny(hit);
      throw new DOMException("DLP blocked file upload", "NotAllowedError");
    }
    return nativeSend.apply(this, arguments);
  };
  if (nativeBeacon) {
    navigator.sendBeacon = function(url, data) {
      const hit = inspect(data);
      if (hit) { deny(hit); return false; }
      return nativeBeacon(url, data);
    };
  }
})();
