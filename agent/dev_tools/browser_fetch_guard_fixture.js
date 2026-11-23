// Chromium supplies the DOM, FileReader, FormData and Request. Stub extension
// messaging, the loopback agent, and the receiver so the suite stays offline.
const origin = "https://lab.example";
const upload = origin + "/upload";
const fixtureFetch = window.fetch.bind(window);
const nativeSetTimeout = window.setTimeout.bind(window);
window.setTimeout = (fn, ms, ...args) => nativeSetTimeout(fn, ms === 15000 ? 600 : ms, ...args);
window.alert = () => {};

const sends = [];
window.fetch = async (input, init) => {
  const request = new Request(input, init);
  request.signal.throwIfAborted();
  sends.push(request);
  return new Response("received");
};

const inspections = [];
const rules = [{policy_id: 4, action: "BLOCK", extensions: []}];
const agentLogs = [];
const sender = {url: origin + "/page", tab: {id: 1}, frameId: 0, documentId: "fixture"};
let onInspect = payload => defaultVerdict(payload);
let workerMessage;
let storage = {};
const noopEvent = {addListener() {}};
const runtime = {
  onInstalled: noopEvent,
  onStartup: noopEvent,
  onMessage: {addListener(fn) { workerMessage = fn; }},
  sendMessage(msg, reply) {
    workerMessage(JSON.parse(JSON.stringify(msg)), {...sender}, reply);
  }
};
Object.defineProperty(window.chrome, "runtime", {value: runtime});

function defaultVerdict(payload) {
  return atob(payload.content_base64).includes("Confidential")
    ? {decision: "BLOCK", reason: "CONTENT_MATCH"}
    : {decision: "ALLOW", reason: "CLEAN"};
}

async function agentFetch(url, options) {
  if (url.endsWith("/rules")) return Response.json({updated: true, chrome: rules, edge: rules});
  if (!url.endsWith("/inspect-content")) throw new Error("Unexpected agent endpoint " + url);
  const payload = JSON.parse(options.body);
  inspections.push({...payload, policyDestination: options.headers["X-DLP-Destination"]});
  const verdict = await onInspect(payload);
  if (verdict.decision !== "ALLOW") agentLogs.push(verdict.decision);
  return Response.json({reusable_for_page_fetch: payload.initial_destination_hint === undefined, ...verdict});
}

new Function("chrome", "fetch", workerSource)({
  runtime,
  alarms: {create() {}, onAlarm: noopEvent},
  storage: {local: {
    async set(values) { storage = {...storage, ...values}; },
    async get() { return storage; }
  }}
}, agentFetch);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function equal(actual, expected, message) {
  assert(JSON.stringify(actual) === JSON.stringify(expected),
    `${message}. Got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
}

async function rejects(promise, expected) {
  try { await promise; }
  catch (error) {
    assert(error === expected || error.name === expected, "Unexpected rejection: " + error);
    return;
  }
  throw new Error("Expected rejection");
}

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return {promise, resolve};
}

function form(text, name = "sample.txt") {
  const body = new FormData();
  body.append("file", new File([text], name, {type: "text/plain"}));
  return body;
}

function submit(body, options) {
  return fetch(upload, {method: "POST", body, ...options});
}

function select(input, file) {
  const replayed = new Promise(resolve => input.addEventListener("change", resolve, {once: true}));
  const transfer = new DataTransfer();
  transfer.items.add(file);
  input.files = transfer.files;
  input.dispatchEvent(new Event("input", {bubbles: true}));
  return replayed;
}

addEventListener("DOMContentLoaded", async () => {
  const results = [];
  const output = document.getElementById("results");
  async function test(name, fn) {
    output.textContent = JSON.stringify(results) + " Running " + name;
    inspections.length = 0;
    sends.length = 0;
    agentLogs.length = 0;
    onInspect = defaultVerdict;
    try { await fn(); results.push({name}); }
    catch (error) { results.push({name, error: error.stack || String(error)}); }
  }

  await test("Policy 4 blocks a programmatic file before dispatch", async () => {
    await rejects(submit(form("Confidential - DLP browser test", "sensitive.txt")), "NotAllowedError");
    equal([inspections.length, sends.length, agentLogs], [1, 0, ["BLOCK"]], "block outcome");
  });

  await test("Clean file waits for approval then dispatches with options", async () => {
    const inspected = deferred();
    const verdict = deferred();
    onInspect = () => { inspected.resolve(); return verdict.promise; };
    const options = Object.create({method: "PUT", credentials: "include", mode: "cors",
      cache: "no-store", redirect: "manual", headers: {"X-Lab": "preserved"}});
    Object.defineProperty(options, "body", {value: form("clean")});
    const response = fetch(upload, options);
    await inspected.promise;
    equal(sends.length, 0, "early send");
    verdict.resolve({decision: "ALLOW"});
    equal(await (await response).text(), "received", "fetch response");
    const [request] = sends;
    equal([request.method, request.credentials, request.mode, request.cache, request.redirect,
      request.headers.get("X-Lab")], ["PUT", "include", "cors", "no-store", "manual", "preserved"], "options");
    equal(await (await request.formData()).get("file").text(), "clean", "file contents");
    equal([sends.length, agentLogs], [1, []], "clean outcome");
  });

  await test("REPORT_ONLY dispatches and records one verdict", async () => {
    onInspect = () => ({decision: "REPORT_ONLY", reason: "CONTENT_MATCH"});
    await submit(form("report only"));
    equal([inspections.length, sends.length, agentLogs], [1, 1, ["REPORT_ONLY"]], "report-only outcome");
  });

  await test("Abort preserves the reason and drops late approval", async () => {
    const inspected = deferred();
    const verdict = deferred();
    onInspect = () => { inspected.resolve(); return verdict.promise; };
    const controller = new AbortController();
    const reason = new Error("cancel this upload");
    const response = submit(form("clean"), {signal: controller.signal});
    const rejected = rejects(response, reason);
    await inspected.promise;
    controller.abort(reason);
    await rejected;
    verdict.resolve({decision: "ALLOW"});
    await new Promise(resolve => setTimeout(resolve, 0));
    await rejects(submit(form("another"), {signal: controller.signal}), reason);
    equal([inspections.length, sends.length], [1, 0], "abort outcome");
  });

  await test("Mutation cannot change the bytes, field list, or request options", async () => {
    const body = form("original");
    body.append("note", "first");
    body.append("note", "second");
    body.append("file", new Blob(["second file"], {type: "text/plain"}), "effective.txt");
    const headers = new Headers({"X-Lab": "original"});
    let reads = 0;
    const options = {method: "POST", headers, get body() { reads++; return body; }};
    const response = fetch(upload, options);
    body.delete("file");
    body.set("note", "changed");
    body.append("file", new File(["new file"], "late.txt"));
    options.method = "PUT";
    headers.set("X-Lab", "changed");
    await response;
    equal(reads, 1, "body getter count");
    const [request] = sends;
    equal([request.method, request.headers.get("X-Lab")], ["POST", "original"], "frozen options");
    const wire = [];
    for (const [key, value] of await request.formData()) {
      wire.push([key, typeof value === "string" ? value : [value.name, await value.text()]]);
    }
    equal(wire, [["file", ["sample.txt", "original"]], ["note", "first"],
      ["note", "second"], ["file", ["effective.txt", "second file"]]], "frozen multipart fields");
    equal(inspections.map(p => [p.file_name, atob(p.content_base64)]),
      [["sample.txt", "original"], ["effective.txt", "second file"]], "inspected bytes");
  });

  await test("A blocked later file prevents dispatch of the complete form", async () => {
    const body = form("clean", "first.txt");
    body.append("file", new File(["Confidential"], "second.txt", {type: "application/x-lab,variant"}));
    await rejects(submit(body), "NotAllowedError");
    equal(inspections.map(p => [p.file_name, atob(p.content_base64)]),
      [["first.txt", "clean"], ["second.txt", "Confidential"]], "checked bytes up to the block");
    equal(sends.length, 0, "multipart body stayed local");
  });

  await test("Agent failure and scan timeout fail closed", async () => {
    onInspect = () => { throw new TypeError("Agent offline"); };
    await rejects(submit(form("offline")), "NotAllowedError");
    const late = deferred();
    onInspect = () => late.promise;
    await rejects(submit(form("timeout")), "NotAllowedError");
    late.resolve({decision: "ALLOW"});
    await new Promise(resolve => setTimeout(resolve, 0));
    equal([inspections.length, sends.length], [2, 0], "failure outcomes");
  });

  await test("Text-only FormData and non-FormData preserve Fetch behavior", async () => {
    const body = new FormData();
    body.append("note", "one");
    body.append("note", "two");
    await submit(body);
    await submit("ordinary text");
    await fetch(new Request(upload, {method: "POST", body: "existing Request"}));
    const optional = document.createElement("form");
    optional.innerHTML = '<input name="note" value="no attachment"><input type="file" name="file">';
    await submit(new FormData(optional));
    equal((await sends[0].formData()).getAll("note"), ["one", "two"], "text fields");
    equal(await sends[1].text(), "ordinary text", "text body");
    equal(await sends[2].text(), "existing Request", "Request body");
    equal((await sends[3].formData()).get("note"), "no attachment", "unselected file input");
    equal([sends.length, inspections.length], [4, 0], "passthrough outcome");
  });

  await test("Picker verdict reuse is single-use and scoped to exact bytes and initial origin", async () => {
    const picker = document.getElementById("picker");
    const bytes = "picker report-only";
    const name = "picked.txt";
    onInspect = () => ({decision: "REPORT_ONLY", reason: "CONTENT_MATCH"});
    await select(picker, new File([bytes], name));
    equal(picker.files[0]?.name, name, "allowed picker restored its file");
    await fetch("https://receiver.example/upload", {method: "POST", body: form(bytes, name)});
    await submit(form("different", name));
    await submit(form(bytes, name));
    equal([inspections.length, sends.length, agentLogs.length], [3, 3, 3], "picker verdict reuse");
    equal(inspections[1].initial_destination_hint, "https://receiver.example", "initial destination hint");
    equal(inspections[1].policyDestination, undefined, "hint excluded from the policy destination header");
    await submit(form(bytes, name));
    equal([inspections.length, sends.length, agentLogs.length], [4, 4, 4], "reuse consumed");
  });

  await test("Non-reusable picker approvals still require a Fetch verdict", async () => {
    onInspect = payload => payload.initial_destination_hint === undefined
      ? {decision: "ALLOW", reusable_for_page_fetch: false}
      : {decision: "BLOCK", reason: "CONTENT_MATCH"};
    const picker = document.getElementById("picker");
    await select(picker, new File(["fresh verdict"], "fresh.txt"));
    await rejects(submit(form("fresh verdict", "fresh.txt")), "NotAllowedError");
    equal([inspections.length, sends.length], [2, 0], "non-reusable approval outcome");
  });

  await test("Detached picker still restores files and regular picker still blocks", async () => {
    const detached = document.createElement("input");
    detached.type = "file";
    await select(detached, new File(["detached file"], "detached.txt"));
    equal(await detached.files[0].text(), "detached file", "detached picker replay");
    const picker = document.getElementById("picker");
    const inspected = deferred();
    onInspect = payload => { inspected.resolve(); return defaultVerdict(payload); };
    select(picker, new File(["Confidential"], "picker-sensitive.txt"));
    await inspected.promise;
    equal(picker.files.length, 0, "blocked picker selection cleared");
    equal(sends.length, 0, "no picker upload");
  });

  await test("Zero bytes and the size boundary are inspected, oversized files stay local", async () => {
    const limit = 2 * 1024 * 1024;
    await submit(form("", "empty.txt"));
    await submit(form("a".repeat(limit), "limit.txt"));
    await rejects(submit(form("a".repeat(limit + 1))), "NotAllowedError");
    equal(inspections.map(p => atob(p.content_base64).length), [0, limit], "agent payload sizes");
    equal(sends.length, 2, "only supported sizes dispatched");
  });

  output.textContent = JSON.stringify(results);
  output.dataset.finished = "true";
  await fixtureFetch("/done");
});
