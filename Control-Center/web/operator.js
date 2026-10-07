"use strict";
// Loaded only by the Operator gateway. All mutations use dispatcher schemas.
(async function operatorSurface() {
  document.body.classList.add("operator-shell");
  const titleNode = document.querySelector("h1");
  titleNode.removeAttribute("data-i18n"); titleNode.textContent = "Operator console / 设备控制台";
  const footerCaption = document.querySelector("footer span");
  footerCaption.removeAttribute("data-i18n"); footerCaption.textContent = "One Operator domain · canonical lifecycle · observed runtime facts";
  const friendlyErrors = {
    ProfileUnavailable:"The selected Profile needs a matching installed artifact or runtime prerequisite. Open Profiles and run Doctor.",
    RuntimeObservationRequired:"Current runtime observation is required. Refresh service status and review readiness.",
    ApplicationBoundaryBusy:"This application's boundary is already in use. Close the existing attachment before reconnecting.",
    ApplicationSessionExpiredOrUnknown:"The bounded application session has expired. Review a fresh connection plan.",
    NativeConfigurationRejected:"The native validator rejected this draft. Check required keys, peer material and endpoint fields.",
    ManagedConfigurationCapacity:"The bounded configuration snapshot store is full. Reclaim unused managed snapshots before saving.",
    ServiceStopRequired:"Stop this service, then review a fresh configuration plan before applying.",
  };
  let methods = {};
  let activeSession = null;
  let reading = false;
  let disposed = false;
  const authForm = $("auth-form");
  const label = authForm.querySelector("label");
  label.removeAttribute("data-i18n"); label.textContent = "Pair this browser / 配对此浏览器";
  const hint = authForm.querySelector(".hint");
  hint.removeAttribute("data-i18n"); hint.textContent = "Enter the one-time operator pairing code. Backend credentials stay on the host.";
  $("token").maxLength = 4096;
  const submit = authForm.querySelector("button");
  submit.removeAttribute("data-i18n"); submit.textContent = "Pair / 配对";
  async function rpc(method, params = {}) {
    const spec = methods[method];
    if (!spec) throw new Error("Operation unavailable in the authoritative schema.");
    const allowed = spec.input_schema.properties || {};
    for (const key of Object.keys(params)) if (!(key in allowed)) throw new Error("Unsupported operation parameter.");
    const response = await fetch("/v1/rpc", {method:"POST", credentials:"same-origin", cache:"no-store", redirect:"error",
      headers:{"Content-Type":"application/json", "X-Shadow6-CSRF":operatorCSRF}, body:JSON.stringify({method, params})});
    const value = await response.json();
    if (!response.ok || value.ok === false) {
      const code = value.error?.code || value.code || "RequestRejected";
      const error = new Error(code.startsWith("Reviewed") ? "The service changed after review. Review its new state; this operation was not retried." : friendlyErrors[code] || code);
      error.code = code; throw error;
    }
    return value.result || value;
  }
  const workspace = document.createElement("section"); workspace.className = "panel operator-workspace";
  const title = document.createElement("h2"); title.textContent = "Service workspace / 服务工作区";
  const service = document.createElement("input"); service.id = "operator-service"; service.maxLength = 4096;
  const serviceLabel = document.createElement("label"); serviceLabel.htmlFor = service.id; serviceLabel.textContent = "Named Service";
  const actions = document.createElement("div"); actions.className = "operator-actions";
  const facts = document.createElement("pre"); facts.className = "operator-facts";
  facts.textContent = "Choose a service to review observed state and deployment evidence.";
  const result = document.createElement("p"); result.setAttribute("role", "status");
  const terminal = document.createElement("section"); terminal.hidden = true;
  const budget = document.createElement("p");
  const output = document.createElement("pre"); output.className = "operator-output";
  output.setAttribute("aria-label", "Received application data");
  const dataLabel = document.createElement("label"); dataLabel.htmlFor = "operator-data"; dataLabel.textContent = "Application payload";
  const data = document.createElement("textarea"); data.id = "operator-data"; data.maxLength = 44000;
  const encoding = document.createElement("select"); encoding.setAttribute("aria-label", "Payload encoding");
  for (const name of ["Text", "Hex", "Base64"]) { const option = document.createElement("option"); option.textContent = name; encoding.append(option); }
  const send = document.createElement("button"); send.textContent = "Send / 发送";
  const close = document.createElement("button"); close.textContent = "Close attachment / 关闭应用连接";
  terminal.append(budget, output, dataLabel, data, encoding, send, close);
  workspace.append(title, serviceLabel, service, actions, facts, result, terminal);
  $("main").insertBefore(workspace, $("main").querySelector("footer"));
  const overview = document.querySelector(".overview-grid");
  const servicesPage = $("services-title").closest("section");
  const profilesPage = $("profiles-title").closest("section");
  const connectPage = document.createElement("section"); connectPage.className = "panel";
  const connectHeading = document.createElement("h2"); connectHeading.textContent = "Application connection / 应用连接";
  const connectHint = document.createElement("p"); connectHint.textContent = "Review a Named Service in Services, then Connect. This bounded operator console preserves the Profile's record or stream semantics.";
  connectPage.append(connectHeading, connectHint, terminal);
  const labPage = document.createElement("section"); labPage.className = "panel";
  const labHeading = document.createElement("h2"); labHeading.textContent = "Test Lab / 实验室";
  const labEvidence = document.createElement("p");
  labEvidence.textContent = "No verified artifact report has been attached to this operator surface. Runtime health and installed Profiles are not Test Lab PASS evidence. Use the existing Test Lab artifact/provenance workflow to inspect WAN and PCAP results.";
  const labRefresh = document.createElement("button"); labRefresh.textContent = "Load verified report";
  const labRows = document.createElement("div"); labRows.className = "profile-grid";
  labRefresh.onclick = async () => {
    labRefresh.disabled = true;
    try {
      const report = await rpc("lab.report");
      labRows.replaceChildren();
      if (!report.available) { labEvidence.textContent = "No verified report attached. Start shadow6 web with --lab-report to consume existing Test Lab evidence."; return; }
      labEvidence.textContent = `Run ${report.runId} · Source ${report.sourceCommit} · Inventory ${report.inventoryStatus || "unavailable"} · ${report.networkMode}\n${report.reportDigest}`;
      for (const row of report.results || []) {
        const card = document.createElement("article"); card.className = "profile-card";
        const title = document.createElement("strong"); title.textContent = `${row.profile} / ${row.scenario}`;
        const observed = document.createElement("p"); observed.textContent = row.status === "FAIL" && row.scenario !== "clean" ? "Measured failure · evidence available" : row.status;
        const details = document.createElement("pre"); details.className = "operator-facts";
        details.textContent = JSON.stringify({correctness:row.correctness,pcap:row.capture,metrics:row.metrics,game:row.applicationGame,stages:row.stages},null,2);
        card.append(title,observed,details); labRows.append(card);
      }
      for (const row of report.s6epe || []) {
        const card = document.createElement("article"); card.className = "profile-card";
        const title = document.createElement("strong"); title.textContent = `${row.profile} · S6EPE/${row.carrier}`;
        const observed = document.createElement("pre"); observed.className = "operator-facts";
        observed.textContent = JSON.stringify({legal:row.legal,status:row.status,results:row.results},null,2);
        card.append(title,observed); labRows.append(card);
      }
    } catch (error) { labEvidence.textContent = error.message; }
    finally { labRefresh.disabled = false; }
  };
  labPage.append(labHeading, labEvidence,labRefresh,labRows);
  const systemPage = document.createElement("section"); systemPage.className = "panel";
  const systemHeading = document.createElement("h2"); systemHeading.textContent = "System / 系统";
  const security = document.createElement("p"); security.textContent = "One instance, one authenticated Operator domain. Backend bearer credentials remain on the host. Lifecycle safety uses canonical confirmation, locks and bounded attachments.";
  const doctorButton = document.createElement("button"); doctorButton.textContent = "Run read-only Doctor";
  const doctorOutput = document.createElement("pre"); doctorOutput.className = "operator-facts";
  doctorButton.onclick = async () => {
    doctorButton.disabled = true;
    try {
      const doctor = await rpc("system.doctor");
      // Aggregate counts only: raw paths/configuration are never rendered here.
      doctorOutput.textContent = JSON.stringify({schema:doctor.schema, checks:(doctor.checks || []).map(check => ({passed:check.passed, code:check.code}))},null,2);
    } catch (error) { doctorOutput.textContent = error.message; }
    finally { doctorButton.disabled = false; }
  };
  const revokeButton = document.createElement("button"); revokeButton.textContent = "Revoke all Web sessions";
  revokeButton.onclick = async () => {
    if (!await confirmOperation("Revoke every Web session? Pair again using a fresh gateway pairing code.")) return;
    await closeSession();
    await request("/gateway/revoke",{method:"POST"});
    gatewayAuth = false; operatorCSRF = ""; bearer = ""; authForm.hidden = false;
    window.location.reload();
  };
  const activityButton = document.createElement("button"); activityButton.textContent = "Activity / 最近操作";
  const activityOutput = document.createElement("pre"); activityOutput.className = "operator-facts";
  activityButton.onclick = async () => {
    activityButton.disabled = true;
    try {
      const activity = await rpc("system.activity");
      activityOutput.textContent = (activity.events || []).map(event => `${new Date(event.timestamp*1000).toISOString()}  ${event.service || ""}  ${event.method}  ${event.result}`).join("\n") || "No recorded operations.";
    } catch (error) { activityOutput.textContent = error.message; }
    finally { activityButton.disabled = false; }
  };
  systemPage.append(systemHeading, security, doctorButton, doctorOutput, activityButton, activityOutput, revokeButton);
  const footer = $("main").querySelector("footer");
  for (const page of [connectPage,labPage,systemPage]) $("main").insertBefore(page,footer);
  const sections = new Map([
    ["overview",[overview]], ["services",[servicesPage,workspace]],
    ["connect",[connectPage]], ["profiles",[profilesPage]], ["lab",[labPage]], ["system",[systemPage]],
  ]);
  const navigation = document.createElement("nav"); navigation.className = "operator-navigation";
  navigation.setAttribute("aria-label", "Operator workspace");
  const labels = {overview:"Overview / 概览",services:"Services / 服务",connect:"Connect / 连接",profiles:"Profiles / 核心与 Profile",lab:"Lab / 实验室",system:"System / 系统"};
  function navigate() {
    const selected = sections.has(location.hash.slice(1)) ? location.hash.slice(1) : "overview";
    for (const [key,pages] of sections) for (const page of pages) page.hidden = key !== selected;
    for (const link of navigation.children) {
      if (link.hash === "#"+selected) link.setAttribute("aria-current","page"); else link.removeAttribute("aria-current");
    }
  }
  for (const [key,label] of Object.entries(labels)) {
    const link = document.createElement("a"); link.href = "#"+key; link.textContent = label; navigation.append(link);
  }
  $("main").insertBefore(navigation,overview);
  window.addEventListener("hashchange",navigate); navigate();
  window.addEventListener("shadow6-service-selected", async event => {
    service.value = event.detail; location.hash = "services";
    try { await reviewStatus(); workspace.scrollIntoView({block:"start",behavior:"smooth"}); }
    catch (error) { result.textContent = error.message; }
  });
  function safeFacts(value) {
    // Select evidence explicitly: never dump native config or secret materials.
    return JSON.stringify({name:value.name, state:value.state, readiness:value.runtime?.readiness,
      evidence:value.readinessEvidence, core:value.coreBinding?.core,
      profile:value.profileBinding?.profile, lock:value.deploymentLock?.digest,
      limits:value.deploymentLock?.limitResolution}, null, 2);
  }
  function button(text, method, handler) {
    const node = document.createElement("button"); node.textContent = text; node.disabled = true;
    node.dataset.method = method;
    node.addEventListener("click", async () => {
      node.disabled = true; result.textContent = "Working…";
      try { await handler(); } catch (error) { result.textContent = error.message; }
      finally { node.disabled = !methods[method]; }
    }); actions.append(node);
  }
  async function reviewStatus() {
    const value = await rpc("service.status", {name:service.value}); facts.textContent = safeFacts(value);
    if (typeof privacyChoice !== "undefined") privacyChoice.value = value.privacy || "native";
    return value;
  }
  // Native <dialog> provides keyboard focus trapping and Escape cancellation.
  function confirmOperation(text, typedName = null) {
    return new Promise(resolve => {
      const dialog = document.createElement("dialog");
      const description = document.createElement("p"); description.textContent = text;
      const approve = document.createElement("button"); approve.textContent = "Confirm / 确认";
      const cancel = document.createElement("button"); cancel.textContent = "Cancel / 取消";
      dialog.append(description);
      if (typedName !== null) {
        const field = document.createElement("input"); field.setAttribute("aria-label", "Type service name to remove");
        approve.disabled = true; field.addEventListener("input", () => { approve.disabled = field.value !== typedName; }); dialog.append(field);
      }
      const finish = value => { dialog.close(); dialog.remove(); resolve(value); };
      cancel.onclick = () => finish(false); approve.onclick = () => finish(true);
      dialog.addEventListener("cancel", event => { event.preventDefault(); finish(false); });
      dialog.append(cancel, approve); document.body.append(dialog); dialog.showModal();
    });
  }
  button("Inspect / 查看", "service.status", async () => { await reviewStatus(); result.textContent = "Current canonical observation loaded."; });
  for (const action of ["run","stop","restart","apply","remove"]) {
    button(action, `service.${action}`, async () => {
      const name = service.value;
      const current = await reviewStatus(); const digest = current.deploymentLock?.digest;
      if (!digest) throw new Error("A reviewed DeploymentLock is required.");
      const impact = action === "remove" ? "Stops the service, closes attachments and removes its registry/observation state. Core binaries remain installed." :
        ["stop","restart"].includes(action) ? "Active application sessions will be interrupted." : "Uses the current locked deployment.";
      if (!await confirmOperation(`${action} ${name}?\n${impact}\nLock: ${digest}`, action === "remove" ? name : null)) return;
      await rpc(`service.${action}`, {name, confirmed:true, expected_lock_digest:digest});
      await reviewStatus(); result.textContent = `${action}: completed`;
    });
  }
  button("Relock reviewed material", "service.relock", async () => {
    const current = await reviewStatus();
    const name = service.value;
    const lock = current.deploymentLock?.digest;
    if (!lock) throw new Error("A reviewed DeploymentLock is required.");
    const plan = await rpc("service.config_plan", {name,core:current.coreBinding.core,profile:current.profileBinding.profile,source:"locked"});
    if (!plan.valid || plan.requiresStop) throw new Error("Stop the service and resolve material diagnostics before relocking.");
    configEvidence.textContent = JSON.stringify({plan:plan.expected_plan_digest,material:plan.materialDigest,lock},null,2);
    if (!await confirmOperation(`Relock ${name}? Review the currently bound material digest.\n${plan.materialDigest}`)) return;
    await rpc("service.relock", {name,confirmed:true,expected_lock_digest:lock,expected_material_digest:plan.materialDigest});
    await reviewStatus(); result.textContent = "Reviewed material relocked.";
  });
  // Core selection is operator-explicit; form structure comes from the
  // canonical native realization provider, never a frontend Core switch.
  const configuration = document.createElement("section");
  const configHeading = document.createElement("h3"); configHeading.textContent = "Create / Configure service";
  const configForm = document.createElement("form");
  const coreChoice = document.createElement("select"); coreChoice.id = "config-core"; coreChoice.required = true;
  const profileChoice = document.createElement("select"); profileChoice.id = "config-profile"; profileChoice.required = true;
  const roleChoice = document.createElement("select"); roleChoice.id = "config-role"; roleChoice.required = true;
  const privacyChoice = document.createElement("select"); privacyChoice.id = "config-privacy";
  const nativeFields = document.createElement("div"); nativeFields.className = "native-fields";
  const configMode = document.createElement("button"); configMode.type = "button"; configMode.textContent = "Form / JSON";
  const jsonLabel = document.createElement("label"); jsonLabel.htmlFor = "config-json"; jsonLabel.textContent = "Native configuration JSON (advanced)";
  const configJSON = document.createElement("textarea"); configJSON.id = "config-json"; configJSON.maxLength = 65536; configJSON.hidden = true; jsonLabel.hidden = true;
  const configEvidence = document.createElement("pre"); configEvidence.className = "operator-facts";
  const reviewConfig = document.createElement("button"); reviewConfig.type = "submit"; reviewConfig.textContent = "Validate & review draft";
  const applyConfig = document.createElement("button"); applyConfig.type = "button"; applyConfig.textContent = "Plan & apply saved material"; applyConfig.disabled = true;
  const runAfterApply = document.createElement("input"); runAfterApply.type = "checkbox"; runAfterApply.id = "run-after-apply";
  const runLabel = document.createElement("label"); runLabel.htmlFor = runAfterApply.id; runLabel.textContent = "Run after reviewed apply";
  const specLabel = document.createElement("label"); specLabel.htmlFor = "config-composition"; specLabel.textContent = "Deployment composition (advanced, existing canonical spec)";
  const specInput = document.createElement("textarea"); specInput.id = "config-composition"; specInput.maxLength = 65536; specInput.value = "{}";
  function labeled(label, node) {
    const text = document.createElement("label"); text.htmlFor = node.id; text.textContent = label; configForm.append(text,node);
  }
  for (const [label,node] of [["1. Explicit Core",coreChoice],["2. Explicit Profile",profileChoice],["3. Native role",roleChoice],["Privacy",privacyChoice]]) labeled(label,node);
  function choosePlaceholder(node,text) { node.replaceChildren(); const option = document.createElement("option"); option.value = ""; option.textContent = text; node.append(option); }
  choosePlaceholder(coreChoice,"Choose Core"); choosePlaceholder(profileChoice,"Choose Profile"); choosePlaceholder(roleChoice,"Choose role");
  for (const role of ["broker","agent","client"]) { const option = document.createElement("option"); option.value = role; option.textContent = role; roleChoice.append(option); }
  for (const name of ["native","envelope"]) { const option = document.createElement("option"); option.value = name; option.textContent = name; privacyChoice.append(option); }
  let sourceContracts = [];
  let readNativeForm = () => ({});
  let draftDigest = null;
  let loadedName = null;
  let editGeneration = 0;
  let activeInputSchema = null;
  function secretField(key,value) {
    return Boolean(value?.secret || value?.unchanged) || /(?:private|secret|password|token|credential)|^(?:key|key_material|auth_key|psk|api_key|signing_key|bearer)$/i.test(key);
  }
  function editor(value, fieldPath = "", schema = activeInputSchema) {
    const reads = [];
    for (const [key,initial] of Object.entries(value)) {
      const path = fieldPath ? fieldPath+" / "+key : key;
      if (initial && typeof initial === "object" && !Array.isArray(initial) && !secretField(key,initial)) {
        const group = document.createElement("fieldset"); const legend = document.createElement("legend"); legend.textContent = path; group.append(legend); nativeFields.append(group);
        // Nested fields remain typed; no native material is reflected as HTML.
        const child = document.createElement("div"); group.append(child);
        const read = objectEditor(initial,child,path,schema?.properties?.[key]); reads.push([key,read]);
      } else reads.push([key,fieldEditor(initial,key,path,nativeFields,schema?.properties?.[key])]);
    }
    return () => Object.fromEntries(reads.map(([key,read]) => [key,read()]));
  }
  function objectEditor(value,root,prefix,schema) {
    const reads = Object.entries(value).map(([key,item]) => {
      if (item && typeof item === "object" && !Array.isArray(item) && !secretField(key,item)) {
        const group = document.createElement("fieldset"); const title = document.createElement("legend"); title.textContent = key; group.append(title); root.append(group);
        return [key,objectEditor(item,group,prefix+" / "+key,schema?.properties?.[key])];
      }
      return [key,fieldEditor(item,key,prefix+" / "+key,root,schema?.properties?.[key])];
    });
    return () => Object.fromEntries(reads.map(([key,read]) => [key,read()]));
  }
  let fieldIndex = 0;
  function fieldEditor(initial,key,path,root,schema) {
    const secret = schema?.writeOnly === true || secretField(key,initial);
    if (Array.isArray(initial) && !secret) {
      const group=document.createElement("fieldset"); const legend=document.createElement("legend"); legend.textContent=path; group.append(legend); root.append(group);
      const rows=[]; const add=document.createElement("button"); add.type="button"; add.textContent="Add item";
      const maximum=Math.min(schema?.maxItems || 256,256);
      function append(value) {
        const row=document.createElement("div"); group.insertBefore(row,add);
        const index=rows.length;
        const read=value && typeof value==="object" && !Array.isArray(value) ? objectEditor(value,row,path+" / "+index,schema?.items) : fieldEditor(value,String(index),path+" / "+index,row,schema?.items);
        const entry={row,read};rows.push(entry);
        const remove=document.createElement("button"); remove.type="button"; remove.textContent="Remove item";
        remove.onclick=()=>{rows.splice(rows.indexOf(entry),1);row.remove();add.disabled=rows.length>=maximum;}; row.append(remove);
        add.disabled=rows.length>=maximum;
      }
      function blank(value,key="") {
        if (secretField(key,value)) return "";
        if (Array.isArray(value)) return [];
        if (value && typeof value==="object") return Object.fromEntries(Object.entries(value).map(([name,item])=>[name,blank(item,name)]));
        return typeof value==="boolean" ? false : typeof value==="number" ? 0 : "";
      }
      add.onclick=()=>{if(rows.length<maximum)append(blank(initial[0]));}; group.append(add);
      for (const value of initial) append(value);
      return ()=>rows.map(entry=>entry.read());
    }
    const input = document.createElement("input");
    input.id = `native-field-${++fieldIndex}`;
    const label = document.createElement("label"); label.htmlFor = input.id; label.textContent = path;
    if (secret) { input.type = "password"; input.autocomplete = "new-password"; input.placeholder = initial?.secret ? "unchanged — enter replacement" : "required secret material"; }
    else if (typeof initial === "boolean") { input.type = "checkbox"; input.checked = initial; }
    else if (typeof initial === "number") { input.type = "number"; input.step = "1"; input.value = String(initial); if (schema?.minimum !== undefined) input.min = String(schema.minimum); if (schema?.maximum !== undefined) input.max = String(schema.maximum); }
    else { input.type = "text"; input.value = Array.isArray(initial) ? JSON.stringify(initial) : initial === null ? "null" : String(initial); }
    if (schema?.maxLength !== undefined) input.maxLength = schema.maxLength;
    root.append(label,input);
    let confirmation = null;
    let replacing = !(initial?.secret || initial?.unchanged);
    if (secret) {
      confirmation = document.createElement("input"); confirmation.type = "password"; confirmation.id = input.id+"-confirm"; confirmation.autocomplete = "new-password";
      const confirmLabel = document.createElement("label"); confirmLabel.htmlFor = confirmation.id; confirmLabel.textContent = "Confirm replacement: "+path; root.append(confirmLabel,confirmation);
      if (initial?.secret || initial?.unchanged) {
        input.hidden = true; confirmation.hidden = true; confirmLabel.hidden = true;
        const replace = document.createElement("button"); replace.type = "button"; replace.textContent = "Replace secret / 替换秘密";
        replace.onclick = () => {
          replacing = !replacing; input.hidden = confirmation.hidden = confirmLabel.hidden = !replacing;
          replace.textContent = replacing ? "Keep unchanged / 保持原值" : "Replace secret / 替换秘密";
          if (!replacing) { input.value = ""; confirmation.value = ""; } else input.focus();
        }; root.append(replace);
      }
    }
    return () => {
      if (secret) {
        if (input.value !== confirmation.value) throw new Error("Secret replacement confirmation does not match.");
        if (!replacing && (initial?.secret || initial?.unchanged)) return {unchanged:true};
        return input.value;
      }

      if (typeof initial === "boolean") return input.checked;
      if (typeof initial === "number") {
        const value = Number(input.value); if (input.value.trim() === "" || !Number.isSafeInteger(value) || (schema?.minimum !== undefined && value < schema.minimum) || (schema?.maximum !== undefined && value > schema.maximum)) throw new Error("Expected bounded integer: "+path); return value;
      }
      return initial === null && input.value === "null" ? null : input.value;
    };
  }
  async function loadConfiguration() {
    const generation = ++editGeneration;
    if (!coreChoice.value || !profileChoice.value || !roleChoice.value) return;
    const name = service.value;
    const metadata = await rpc("core.config_form",{core:coreChoice.value,profile:profileChoice.value,role:roleChoice.value});
    const stored = name ? await rpc("service.config_inspect",{name}) : null;
    if (generation !== editGeneration) return;
    loadedName = name; draftDigest = stored?.digest || null;
    activeInputSchema = metadata.inputSchema;
    const value = stored?.document || metadata.template;
    nativeFields.replaceChildren(); readNativeForm = editor(value);
    configJSON.hidden = true; jsonLabel.hidden = true; nativeFields.hidden = false;
    configEvidence.textContent = `${metadata.provider} · ${metadata.contractDigest}\nSecret fields are write-only. Save does not apply or restart.`;
    applyConfig.disabled = !stored?.exists;
  }
  coreChoice.onchange = () => {
    choosePlaceholder(profileChoice,"Choose Profile");
    for (const item of sourceContracts.filter(item => item.core === coreChoice.value)) {
      const option = document.createElement("option"); option.value = item.id;
      option.textContent = `${item.id} · ${item.nativeTransport} · ${item.applicationBoundary.kind}`; profileChoice.append(option);
    }
    nativeFields.replaceChildren(); applyConfig.disabled = true;
  };
  profileChoice.onchange = () => { void loadConfiguration().catch(error => { configEvidence.textContent = error.message; }); };
  roleChoice.onchange = profileChoice.onchange;
  configMode.onclick = () => {
    try {
      if (configJSON.hidden) { configJSON.value = JSON.stringify(readNativeForm(),null,2); configJSON.hidden = false; jsonLabel.hidden = false; nativeFields.hidden = true; }
      else { const value = JSON.parse(configJSON.value); nativeFields.replaceChildren(); readNativeForm = editor(value); configJSON.hidden = true; jsonLabel.hidden = true; nativeFields.hidden = false; }
    } catch (error) { configEvidence.textContent = error.message; }
  };
  configForm.onsubmit = async event => {
    event.preventDefault(); reviewConfig.disabled = true;
    try {
      if (!service.value || loadedName !== service.value) await loadConfiguration();
      const name = service.value;
      const document = configJSON.hidden ? JSON.stringify(readNativeForm()) : configJSON.value;
      const params = {name,core:coreChoice.value,profile:profileChoice.value,role:roleChoice.value,document,expected_digest:draftDigest};
      const reviewed = await rpc("service.config_review",params);
      configEvidence.textContent = JSON.stringify({core:reviewed.review.core,profile:reviewed.review.profile,role:roleChoice.value,changes:reviewed.review.changes,digest:reviewed.review.digest,evidence:reviewed.review.evidence},null,2);
      if (!await confirmOperation(`Save reviewed draft for ${name}?\nExisting runtime material remains unchanged.\n${reviewed.review.digest}`)) return;
      const saved = await rpc("service.config_save",{...params,confirmed:true,expected_review_digest:reviewed.expected_review_digest});
      draftDigest = saved.digest; applyConfig.disabled = false;
      configEvidence.textContent = "Draft saved. Plan and review the deployment separately before applying.";
      // Clear replacement inputs promptly; reload receives only redacted values.
      await loadConfiguration();
    } catch (error) { configEvidence.textContent = error.message; }
    finally { reviewConfig.disabled = false; }
  };
  applyConfig.onclick = async () => {
    applyConfig.disabled = true;
    try {
      const name = service.value; const params = {name,core:coreChoice.value,profile:profileChoice.value,privacy:privacyChoice.value};
      const spec = JSON.parse(specInput.value); if (Object.keys(spec).length) params.spec = spec;
      const plan = await rpc("service.config_plan",params);
      configEvidence.textContent = JSON.stringify({valid:plan.valid,diagnostics:plan.diagnostics,
        limits:plan.limitResolution,material:plan.materialDigest,lock:plan.expected_lock_digest,plan:plan.expected_plan_digest},null,2);
      if (!plan.valid) throw new Error("Profile or deployment material is unavailable. Resolve the canonical diagnostics first.");
      if (plan.requiresStop) throw new Error("Stop the running service, then review a fresh plan before applying. No automatic stop or retry was performed.");
      if (!await confirmOperation(`Apply and relock ${name}?${runAfterApply.checked ? " Then run the runtime." : " Runtime remains stopped."}\n${plan.materialDigest}`)) return;
      await rpc("service.config_apply",{...params,confirmed:true,run:runAfterApply.checked,
        expected_plan_digest:plan.expected_plan_digest,expected_material_digest:plan.materialDigest,expected_lock_digest:plan.expected_lock_digest});
      await reviewStatus(); result.textContent = "Reviewed configuration applied.";
    } catch (error) { configEvidence.textContent = error.message; }
    finally { applyConfig.disabled = false; }
  };
  const reclaimConfig = document.createElement("button"); reclaimConfig.type = "button"; reclaimConfig.textContent = "Reclaim unused snapshots";
  reclaimConfig.onclick = async () => {
    reclaimConfig.disabled = true;
    try {
      const inspected = await rpc("service.config_inspect",{name:service.value});
      if (!await confirmOperation(`Reclaim unused configuration snapshots for ${service.value}?\nOnly hash-verified snapshots unused by any Named Service will be removed. Active material and the current draft are preserved.`)) return;
      const reclaimed = await rpc("service.config_reclaim",{name:service.value,confirmed:true,expected_digest:inspected.digest});
      configEvidence.textContent = `${reclaimed.removedSnapshots} unused snapshots reclaimed. Active materials preserved.`;
    } catch (error) { configEvidence.textContent = error.message; }
    finally { reclaimConfig.disabled = false; }
  };
  const discardDraft = document.createElement("button"); discardDraft.type = "button"; discardDraft.textContent = "Discard removed service draft";
  discardDraft.onclick = async () => {
    discardDraft.disabled = true;
    try {
      const name=service.value;
      const inspected=await rpc("service.config_inspect",{name});
      if (!await confirmOperation(`Discard the removed service's draft and unused snapshots for ${name}? Active materials referenced by other services are preserved.`,name)) return;
      await rpc("service.config_reclaim",{name,confirmed:true,expected_digest:inspected.digest,discard_draft:true});
      draftDigest=null;applyConfig.disabled=true;nativeFields.replaceChildren();configJSON.value="";
      configEvidence.textContent="Removed service draft discarded; referenced materials preserved.";
    } catch (error) { configEvidence.textContent=error.message; }
    finally { discardDraft.disabled=false; }
  };
  configForm.append(configMode,nativeFields,jsonLabel,configJSON,specLabel,specInput,reviewConfig,runAfterApply,runLabel,applyConfig,reclaimConfig,discardDraft,configEvidence);
  configuration.append(configHeading,configForm); workspace.append(configuration);
  function updateBudget(meta) {
    budget.textContent = `${meta.boundary} · ${Math.ceil(meta.lifetimeRemainingMs / 1000)}s remaining · ${meta.bytesRemaining} bytes remaining${meta.recordPreserving ? " · One Send = One Application Record" : " · Byte stream"}`;
  }
  function appendRecord(meta) {
    updateBudget(meta);
    const bytes = Uint8Array.from(atob(meta.dataBase64 || ""), char => char.charCodeAt(0));
    const text = encoding.value === "Hex" ? Array.from(bytes, byte => byte.toString(16).padStart(2,"0")).join(" ") : encoding.value === "Base64" ? meta.dataBase64 : new TextDecoder().decode(bytes);
    output.textContent = (output.textContent + `\n${meta.recordPreserving ? "Record " : "Chunk "}${bytes.length} bytes · ${new Date().toISOString()}\n${text}`).slice(-65536);
  }
  async function closeSession() {
    const old = activeSession; activeSession = null; terminal.hidden = true;
    if (old) await rpc("service.session_close", {handle:old.handle});
  }
  async function readLoop(session) {
    if (reading) return;
    reading = true;
    try {
      while (!disposed && activeSession === session) {
        try {
          const meta = await rpc("service.session_read", {handle:session.handle, max_bytes:Math.min(session.maxReadBytes,methods["service.session_read"].input_schema.properties.max_bytes.maximum), timeout_ms:Math.min(1000,methods["service.session_read"].input_schema.properties.timeout_ms.maximum)});
          if (activeSession !== session) break;
          appendRecord(meta);
          if (meta.closed || meta.eof) { await closeSession(); break; }
        } catch (error) {
          if (error.code === "ApplicationSessionTimeout") continue;
          result.textContent = error.message; await closeSession(); break;
        }
      }
    } finally { reading = false; }
  }
  button("Connect / 连接", "service.connection_review", async () => {
    if (activeSession || reading) throw new Error("Close the current attachment and wait for its outstanding read.");
    const name = service.value; const review = await rpc("service.connection_review", {name});
    facts.textContent = JSON.stringify({profile:review.plan.profileBinding, readiness:review.plan.readiness,
      boundary:review.plan.applicationBoundary, lock:review.expected_lock_digest,
      material:review.expected_material_digest, plan:review.expected_plan_digest}, null, 2);
    if (!await confirmOperation(`Connect ${name}? Review the Profile, boundary and digests shown in the workspace.`)) return;
    const connected = await rpc("service.connect_execute", {name, confirmed:true,
      expected_plan_digest:review.expected_plan_digest, expected_material_digest:review.expected_material_digest,
      expected_lock_digest:review.expected_lock_digest});
    if (!connected.session) throw new Error("Runtime has no available application attachment.");
    activeSession = connected.session; terminal.hidden = false; location.hash = "connect"; output.textContent = "";
    updateBudget(activeSession); result.textContent = "Connected to the observed ApplicationBoundary.";
    void readLoop(activeSession);
  });
  send.onclick = async () => {
    if (!activeSession) return;
    send.disabled = true;
    try {
      let bytes;
      if (encoding.value === "Text") bytes = new TextEncoder().encode(data.value);
      else if (encoding.value === "Base64") {
        if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(data.value)) throw new Error("Invalid base64");
        bytes = Uint8Array.from(atob(data.value), char => char.charCodeAt(0));
      } else {
        const value = data.value.replace(/\s/g, "");
        if (!/^(?:[0-9a-fA-F]{2})*$/.test(value)) throw new Error("Invalid hex");
        bytes = Uint8Array.from(value.match(/../g) || [], byte => parseInt(byte,16));
      }
      const maxWrite = methods["service.session_write"].input_schema.properties.data_base64.maxLength;
      if (bytes.length > Math.min(activeSession.maxWriteBytes, activeSession.maxRecord || activeSession.maxWriteBytes)) throw new Error("Payload exceeds the declared session/record limit.");
      const encoded = btoa(String.fromCharCode(...bytes));
      if (encoded.length > maxWrite) throw new Error("Payload exceeds the declared session/record limit.");
      updateBudget(await rpc("service.session_write", {handle:activeSession.handle, data_base64:encoded, timeout_ms:Math.min(1000,methods["service.session_write"].input_schema.properties.timeout_ms.maximum)}));
      data.value = "";
    } catch (error) { result.textContent = error.message; }
    finally { send.disabled = false; }
  };
  close.onclick = () => { void closeSession().catch(error => { result.textContent = error.message; }); };
  async function authenticated(value) {
    gatewayAuth = true; operatorCSRF = value.csrf; bearer = "operator-session";
    methods = (await request("/v1/schema")).methods;
    const catalog = await rpc("core.profiles"); sourceContracts = catalog.sourceContracts || [];
    choosePlaceholder(coreChoice,"Choose Core");
    for (const core of [...new Set(sourceContracts.map(item => item.core))]) {
      const option = document.createElement("option"); option.value = core; option.textContent = core; coreChoice.append(option);
    }
    authForm.hidden = true;
    for (const node of actions.querySelectorAll("button")) node.disabled = !methods[node.dataset.method];
    await refreshAll();
  }
  authForm.addEventListener("submit", async event => {
    event.preventDefault(); event.stopImmediatePropagation();
    const code = $("token").value; $("token").value = ""; submit.disabled = true;
    try {
      const response = await fetch("/gateway/pair", {method:"POST", credentials:"same-origin", redirect:"error",
        headers:{"Content-Type":"application/json"}, body:JSON.stringify({code})});
      if (!response.ok) throw new Error("Pairing rejected or expired. Restart the gateway with a new pairing credential.");
      await authenticated(await response.json());
    } catch (error) { showError(error.message); }
    finally { submit.disabled = false; }
  }, true);
  $("disconnect").addEventListener("click", async () => {
    try { await closeSession(); await request("/gateway/logout", {method:"POST"}); }
    finally { gatewayAuth = false; operatorCSRF = ""; bearer = ""; authForm.hidden = false; }
  }, true);
  window.addEventListener("pagehide", () => {
    disposed = true;
    if (activeSession) {
      void fetch("/v1/rpc", {method:"POST", credentials:"same-origin", keepalive:true,
        headers:{"Content-Type":"application/json", "X-Shadow6-CSRF":operatorCSRF},
        body:JSON.stringify({method:"service.session_close", params:{handle:activeSession.handle}})});
      activeSession = null;
    }
  });
  try {
    const response = await fetch("/gateway/session", {credentials:"same-origin", cache:"no-store"});
    if (response.ok) await authenticated(await response.json());
  } catch (error) { showError(error.message); }
})();
