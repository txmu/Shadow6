"use strict";

const translations = {
  en: {
    skip: "Skip to content", subtitle: "Control Center", localOnly: "Loopback only", workspace: "LOCAL WORKSPACE",
    title: "Your Shadow6 systems, at a glance.", intro: "Review observed status, installed Native Profiles, and Named Services from this device.",
    tokenLabel: "Local bearer token", tokenHint: "The token stays in memory and is sent only to this loopback API.", connect: "Connect",
    overview: "OVERVIEW", hostStatus: "Host status", refresh: "Refresh", connectToView: "Connect to view current status.",
    serviceCount: "NAMED SERVICES", serviceCountCaption: "Registered local services", profileCount: "NATIVE PROFILES",
    profileCountCaption: "Source contracts in the catalog", operations: "OPERATIONS", namedServices: "Named Services",
    name: "Name", core: "Core", profile: "Profile", state: "Observed state", endpoint: "Endpoint", previous: "Previous", next: "Next",
    servicesEmpty: "Connect to load service status.", capabilities: "CAPABILITIES", nativeProfiles: "Native Profiles",
    profileReadOnly: "Read-only availability", profilesEmpty: "Connect to inspect installed Profile prerequisites.",
    footer: "Shadow6 Control Center · authenticated, loopback-only, read-only by default", loading: "Loading local status…",
    unauthorized: "Token rejected. Check the local token file.", requestFailed: "The local service did not return a usable response.", disconnect: "Disconnect",
    host: "Host", platform: "Platform", cores: "Installed Cores", healthChecks: "Health checks", ready: "Ready", unavailable: "Needs attention",
    noServices: "No Named Services are registered.", page: "Page %1 of %2", profileAvailable: "Installed and available",
    profileUnavailable: "Prerequisites unavailable", idle: "No running services", unknown: "Unknown",
  },
  zh: {
    skip: "跳到正文", subtitle: "控制中心", localOnly: "仅限回环地址", workspace: "本机工作区",
    title: "Shadow6 状态，一览即知。", intro: "在本机查看运行状态、已安装的 Native Profile 与命名服务。",
    tokenLabel: "本机 Bearer Token", tokenHint: "Token 只保存在内存中，并且只发送到本机回环 API。", connect: "连接",
    overview: "概览", hostStatus: "主机状态", refresh: "刷新", connectToView: "连接后查看当前状态。",
    serviceCount: "命名服务", serviceCountCaption: "已登记的本机服务", profileCount: "Native Profile",
    profileCountCaption: "目录中的源契约数量", operations: "运维", namedServices: "命名服务",
    name: "名称", core: "核心", profile: "Profile", state: "观测状态", endpoint: "端点", previous: "上一页", next: "下一页",
    servicesEmpty: "连接后加载服务状态。", capabilities: "能力", nativeProfiles: "Native Profile",
    profileReadOnly: "只读可用性", profilesEmpty: "连接后检查已安装 Profile 的运行条件。",
    footer: "Shadow6 控制中心 · 认证保护 · 仅限回环地址 · 默认只读", loading: "正在读取本机状态…",
    unauthorized: "Token 未通过验证，请检查本机 Token 文件。", requestFailed: "本机服务未返回可用结果。", disconnect: "断开连接",
    host: "主机", platform: "平台", cores: "已安装核心", healthChecks: "健康检查", ready: "就绪", unavailable: "需要处理",
    noServices: "尚未登记命名服务。", page: "第 %1 页，共 %2 页", profileAvailable: "已安装且可用",
    profileUnavailable: "运行条件不可用", idle: "没有运行中的服务", unknown: "未知",
  },
};

const $ = (id) => document.getElementById(id);
let language = navigator.language.toLowerCase().startsWith("zh") ? "zh" : "en";
let bearer = "";
let offset = 0;
let totalServices = 0;
const pageSize = 50;

function translate(key) { return translations[language][key] || translations.en[key] || key; }
function applyLanguage() {
  document.documentElement.lang = language === "zh" ? "zh-CN" : "en";
  document.querySelectorAll("[data-i18n]").forEach((node) => { node.textContent = translate(node.dataset.i18n); });
  $("language").textContent = language === "zh" ? "EN" : "中文";
  if (bearer) refreshAll();
}
function showError(message) { $("error").textContent = message; $("error").hidden = !message; }
function setLoading(value) { $("loading").hidden = !value; }
async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (bearer) headers.set("Authorization", `Bearer ${bearer}`);
  const response = await fetch(path, { ...options, headers, cache: "no-store", credentials: "same-origin", redirect: "error" });
  if (!response.ok) {
    if (response.status === 401) throw new Error(translate("unauthorized"));
    throw new Error(`${translate("requestFailed")} (${response.status})`);
  }
  return response.json();
}
function appendStatus(label, value) {
  const item = document.createElement("div"); item.className = "status-item";
  const strong = document.createElement("strong"); strong.textContent = value || translate("unknown");
  const caption = document.createElement("span"); caption.textContent = label;
  item.append(strong, caption); $("status").append(item);
}
function renderStatus(data) {
  const root = $("status"); root.replaceChildren(); root.classList.remove("empty-state");
  const status = data.result || data;
  const details = status.observation || {};
  const components = details.components || {};
  const cores = Object.entries(components).filter(([name, value]) => name.startsWith("core-") && (value.binaries || []).length > 0).length;
  const checks = status.doctor?.checks || [];
  const passed = checks.filter((item) => item.passed).length;
  appendStatus(translate("cores"), String(cores));
  appendStatus(translate("healthChecks"), checks.length ? `${passed} / ${checks.length}` : translate("unknown"));
  appendStatus(translate("platform"), navigator.platform || "—");
}
function renderServices(page) {
  totalServices = page.total;
  $("service-total").textContent = String(page.total);
  const body = $("services"); body.replaceChildren();
  if (!page.items.length) {
    const row = document.createElement("tr"); const cell = document.createElement("td");
    cell.colSpan = 5; cell.className = "empty-state"; cell.textContent = translate("noServices"); row.append(cell); body.append(row);
  }
  for (const item of page.items) {
    const row = document.createElement("tr");
    const name = document.createElement("td"); name.className = "service-name"; name.textContent = item.name || "";
    const core = document.createElement("td"); core.textContent = item.core || "—";
    const profile = document.createElement("td"); profile.textContent = item.profile || "—";
    const stateCell = document.createElement("td"); const pill = document.createElement("span");
    pill.className = "pill"; pill.dataset.state = item.state || "unknown"; pill.textContent = item.state || translate("unknown"); stateCell.append(pill);
    const endpoint = document.createElement("td"); endpoint.textContent = item.endpoint || "—";
    row.append(name, core, profile, stateCell, endpoint); body.append(row);
  }
  const pages = Math.max(1, Math.ceil(page.total / pageSize));
  const current = Math.min(pages, Math.floor(offset / pageSize) + 1);
  $("page-number").textContent = translate("page").replace("%1", String(current)).replace("%2", String(pages));
  $("page-caption").textContent = page.total ? `${page.total} · ${page.offset + 1}–${Math.min(page.offset + page.items.length, page.total)}` : "";
  $("previous").disabled = offset <= 0;
  $("next").disabled = offset + pageSize >= page.total;
}
function renderProfiles(data) {
  const profiles = data.result?.profiles || data.profiles || [];
  $("profile-total").textContent = String(data.result?.sourceContracts?.length || 13);
  const available = new Set(data.result?.availableProfiles || []);
  const root = $("profiles"); root.replaceChildren();
  for (const profile of profiles) {
    const card = document.createElement("article"); card.className = "profile-card";
    const name = document.createElement("strong"); name.textContent = profile.profile || profile.id || "Native Profile";
    const detail = document.createElement("span"); detail.textContent = `${profile.core || ""} · ${(profile.runtimeRequirements?.libraries || []).join(", ") || "native runtime"}`;
    const state = document.createElement("span"); state.className = "availability";
    state.textContent = available.has(profile.profile) ? translate("profileAvailable") : translate("profileUnavailable");
    card.append(name, detail, state); root.append(card);
  }
}
async function refreshAll() {
  if (!bearer) return;
  showError(""); setLoading(true); $("refresh").disabled = true;
  try {
    const [status, services, profiles] = await Promise.all([
      request("/v1/status"), request(`/v1/services/page?limit=${pageSize}&offset=${offset}`),
      request("/v1/rpc", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ method: "core.profiles", params: {} }) }),
    ]);
    renderStatus(status); renderServices(services); renderProfiles(profiles);
    $("refresh").disabled = false;
    $("disconnect").hidden = false;
  } catch (error) {
    showError(error instanceof Error ? error.message : translate("requestFailed"));
    $("refresh").disabled = false;
  } finally { setLoading(false); }
}

$("auth-form").addEventListener("submit", (event) => {
  event.preventDefault(); bearer = $("token").value.trim(); $("token").value = ""; offset = 0; refreshAll();
});
$("refresh").addEventListener("click", refreshAll);
$("disconnect").addEventListener("click", () => {
  bearer = ""; offset = 0; $("disconnect").hidden = true; $("refresh").disabled = true;
  $("service-total").textContent = "—"; $("profile-total").textContent = "—";
  $("status").className = "status-content empty-state"; $("status").textContent = translate("connectToView");
  $("services").replaceChildren(); $("profiles").replaceChildren();
  showError("");
});
$("previous").addEventListener("click", () => { offset = Math.max(0, offset - pageSize); refreshAll(); });
$("next").addEventListener("click", () => { if (offset + pageSize < totalServices) { offset += pageSize; refreshAll(); } });
$("language").addEventListener("click", () => { language = language === "zh" ? "en" : "zh"; applyLanguage(); });
applyLanguage();
