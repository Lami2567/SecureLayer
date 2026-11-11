import type { PolicyDecisionRecord, ProtectedApplication, RuntimeResponse, SecureLayerConfig } from "./types.js";

// DOM Element references
const badgeDecision = document.querySelector<HTMLSpanElement>("#badgeDecision")!;
const evalReason = document.querySelector<HTMLDivElement>("#evalReason")!;
const btnCheckTab = document.querySelector<HTMLButtonElement>("#btnCheckTab")!;
const btnValidateDevice = document.querySelector<HTMLButtonElement>("#btnValidateDevice")!;

const certStatusEl = document.querySelector<HTMLDivElement>("#certStatus")!;
const userSessionEl = document.querySelector<HTMLDivElement>("#userSession")!;
const deviceIdDisplay = document.querySelector<HTMLDivElement>("#deviceIdDisplay")!;

const controlPlaneInput = document.querySelector<HTMLInputElement>("#controlPlaneUrl")!;
const tenantInput = document.querySelector<HTMLInputElement>("#tenantId")!;
const usernameInput = document.querySelector<HTMLInputElement>("#username")!;
const tokenInput = document.querySelector<HTMLInputElement>("#token")!;

const btnLogin = document.querySelector<HTMLButtonElement>("#btnLogin")!;
const btnRegisterDevice = document.querySelector<HTMLButtonElement>("#btnRegisterDevice")!;
const btnLogout = document.querySelector<HTMLButtonElement>("#btnLogout")!;

const appListEl = document.querySelector<HTMLDivElement>("#appList")!;
const appCountEl = document.querySelector<HTMLSpanElement>("#appCount")!;
const auditListEl = document.querySelector<HTMLDivElement>("#auditList")!;
const btnClearAudit = document.querySelector<HTMLButtonElement>("#btnClearAudit")!;
const messageBox = document.querySelector<HTMLDivElement>("#messageBox")!;

// Event Listeners
btnLogin.addEventListener("click", () => {
  showMessage("Authenticating user session...", "info");
  void send({
    type: "LOGIN",
    controlPlaneUrl: controlPlaneInput.value.trim(),
    tenantId: tenantInput.value.trim(),
    username: usernameInput.value.trim() || undefined,
    token: tokenInput.value.trim(),
  }).then(handleResponse);
});

btnRegisterDevice.addEventListener("click", () => {
  showMessage("Generating Web Crypto keys & registering device...", "info");
  void send({ type: "REGISTER_DEVICE" }).then(handleResponse);
});

btnValidateDevice.addEventListener("click", () => {
  showMessage("Validating device certificate with control plane...", "info");
  void send({ type: "VALIDATE_DEVICE" }).then(handleResponse);
});

btnCheckTab.addEventListener("click", () => {
  showMessage("Evaluating policy on current tab...", "info");
  void send({ type: "CHECK_CURRENT_TAB" }).then((res) => {
    if (!res.ok) {
      showMessage(res.error ?? "Failed to evaluate current tab", "error");
      return;
    }
    if (res.decision) {
      renderDecision(res.decision);
      showMessage(`Evaluation complete: ${res.decision.decision}`, res.decision.allowed ? "success" : "error");
    } else if (res.detection && !res.detection.protected) {
      showMessage("Current tab is not a configured protected application", "info");
    }
    void refreshStatus();
  });
});

btnLogout.addEventListener("click", () => {
  showMessage("Clearing session...", "info");
  void send({ type: "LOGOUT" }).then(handleResponse);
});

btnClearAudit.addEventListener("click", () => {
  void send({ type: "CLEAR_AUDIT" }).then(handleResponse);
});

// Initial load
void refreshStatus();

async function refreshStatus(): Promise<void> {
  const res = await send({ type: "STATUS" });
  if (res.ok && res.status) {
    renderStatus(res.status);
  }
}

function handleResponse(response: RuntimeResponse): void {
  if (!response.ok) {
    showMessage(response.error ?? "Operation failed", "error");
    return;
  }
  if (response.status) {
    renderStatus(response.status);
    showMessage("Status updated successfully", "success");
  }
}

function renderStatus(status: SecureLayerConfig): void {
  controlPlaneInput.value = status.controlPlaneUrl ?? "";
  tenantInput.value = status.tenantId ?? "";
  usernameInput.value = status.username ?? "";
  tokenInput.value = status.token ?? "";

  // Device & Certificate Status
  certStatusEl.textContent = status.certificateStatus ?? "NOT_REGISTERED";
  certStatusEl.style.color = status.certificateStatus === "VALID" ? "#34d399" : (status.certificateStatus === "DENIED" ? "#f87171" : "#94a3b8");

  // User session
  userSessionEl.textContent = status.loggedIn ? `Active (${status.username || "User"})` : "Logged Out";
  userSessionEl.style.color = status.loggedIn ? "#60a5fa" : "#94a3b8";

  // Device Key & Identifier
  if (status.deviceIdentifier) {
    const shortId = status.deviceIdentifier.length > 20
      ? `${status.deviceIdentifier.slice(0, 10)}...${status.deviceIdentifier.slice(-8)}`
      : status.deviceIdentifier;
    deviceIdDisplay.textContent = shortId;
    deviceIdDisplay.title = status.deviceIdentifier;
  } else {
    deviceIdDisplay.textContent = "Not Registered (Generate via Button)";
  }

  // Decision Card
  renderDecision(status.lastDecision);

  // Protected Apps
  renderApps(status.protectedApplications ?? []);

  // Audit Events
  renderAudits(status.auditEvents ?? []);
}

function renderDecision(decision?: PolicyDecisionRecord): void {
  if (!decision) {
    badgeDecision.className = "badge badge-unknown";
    badgeDecision.textContent = "UNKNOWN";
    evalReason.textContent = "No protected application evaluated yet";
    return;
  }

  badgeDecision.className = decision.allowed ? "badge badge-allow" : "badge badge-deny";
  badgeDecision.textContent = decision.decision;
  evalReason.innerHTML = `<strong>${escapeHtml(decision.reason)}</strong><br><span style="opacity:0.7">${escapeHtml(decision.url)}</span>`;
}

function renderApps(apps: ProtectedApplication[]): void {
  appCountEl.textContent = String(apps.length);
  appListEl.innerHTML = "";

  if (apps.length === 0) {
    appListEl.innerHTML = `<div style="color:var(--text-muted);padding:4px;">No protected applications defined</div>`;
    return;
  }

  for (const app of apps) {
    const item = document.createElement("div");
    item.className = "app-item";
    item.innerHTML = `
      <div class="app-meta">
        <strong>${escapeHtml(app.displayName || app.applicationId)}</strong><br>
        <span class="app-pattern">${escapeHtml(app.originPattern)}</span>
      </div>
      <span style="font-size:10px;opacity:0.7;">${escapeHtml(app.policyName)}</span>
    `;
    appListEl.appendChild(item);
  }
}

function renderAudits(audits: SecureLayerConfig["auditEvents"]): void {
  auditListEl.innerHTML = "";
  if (!audits || audits.length === 0) {
    auditListEl.innerHTML = `<div style="color:var(--text-muted);padding:4px;">No recent security events</div>`;
    return;
  }

  for (const audit of audits.slice(0, 10)) {
    const time = new Date(audit.createdAt).toLocaleTimeString();
    const item = document.createElement("div");
    item.className = "audit-item";
    const outcomeColor = audit.outcome === "ALLOW" ? "#34d399" : (audit.outcome === "DENY" ? "#f87171" : "#94a3b8");
    item.innerHTML = `
      <div>
        <span style="color:var(--text-muted)">${escapeHtml(time)}</span>
        <span style="margin-left:4px">${escapeHtml(audit.action)}</span>
      </div>
      <span style="font-weight:bold;color:${outcomeColor}">${escapeHtml(audit.outcome)}</span>
    `;
    auditListEl.appendChild(item);
  }
}

function showMessage(text: string, type: "info" | "success" | "error"): void {
  messageBox.textContent = text;
  messageBox.style.display = "block";
  messageBox.style.borderColor = type === "error" ? "#ef4444" : (type === "success" ? "#10b981" : "#3b82f6");
  messageBox.style.color = type === "error" ? "#fca5a5" : (type === "success" ? "#86efac" : "#bfdbfe");

  window.setTimeout(() => {
    messageBox.style.display = "none";
  }, 4000);
}

function send(message: Record<string, unknown>): Promise<RuntimeResponse> {
  return new Promise((resolve) => chrome.runtime.sendMessage(message, resolve));
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
