import { recordAudit, registerDevice, requestPolicy, validateDevice } from "./api.js";
import { ensureDeviceKey, publicJwk, publicJwkThumbprint, sha256Base64, signContext } from "./crypto.js";
import { DEFAULT_CONFIG } from "./defaults.js";
import { detectProtectedApplication } from "./detection.js";
import { clearSession, loadConfig, saveConfig } from "./storage.js";
import type { AuditRecord, PolicyDecisionRecord, RuntimeMessage, RuntimeResponse } from "./types.js";

chrome.runtime.onInstalled.addListener(() => {
  void (async () => {
    const current = await loadConfig();
    await saveConfig({
      ...DEFAULT_CONFIG,
      ...current,
      protectedApplications: current.protectedApplications?.length ? current.protectedApplications : DEFAULT_CONFIG.protectedApplications,
    });
  })();
});

// Automatically detect protected URLs when the user navigates tabs
chrome.tabs.onUpdated?.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && !tab.url.startsWith("chrome://")) {
    void detectAndEvaluate(tab.url, tabId);
  }
});

chrome.runtime.onMessage.addListener((message: RuntimeMessage, sender, sendResponse) => {
  void handleMessage(message, sender.tab?.id).then(sendResponse).catch((error: Error) => {
    sendResponse({ ok: false, error: error.message } satisfies RuntimeResponse);
  });
  return true;
});

async function handleMessage(message: RuntimeMessage, tabId?: number): Promise<RuntimeResponse> {
  switch (message.type) {
    case "STATUS":
      return { ok: true, status: await loadConfig() };
    case "LOGIN":
      return { ok: true, status: await saveConfig({
        controlPlaneUrl: message.controlPlaneUrl,
        tenantId: message.tenantId,
        username: message.username,
        token: message.token,
        loggedIn: Boolean(message.token),
      }) };
    case "LOGOUT":
      return { ok: true, status: await clearSession() };
    case "REGISTER_DEVICE":
      return { ok: true, status: await registerCurrentDevice() };
    case "VALIDATE_DEVICE": {
      const config = await loadConfig();
      const valResult = await validateDevice(config);
      const updated = await saveConfig({ certificateStatus: valResult.certificateStatus });
      return { ok: true, status: updated };
    }
    case "DETECT_PROTECTED_APPLICATION":
      return detectAndEvaluate(message.url ?? "", tabId);
    case "CHECK_CURRENT_TAB":
      return evaluateActiveTab();
    case "ADD_PROTECTED_APP": {
      if (!message.application) {
        return { ok: false, error: "Application details required" };
      }
      const config = await loadConfig();
      const apps = [...config.protectedApplications.filter(a => a.applicationId !== message.application!.applicationId), message.application];
      const updated = await saveConfig({ protectedApplications: apps });
      return { ok: true, status: updated };
    }
    case "REMOVE_PROTECTED_APP": {
      const config = await loadConfig();
      const apps = config.protectedApplications.filter(a => a.applicationId !== message.pattern && a.originPattern !== message.pattern);
      const updated = await saveConfig({ protectedApplications: apps });
      return { ok: true, status: updated };
    }
    case "CLEAR_AUDIT": {
      const updated = await saveConfig({ auditEvents: [] });
      return { ok: true, status: updated };
    }
    default:
      return { ok: false, error: `Unknown message type: ${message.type}` };
  }
}

async function registerCurrentDevice() {
  const config = await loadConfig();
  const keyPair = await ensureDeviceKey();
  const deviceIdentifier = await publicJwkThumbprint(keyPair);
  const registration = await registerDevice(config, deviceIdentifier, await publicJwk(keyPair));
  return saveConfig({
    deviceId: registration.deviceId,
    deviceIdentifier,
    certificateStatus: registration.certificateStatus,
    pemCertificate: registration.pemCertificate,
    certificateFingerprintSha256: registration.certificateFingerprintSha256,
    registeredAt: new Date().toISOString(),
  });
}

async function evaluateActiveTab(): Promise<RuntimeResponse> {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const activeTab = tabs[0];
  if (!activeTab || !activeTab.url) {
    return { ok: false, error: "No active browser tab found" };
  }
  return detectAndEvaluate(activeTab.url, activeTab.id);
}

async function detectAndEvaluate(url: string, tabId?: number): Promise<RuntimeResponse> {
  const config = await loadConfig();
  const detection = detectProtectedApplication(url, config.protectedApplications);
  if (!detection.protected || !detection.application) {
    updateBadge(undefined, tabId);
    return { ok: true, detection };
  }

  // Verify device status and certificate validity
  const certResult = await validateDevice(config);
  const withCertificate = await saveConfig({ certificateStatus: certResult.certificateStatus });

  // Evaluate policy on control plane (Default DENY)
  const decision = await requestPolicy(withCertificate, detection.application, url);

  // Cryptographically sign the audit payload using the non-extractable device key
  const auditPayload = {
    applicationId: detection.application.applicationId,
    decision: decision.decision,
    deviceIdentifier: withCertificate.deviceIdentifier,
    url,
    evaluatedAt: decision.evaluatedAt,
  };
  const keyPair = await ensureDeviceKey();
  const eventHash = await sha256Base64(JSON.stringify(auditPayload));
  const signature = await signContext(auditPayload, keyPair);

  // Transmit audit to control plane and store locally
  await recordAudit(withCertificate, decision, eventHash, signature).catch(() => undefined);
  await rememberDecision(decision, eventHash);
  await notifyDecision(decision, tabId);
  updateBadge(decision, tabId);

  return { ok: true, detection, decision };
}

async function rememberDecision(decision: PolicyDecisionRecord, eventHashBase64?: string): Promise<void> {
  const current = await loadConfig();
  const audit: AuditRecord = {
    id: crypto.randomUUID(),
    action: "browser-access-evaluation",
    resource: decision.url,
    outcome: decision.decision,
    createdAt: decision.evaluatedAt,
    eventHashBase64,
  };
  await saveConfig({
    lastDecision: decision,
    auditEvents: [audit, ...current.auditEvents].slice(0, 30),
  });
}

function updateBadge(decision?: PolicyDecisionRecord, tabId?: number): void {
  if (typeof chrome === "undefined" || !chrome.action) return;
  if (!decision) {
    chrome.action.setBadgeText({ text: "", ...(tabId ? { tabId } : {}) });
    return;
  }
  const text = decision.allowed ? "OK" : "DENY";
  const color = decision.allowed ? "#16a34a" : "#dc2626";
  chrome.action.setBadgeText({ text, ...(tabId ? { tabId } : {}) });
  chrome.action.setBadgeBackgroundColor({ color, ...(tabId ? { tabId } : {}) });
}

async function notifyDecision(decision: PolicyDecisionRecord, tabId?: number): Promise<void> {
  const title = decision.allowed ? "SecureLayer: Access ALLOWED" : "SecureLayer: Access DENIED";
  await chrome.notifications.create({
    type: "basic",
    iconUrl: "icons/icon-128.svg",
    title,
    message: `${decision.reason} (${decision.url})`,
  }).catch(() => undefined);

  if (tabId !== undefined) {
    await chrome.tabs.sendMessage(tabId, {
      type: "SECURELAYER_DECISION",
      decision,
    }).catch(() => undefined);
  }
}
