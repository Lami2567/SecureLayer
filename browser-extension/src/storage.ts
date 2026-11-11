import { DEFAULT_CONFIG } from "./defaults.js";
import type { SecureLayerConfig } from "./types.js";

const CONFIG_KEY = "secureLayerConfig";

export async function loadConfig(): Promise<SecureLayerConfig> {
  const stored = await chromeStorageGet(CONFIG_KEY);
  const config = stored[CONFIG_KEY];
  return {
    ...DEFAULT_CONFIG,
    ...config,
    protectedApplications: config?.protectedApplications ?? DEFAULT_CONFIG.protectedApplications,
    auditEvents: config?.auditEvents ?? [],
  };
}

export async function saveConfig(update: Partial<SecureLayerConfig>): Promise<SecureLayerConfig> {
  const current = await loadConfig();
  const next = {
    ...current,
    ...update,
  };
  await chromeStorageSet({ [CONFIG_KEY]: next });
  return next;
}

export async function clearSession(): Promise<SecureLayerConfig> {
  return saveConfig({
    token: undefined,
    loggedIn: false,
    lastDecision: undefined,
  });
}

let memoryStorage: Record<string, any> = {};

export function resetMemoryStorageForTesting(): void {
  memoryStorage = {};
}

function chromeStorageGet(key: string): Promise<Record<string, SecureLayerConfig | undefined>> {
  if (typeof chrome === "undefined" || !chrome?.storage?.local) {
    return Promise.resolve({ [key]: memoryStorage[key] });
  }
  return new Promise((resolve) => {
    (chrome.storage.local.get as (keys: string[], callback: (items: Record<string, SecureLayerConfig | undefined>) => void) => void)([key], resolve);
  });
}

function chromeStorageSet(values: Record<string, SecureLayerConfig>): Promise<void> {
  if (typeof chrome === "undefined" || !chrome?.storage?.local) {
    Object.assign(memoryStorage, values);
    return Promise.resolve();
  }
  return new Promise((resolve) => chrome.storage.local.set(values, () => resolve()));
}
