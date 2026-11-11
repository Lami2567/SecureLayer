import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig, saveConfig, clearSession, resetMemoryStorageForTesting } from "../dist/storage.js";

test("Storage: loads default configuration when storage is empty", async () => {
  resetMemoryStorageForTesting();
  const config = await loadConfig();

  assert.equal(config.loggedIn, false);
  assert.equal(config.certificateStatus, "NOT_REGISTERED");
  assert.ok(Array.isArray(config.protectedApplications));
  assert.ok(config.protectedApplications.length > 0);
  assert.deepEqual(config.auditEvents, []);
});

test("Storage: saves and persists partial configuration updates", async () => {
  resetMemoryStorageForTesting();
  await saveConfig({
    controlPlaneUrl: "https://auth.bank.example.com",
    tenantId: "tenant-bank",
    token: "session-jwt-token-xyz",
    username: "alice@bank.example.com",
    loggedIn: true,
    deviceIdentifier: "dev-key-thumbprint-1234",
    certificateStatus: "VALID",
  });

  const reloaded = await loadConfig();
  assert.equal(reloaded.controlPlaneUrl, "https://auth.bank.example.com");
  assert.equal(reloaded.tenantId, "tenant-bank");
  assert.equal(reloaded.token, "session-jwt-token-xyz");
  assert.equal(reloaded.username, "alice@bank.example.com");
  assert.equal(reloaded.loggedIn, true);
  assert.equal(reloaded.certificateStatus, "VALID");
});

test("Storage: clearSession clears token and loggedIn state on logout", async () => {
  resetMemoryStorageForTesting();
  await saveConfig({
    token: "secret-token",
    loggedIn: true,
    deviceIdentifier: "persistent-device-id",
  });

  const cleared = await clearSession();
  assert.equal(cleared.token, undefined);
  assert.equal(cleared.loggedIn, false);
  // Device identity persists across logouts
  assert.equal(cleared.deviceIdentifier, "persistent-device-id");
});
