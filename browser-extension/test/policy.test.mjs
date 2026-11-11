import assert from "node:assert/strict";
import test from "node:test";
import { requestPolicy, deny } from "../dist/api.js";
import { detectProtectedApplication } from "../dist/detection.js";

const TEST_APPLICATION = {
  originPattern: "https://bank.example.com/*",
  applicationId: "banking-web",
  policyName: "banking",
  displayName: "Core Retail Banking Portal",
};

test("Policy Request: denies access when user is not logged in", async () => {
  const config = {
    controlPlaneUrl: "https://securelayer.example.com",
    tenantId: "tenant-primary",
    loggedIn: false,
    token: undefined,
    deviceIdentifier: "device-unknown-999",
    certificateStatus: "VALID",
    protectedApplications: [TEST_APPLICATION],
    auditEvents: [],
  };

  const decision = await requestPolicy(config, TEST_APPLICATION, "https://bank.example.com/accounts");
  assert.equal(decision.decision, "DENY");
  assert.equal(decision.allowed, false);
  assert.match(decision.reason, /not authenticated/i);
});

test("Policy Request: denies access when device is unknown / not registered", async () => {
  const config = {
    controlPlaneUrl: "https://securelayer.example.com",
    tenantId: "tenant-primary",
    loggedIn: true,
    token: "valid-bearer-token",
    deviceIdentifier: undefined,
    certificateStatus: "NOT_REGISTERED",
    protectedApplications: [TEST_APPLICATION],
    auditEvents: [],
  };

  const decision = await requestPolicy(config, TEST_APPLICATION, "https://bank.example.com/accounts");
  assert.equal(decision.decision, "DENY");
  assert.equal(decision.allowed, false);
  assert.match(decision.reason, /untrusted or unregistered/i);
});

test("Policy Request: denies access when device certificate is DENIED or SUSPENDED", async () => {
  const config = {
    controlPlaneUrl: "https://securelayer.example.com",
    tenantId: "tenant-primary",
    loggedIn: true,
    token: "valid-bearer-token",
    deviceIdentifier: "dev-suspended-101",
    certificateStatus: "SUSPENDED",
    protectedApplications: [TEST_APPLICATION],
    auditEvents: [],
  };

  const decision = await requestPolicy(config, TEST_APPLICATION, "https://bank.example.com/accounts");
  assert.equal(decision.decision, "DENY");
  assert.equal(decision.allowed, false);
  assert.match(decision.reason, /SUSPENDED/);
});

test("Policy Request: evaluates to ALLOW when device is trusted and policy server approves", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url, options) => {
      assert.ok(String(url).includes("/api/v1/admin/tenants/tenant-primary/policy-evaluations"));
      const body = JSON.parse(options.body);
      assert.equal(body.policyName, "banking");
      assert.equal(body.deviceIdentifier, "dev-active-1001");
      assert.equal(body.clientId, "banking-web");
      assert.equal(body.requestedResource, "https://bank.example.com/accounts");

      return {
        ok: true,
        json: async () => ({
          allowed: true,
          decision: "ALLOW",
          reason: "Device dev-active-1001 authenticated and active under banking policy",
        }),
      };
    };

    const config = {
      controlPlaneUrl: "https://securelayer.example.com",
      tenantId: "tenant-primary",
      loggedIn: true,
      token: "valid-jwt-token",
      deviceIdentifier: "dev-active-1001",
      deviceId: "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      certificateStatus: "VALID",
      protectedApplications: [TEST_APPLICATION],
      auditEvents: [],
    };

    const decision = await requestPolicy(config, TEST_APPLICATION, "https://bank.example.com/accounts");
    assert.equal(decision.decision, "ALLOW");
    assert.equal(decision.allowed, true);
    assert.match(decision.reason, /authenticated and active/i);
    assert.equal(decision.applicationId, "banking-web");
    assert.equal(decision.deviceIdentifier, "dev-active-1001");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Policy Request: evaluates to DENY when policy engine rejects request", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      return {
        ok: true,
        json: async () => ({
          allowed: false,
          decision: "DENY",
          reason: "Policy rule banking-v1: Caller does not possess active device privileges",
        }),
      };
    };

    const config = {
      controlPlaneUrl: "https://securelayer.example.com",
      tenantId: "tenant-primary",
      loggedIn: true,
      token: "valid-jwt-token",
      deviceIdentifier: "dev-pending-2002",
      certificateStatus: "VALID",
      protectedApplications: [TEST_APPLICATION],
      auditEvents: [],
    };

    const decision = await requestPolicy(config, TEST_APPLICATION, "https://bank.example.com/accounts");
    assert.equal(decision.decision, "DENY");
    assert.equal(decision.allowed, false);
    assert.match(decision.reason, /does not possess active device privileges/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
