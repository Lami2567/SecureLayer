import assert from "node:assert/strict";
import test from "node:test";
import { detectProtectedApplication, matchesPattern } from "../dist/detection.js";

test("matches protected URL patterns", () => {
  assert.equal(matchesPattern("https://bank.example.com/accounts", "https://bank.example.com/*"), true);
  assert.equal(matchesPattern("https://news.example.com/accounts", "https://bank.example.com/*"), false);
});

test("detects protected applications", () => {
  const result = detectProtectedApplication("https://bank.example.com/accounts", [
    {
      originPattern: "https://bank.example.com/*",
      applicationId: "banking-web",
      policyName: "banking",
      displayName: "Banking",
    },
  ]);

  assert.equal(result.protected, true);
  assert.equal(result.application.applicationId, "banking-web");
});

test("returns unprotected when no application matches", () => {
  const result = detectProtectedApplication("https://example.com", []);
  assert.equal(result.protected, false);
});
