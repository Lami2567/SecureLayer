import { SecureLayer } from "@securelayer/sdk-node";

SecureLayer.initialize({
  tenantId: process.env.SECURELAYER_TENANT_ID!,
  gatewayUrl: process.env.SECURELAYER_GATEWAY_URL!,
  keys: {
    privateKeyPem: process.env.SECURELAYER_PRIVATE_KEY_PEM,
    publicKeyPem: process.env.SECURELAYER_PUBLIC_KEY_PEM,
    signingKeyId: "billing-worker",
  },
});

const protectedRequest = await SecureLayer.protectRequest({
  method: "POST",
  path: "/internal/reconcile",
  headers: { "content-type": "application/json" },
  body: { batchId: "batch_2026_10_11" },
});

const response = await fetch("https://internal.example.com/reconcile", {
  method: protectedRequest.request.method,
  headers: protectedRequest.request.headers,
  body: JSON.stringify(protectedRequest.request.body),
});

if (!response.ok) {
  throw new Error(`Request failed: ${response.status}`);
}
