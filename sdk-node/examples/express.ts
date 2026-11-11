import express from "express";
import { SecureLayer } from "@securelayer/sdk-node";

SecureLayer.initialize({
  tenantId: process.env.SECURELAYER_TENANT_ID!,
  gatewayUrl: process.env.SECURELAYER_GATEWAY_URL!,
  bearerToken: process.env.SECURELAYER_TOKEN,
  keys: {
    publicKeyPem: process.env.SECURELAYER_PUBLIC_KEY_PEM,
    privateKeyPem: process.env.SECURELAYER_PRIVATE_KEY_PEM,
    signingKeyId: "orders-api",
  },
});

const app = express();
app.use(express.json());

app.use(async (req, res, next) => {
  const verification = await SecureLayer.verifyRequest({
    method: req.method,
    path: req.path,
    headers: req.headers as Record<string, string | string[] | undefined>,
    body: req.body,
  });

  if (!verification.verified) {
    res.status(401).json({ error: verification.reason });
    return;
  }

  next();
});

app.get("/orders/:id", async (req, res) => {
  const decision = await SecureLayer.policyCheck({
    principal: {
      subject: req.header("x-user") ?? "anonymous",
      scopes: req.header("x-scopes")?.split(" ") ?? [],
    },
    action: req.method,
    resource: req.path,
    policyName: "orders",
    context: {
      httpMethod: req.method,
      ipAddress: req.ip,
      attributes: { orderId: req.params.id },
    },
  });

  if (!decision.allowed) {
    res.status(403).json({ error: decision.decision?.reason ?? "Denied by SecureLayer policy" });
    return;
  }

  await SecureLayer.auditEvent({
    principal: { subject: req.header("x-user") ?? "anonymous" },
    action: req.method,
    resource: req.path,
    outcome: "ALLOW",
  });

  res.json({ id: req.params.id, status: "protected" });
});

app.listen(3000);
