import { SecureLayer, SecureLayerClient, type VerifyRequestOptions, type VerifyRequestResult } from "./client.js";

export interface NodeHttpRequest {
  method?: string;
  url?: string;
  originalUrl?: string;
  path?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  secureLayer?: VerifyRequestResult;
}

export interface NodeHttpResponse {
  statusCode: number;
  setHeader(name: string, value: string): void;
  end(chunk?: unknown): void;
}

export interface MiddlewareOptions extends VerifyRequestOptions {
  client?: SecureLayerClient;
  onFailure?: (reason: string, req: NodeHttpRequest, res: NodeHttpResponse) => void | Promise<void>;
}

/**
 * Express / Connect compatible middleware for incoming request verification.
 * Automatically verifies SecureLayer headers, body integrity hash, Ed25519 signatures, and clock skew.
 */
export function secureLayerMiddleware(options: MiddlewareOptions = {}) {
  return async (req: NodeHttpRequest, res: NodeHttpResponse, next: (err?: unknown) => void): Promise<void> => {
    try {
      const client = options.client ?? SecureLayer.client();
      const verification = await client.verifyRequest(
        {
          method: req.method,
          path: req.originalUrl || req.path || req.url || "/",
          headers: req.headers,
          body: req.body as any,
        },
        options,
      );

      if (!verification.verified) {
        const reason = verification.reason ?? "Request failed SecureLayer verification";
        if (options.onFailure) {
          await options.onFailure(reason, req, res);
          return;
        }

        res.statusCode = 401;
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            error: reason,
            code: "SECURELAYER_VERIFICATION_FAILED",
            envelope: verification.envelope,
          }),
        );
        return;
      }

      req.secureLayer = verification;
      next();
    } catch (err) {
      next(err);
    }
  };
}
