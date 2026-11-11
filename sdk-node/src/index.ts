export { SecureLayer, SecureLayerClient } from "./client.js";
export { SecureLayerHttpError, SecureLayerHttpTransport } from "./transport.js";
export {
  decryptAes256Gcm,
  encryptAes256Gcm,
  hmacSha256,
  resolveSymmetricKey,
  sha256,
  signEd25519,
  verifyEd25519,
  verifyHmacSha256,
} from "./crypto.js";
export { createEnvelope, protocolMetadata, SECURELAYER_PROTOCOL_VERSION } from "./protocol.js";
export { secureLayerMiddleware } from "./middleware.js";

export type {
  AuditEventInput,
  AuthenticateInput,
  AuthenticationResult,
  PolicyCheckInput,
  ProtectableRequest,
  ProtectedRequest,
  RegisterApplicationInput,
  RegisterDeviceInput,
  SecureLayerConfig,
  VerifyRequestOptions,
  VerifyRequestResult,
} from "./client.js";
export type {
  EncryptedPayload,
  SignOptions,
  SignatureResult,
  SymmetricKey,
  SymmetricKeyInput,
  VerifyOptions,
} from "./crypto.js";
export type { MiddlewareOptions, NodeHttpRequest, NodeHttpResponse } from "./middleware.js";
export type { HttpTransportOptions, SecureLayerTransport } from "./transport.js";
export type {
  Authentication,
  AuthorizeRequest,
  AuthorizeResponse,
  Integrity,
  Principal,
  ProtocolEnvelope,
  ProtocolSignature,
  RecordAuditEventRequest,
  RecordAuditEventResponse,
  RequestContext,
  SecurityDecision,
  TenantRef,
  ValidateCertificateRequest,
  ValidateCertificateResponse,
} from "./protocol.js";
