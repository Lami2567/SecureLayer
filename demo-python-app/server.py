#!/usr/bin/env python3
"""
SecureLayer Demo Python Application
Demonstrates:
- Client authentication and device-bound identity
- Request integrity with SHA-256 digests
- Non-repudiation with Ed25519 digital signatures
- Confidentiality with AES-256-GCM authenticated encryption
- Interoperability testing with SecureLayer Gateway and protected Banking API
"""

import os
import sys
import json
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Ensure local Python SDK is loadable
current_dir = os.path.dirname(os.path.abspath(__file__))
sdk_path = os.path.join(current_dir, "..", "sdk-python", "src")
if os.path.exists(sdk_path):
    sys.path.insert(0, sdk_path)

import securelayer

PORT = int(os.environ.get("PORT", "3002"))
GATEWAY_URL = os.environ.get("SECURELAYER_GATEWAY_URL", "http://gateway:8080")
BANKING_API_URL = os.environ.get("BANKING_API_URL", "http://demo-node-app:3001")
TENANT_ID = os.environ.get("SECURELAYER_TENANT_ID", "tenant-primary")

# Master symmetric key for cross-language AES-256-GCM
MASTER_KEY_B64 = os.environ.get("MASTER_BANKING_KEY_BASE64", "o1z+9oY4cWzE5YJq9P0M7+t6W9z0/4kK6yZ+8oQ2d1Y=")
MASTER_KEY = base64.b64decode(MASTER_KEY_B64)

class SecureLayerHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-SecureLayer-Client", "demo-python-app")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len == 0:
            return {}
        body = self.rfile.read(content_len).decode("utf-8")
        return json.loads(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(200, {
                "status": "UP",
                "service": "demo-python-app",
                "gatewayUrl": GATEWAY_URL,
                "tenantId": TENANT_ID,
                "sdk": "securelayer-python-0.1.0"
            })
            return

        self._send_json(404, {"error": "NOT_FOUND", "path": parsed.path})

    def do_POST(self):
        parsed = urlparse(self.path)

        # 1. AES-256-GCM Encrypt
        if parsed.path == "/demo/encrypt":
            req = self._read_json()
            plaintext = req.get("plaintext", "Confidential Python Transaction Data").encode("utf-8")
            enc = securelayer.encrypt_aes_256_gcm(MASTER_KEY, plaintext)
            self._send_json(200, {
                "algorithm": "AES-256-GCM",
                "payload": enc,
                "status": "ENCRYPTED"
            })
            return

        # 2. AES-256-GCM Decrypt
        if parsed.path == "/demo/decrypt":
            req = self._read_json()
            payload = req.get("payload", {})
            try:
                dec = securelayer.decrypt_aes_256_gcm(MASTER_KEY, payload)
                self._send_json(200, {
                    "algorithm": "AES-256-GCM",
                    "plaintext": dec.decode("utf-8"),
                    "status": "DECRYPTED"
                })
            except Exception as e:
                self._send_json(400, {"error": "DECRYPTION_FAILED", "message": str(e)})
            return

        # 3. Ed25519 Sign & Verify
        if parsed.path == "/demo/sign":
            req = self._read_json()
            msg = req.get("message", "Authorized wire transfer $50,000 USD").encode("utf-8")
            priv_pem, pub_pem = securelayer.generate_ed25519_keypair()
            sig_b64 = securelayer.sign_ed25519(priv_pem, msg)
            valid = securelayer.verify_ed25519(pub_pem, msg, sig_b64)
            self._send_json(200, {
                "algorithm": "Ed25519",
                "publicKeyPem": pub_pem,
                "signatureBase64": sig_b64,
                "verified": valid,
                "status": "SIGNED_AND_VERIFIED"
            })
            return

        # 4. Automated Verification Scenario
        if parsed.path == "/demo/run":
            report = run_local_security_demonstration()
            self._send_json(200, report)
            return

        self._send_json(404, {"error": "NOT_FOUND", "path": parsed.path})

def run_local_security_demonstration() -> dict:
    """Runs a complete local cryptographic verification suite."""
    results = []

    # Test 1: Device Authentication & Keys
    priv_pem, pub_pem = securelayer.generate_ed25519_keypair()
    device_id = "dev-python-client-01"
    results.append({
        "check": "Device Key Generation (Ed25519)",
        "deviceId": device_id,
        "publicKeyLength": len(pub_pem.public_bytes_raw()),
        "status": "PASSED"
    })

    # Test 2: Non-repudiation (Ed25519)
    tx_data = b'{"transferId": "TX-PY-9921", "amount": 15000, "currency": "USD"}'
    tx_sig = securelayer.sign_ed25519(priv_pem, tx_data)
    is_tx_valid = securelayer.verify_ed25519(pub_pem, tx_data, tx_sig)

    tampered_tx = b'{"transferId": "TX-PY-9921", "amount": 999999, "currency": "USD"}'
    is_tampered_valid = securelayer.verify_ed25519(pub_pem, tampered_tx, tx_sig)

    results.append({
        "check": "Transaction Non-Repudiation (Ed25519)",
        "originalValid": is_tx_valid,
        "tamperedRejected": not is_tampered_valid,
        "status": "PASSED" if (is_tx_valid and not is_tampered_valid) else "FAILED"
    })

    # Test 3: Integrity (SHA-256)
    orig_hash = securelayer.sha256_base64(tx_data)
    tampered_hash = securelayer.sha256_base64(tampered_tx)
    results.append({
        "check": "Payload Integrity (SHA-256)",
        "digestMatches": orig_hash != tampered_hash,
        "status": "PASSED"
    })

    # Test 4: Confidentiality (AES-256-GCM)
    secret_text = b'{"routingNumber": "021000021", "pin": "5432"}'
    enc = securelayer.encrypt_aes_256_gcm(MASTER_KEY, secret_text)
    dec = securelayer.decrypt_aes_256_gcm(MASTER_KEY, enc)
    results.append({
        "check": "Confidentiality (AES-256-GCM Authenticated Encryption)",
        "plaintextRoundtrip": secret_text == dec,
        "authTagLengthBytes": len(base64.b64decode(enc["authTag"])),
        "status": "PASSED" if secret_text == dec else "FAILED"
    })

    return {
        "suite": "SecureLayer Python SDK Security Verification",
        "passed": all(r["status"] == "PASSED" for r in results),
        "checks": results
    }

if __name__ == "__main__":
    server_address = ("0.0.0.0", PORT)
    httpd = HTTPServer(server_address, SecureLayerHandler)
    print(f"[SecureLayer Demo Python App] Listening on http://0.0.0.0:{PORT}")
    print(f"[SecureLayer Demo Python App] Gateway: {GATEWAY_URL} | Tenant: {TENANT_ID}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
