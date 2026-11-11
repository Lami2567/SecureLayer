import base64
import json
import os
from typing import Any, Dict, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes, serialization


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')


def sha256_base64(data: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return base64.b64encode(digest.finalize()).decode('utf-8')


def encrypt_aes_256_gcm(key_bytes: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> Dict[str, str]:
    if len(key_bytes) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes")
    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(12)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    # in cryptography library, the tag (16 bytes) is appended at the end of ciphertext
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    return {
        "algorithm": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "authTag": base64.b64encode(tag).decode('utf-8'),
        "associatedData": base64.b64encode(associated_data).decode('utf-8') if associated_data else None
    }


def decrypt_aes_256_gcm(key_bytes: bytes, payload: Dict[str, str]) -> bytes:
    if len(key_bytes) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes")
    aesgcm = AESGCM(key_bytes)
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    tag = base64.b64decode(payload["authTag"])
    aad = base64.b64decode(payload["associatedData"]) if payload.get("associatedData") else None
    ciphertext_with_tag = ciphertext + tag
    return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)


def generate_ed25519_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign_ed25519(private_key: ed25519.Ed25519PrivateKey, data: bytes) -> str:
    signature = private_key.sign(data)
    return base64.b64encode(signature).decode('utf-8')


def verify_ed25519(public_key: ed25519.Ed25519PublicKey, data: bytes, signature_b64: str) -> bool:
    try:
        sig_bytes = base64.b64decode(signature_b64)
        public_key.verify(sig_bytes, data)
        return True
    except Exception:
        return False
