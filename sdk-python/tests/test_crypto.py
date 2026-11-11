import unittest
import os
from securelayer.crypto import (
    canonical_json,
    sha256_base64,
    encrypt_aes_256_gcm,
    decrypt_aes_256_gcm,
    generate_ed25519_keypair,
    sign_ed25519,
    verify_ed25519,
)


class CryptoTestCase(unittest.TestCase):
    def test_canonical_json_and_sha256(self):
        data1 = {"b": 2, "a": 1}
        data2 = {"a": 1, "b": 2}
        self.assertEqual(canonical_json(data1), canonical_json(data2))
        hash1 = sha256_base64(canonical_json(data1))
        hash2 = sha256_base64(canonical_json(data2))
        self.assertEqual(hash1, hash2)

    def test_aes_256_gcm_encrypt_decrypt(self):
        key = os.urandom(32)
        plaintext = b"Sensitive payment transfer: $10,000"
        aad = b"tenant-id-123"

        encrypted = encrypt_aes_256_gcm(key, plaintext, associated_data=aad)
        self.assertEqual(encrypted["algorithm"], "AES-256-GCM")
        self.assertIsNotNone(encrypted["nonce"])
        self.assertIsNotNone(encrypted["ciphertext"])
        self.assertIsNotNone(encrypted["authTag"])

        decrypted = decrypt_aes_256_gcm(key, encrypted)
        self.assertEqual(decrypted, plaintext)

    def test_aes_256_gcm_tamper_detection(self):
        key = os.urandom(32)
        plaintext = b"Account balance: $500,000"
        encrypted = encrypt_aes_256_gcm(key, plaintext)

        tampered = dict(encrypted)
        tampered["authTag"] = "AAAA" + tampered["authTag"][4:]
        with self.assertRaises(Exception):
            decrypt_aes_256_gcm(key, tampered)

    def test_ed25519_sign_and_verify(self):
        private_key, public_key = generate_ed25519_keypair()
        message = b"Authorize wire transfer of $250.00"

        signature = sign_ed25519(private_key, message)
        self.assertTrue(verify_ed25519(public_key, message, signature))

        tampered_msg = b"Authorize wire transfer of $250000"
        self.assertFalse(verify_ed25519(public_key, tampered_msg, signature))


if __name__ == "__main__":
    unittest.main()
