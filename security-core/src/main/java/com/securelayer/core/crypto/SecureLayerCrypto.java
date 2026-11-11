package com.securelayer.core.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SecureRandom;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class SecureLayerCrypto {
    private static final String BC_PROVIDER = "BC";
    private static final int AES_256_BITS = 256;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_NONCE_BYTES = 12;

    private final SecureRandom secureRandom;

    public SecureLayerCrypto() {
        this(SecureRandomHolder.INSTANCE);
    }

    public SecureLayerCrypto(SecureRandom secureRandom) {
        ensureBouncyCastleProvider();
        this.secureRandom = secureRandom;
    }

    public SecretKey generateAes256Key() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES", BC_PROVIDER);
            generator.init(AES_256_BITS, secureRandom);
            return generator.generateKey();
        } catch (GeneralSecurityException ex) {
            throw new CryptoException("Unable to generate AES-256 key", ex);
        }
    }

    public AeadCiphertext encryptAes256Gcm(SecretKey key, byte[] plaintext, byte[] associatedData) {
        byte[] nonce = new byte[GCM_NONCE_BYTES];
        secureRandom.nextBytes(nonce);

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BC_PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            if (associatedData != null && associatedData.length > 0) {
                cipher.updateAAD(associatedData);
            }
            return new AeadCiphertext(nonce, cipher.doFinal(plaintext), associatedData == null ? new byte[0] : associatedData);
        } catch (GeneralSecurityException ex) {
            throw new CryptoException("Unable to encrypt payload with AES-256-GCM", ex);
        }
    }

    public byte[] decryptAes256Gcm(SecretKey key, AeadCiphertext value) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BC_PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, value.nonce()));
            if (value.associatedData() != null && value.associatedData().length > 0) {
                cipher.updateAAD(value.associatedData());
            }
            return cipher.doFinal(value.ciphertext());
        } catch (AEADBadTagException ex) {
            throw new CryptoException("Ciphertext authentication failed", ex);
        } catch (GeneralSecurityException ex) {
            throw new CryptoException("Unable to decrypt payload with AES-256-GCM", ex);
        }
    }

    public byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException("SHA-256 is unavailable", ex);
        }
    }

    public KeyPair generateEd25519KeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519", BC_PROVIDER);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException ex) {
            throw new CryptoException("Unable to generate Ed25519 key pair", ex);
        }
    }

    public byte[] signEd25519(KeyPair keyPair, byte[] message) {
        return signEd25519(keyPair.getPrivate(), message);
    }

    public byte[] signEd25519(PrivateKey privateKey, byte[] message) {
        try {
            Signature signature = Signature.getInstance("Ed25519", BC_PROVIDER);
            signature.initSign(privateKey, secureRandom);
            signature.update(message);
            return signature.sign();
        } catch (GeneralSecurityException ex) {
            throw new CryptoException("Unable to sign message with Ed25519", ex);
        }
    }

    public boolean verifyEd25519(KeyPair keyPair, byte[] message, byte[] detachedSignature) {
        return verifyEd25519(keyPair.getPublic(), message, detachedSignature);
    }

    public boolean verifyEd25519(PublicKey publicKey, byte[] message, byte[] detachedSignature) {
        try {
            Signature signature = Signature.getInstance("Ed25519", BC_PROVIDER);
            signature.initVerify(publicKey);
            signature.update(message);
            return signature.verify(detachedSignature);
        } catch (GeneralSecurityException ex) {
            throw new CryptoException("Unable to verify Ed25519 signature", ex);
        }
    }

    public SecretKey hmacSha256Key(byte[] key) {
        return new SecretKeySpec(key.clone(), "HmacSHA256");
    }

    public byte[] hmacSha256(SecretKey key, byte[] message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256", BC_PROVIDER);
            mac.init(key);
            return mac.doFinal(message);
        } catch (GeneralSecurityException ex) {
            throw new CryptoException("Unable to compute HMAC-SHA-256", ex);
        }
    }

    public boolean verifyHmacSha256(SecretKey key, byte[] message, byte[] expectedMac) {
        return MessageDigest.isEqual(hmacSha256(key, message), expectedMac);
    }

    public byte[] secureRandomBytes(int length) {
        if (length < 1) {
            throw new CryptoException("Random byte length must be positive");
        }
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    private static synchronized void ensureBouncyCastleProvider() {
        if (Security.getProvider(BC_PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static final class SecureRandomHolder {
        private static final SecureRandom INSTANCE = new SecureRandom();
    }
}
