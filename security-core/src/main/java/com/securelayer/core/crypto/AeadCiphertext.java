package com.securelayer.core.crypto;

public record AeadCiphertext(byte[] nonce, byte[] ciphertext, byte[] associatedData) {
    public AeadCiphertext {
        nonce = nonce == null ? new byte[0] : nonce.clone();
        ciphertext = ciphertext == null ? new byte[0] : ciphertext.clone();
        associatedData = associatedData == null ? new byte[0] : associatedData.clone();
    }

    @Override
    public byte[] nonce() {
        return nonce.clone();
    }

    @Override
    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    @Override
    public byte[] associatedData() {
        return associatedData.clone();
    }
}
