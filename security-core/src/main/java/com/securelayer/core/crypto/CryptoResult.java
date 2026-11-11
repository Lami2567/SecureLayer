package com.securelayer.core.crypto;

import java.util.Optional;

public record CryptoResult<T>(boolean success, T value, CryptoError error) {
    public static <T> CryptoResult<T> success(T value) {
        return new CryptoResult<>(true, value, null);
    }

    public static <T> CryptoResult<T> failure(CryptoErrorCode code, String message) {
        return new CryptoResult<>(false, null, new CryptoError(code, message));
    }

    public Optional<T> valueOptional() {
        return Optional.ofNullable(value);
    }

    public Optional<CryptoError> errorOptional() {
        return Optional.ofNullable(error);
    }
}
