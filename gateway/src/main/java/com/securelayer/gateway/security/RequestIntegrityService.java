package com.securelayer.gateway.security;

import jakarta.servlet.http.HttpServletRequest;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import org.springframework.stereotype.Service;

@Service
public class RequestIntegrityService {
    public IntegrityResult verify(HttpServletRequest request, byte[] body, String headerName, boolean required) {
        String expected = request.getHeader(headerName);
        if ((expected == null || expected.isBlank()) && required) {
            return IntegrityResult.failed("Missing request integrity header");
        }
        if (expected == null || expected.isBlank()) {
            return IntegrityResult.notProvided();
        }

        String actual = sha256(body == null ? new byte[0] : body);
        try {
            if (!MessageDigest.isEqual(Base64.getDecoder().decode(expected), Base64.getDecoder().decode(actual))) {
                return IntegrityResult.failed("Request body hash mismatch");
            }
        } catch (IllegalArgumentException ex) {
            return IntegrityResult.failed("Request integrity header is not valid base64");
        }
        return IntegrityResult.verified(actual);
    }

    public String sha256(byte[] bytes) {
        try {
            return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    public record IntegrityResult(boolean verified, boolean provided, String hashBase64, String reason) {
        public static IntegrityResult verified(String hashBase64) {
            return new IntegrityResult(true, true, hashBase64, null);
        }

        public static IntegrityResult notProvided() {
            return new IntegrityResult(true, false, null, null);
        }

        public static IntegrityResult failed(String reason) {
            return new IntegrityResult(false, true, null, reason);
        }
    }
}
