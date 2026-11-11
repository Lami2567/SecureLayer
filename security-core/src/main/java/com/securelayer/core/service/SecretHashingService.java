package com.securelayer.core.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class SecretHashingService {
    private final PasswordEncoder passwordEncoder;

    public SecretHashingService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public String hash(String secret) {
        return passwordEncoder.encode(secret);
    }

    public boolean matches(String rawSecret, String storedHash) {
        return passwordEncoder.matches(rawSecret, storedHash);
    }
}
