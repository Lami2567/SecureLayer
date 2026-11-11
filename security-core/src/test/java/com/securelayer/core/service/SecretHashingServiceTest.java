package com.securelayer.core.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

class SecretHashingServiceTest {
    private final SecretHashingService hashing = new SecretHashingService(new BCryptPasswordEncoder(12));

    @Test
    void hashesSecretsWithoutKeepingPlaintext() {
        String hash = hashing.hash("correct horse battery staple");

        assertThat(hash).isNotEqualTo("correct horse battery staple");
        assertThat(hash).startsWith("$2");
        assertThat(hashing.matches("correct horse battery staple", hash)).isTrue();
        assertThat(hashing.matches("wrong secret", hash)).isFalse();
    }
}
