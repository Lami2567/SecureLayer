package com.securelayer.core.api;

import jakarta.validation.constraints.NotBlank;

public record StoreKeyRequest(
        @NotBlank String alias,
        @NotBlank String algorithm,
        @NotBlank String usage,
        @NotBlank String keyMaterialBase64) {
}
