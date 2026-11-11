package com.securelayer.core.api;

import jakarta.validation.constraints.NotBlank;

public record CreateTenantRequest(@NotBlank String name) {
}
