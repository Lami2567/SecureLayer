package com.securelayer.core.api;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Map;

public record CreatePolicyRequest(
        @NotBlank String name,
        @Min(1) int version,
        @NotNull Map<String, Object> document) {
}
