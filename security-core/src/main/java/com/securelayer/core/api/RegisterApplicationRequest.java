package com.securelayer.core.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import java.util.Set;

public record RegisterApplicationRequest(
        @NotBlank String name,
        @NotBlank String clientId,
        @Size(min = 32, max = 512) String clientSecret,
        @NotEmpty Set<String> redirectUris,
        @NotEmpty Set<String> scopes) {
}
