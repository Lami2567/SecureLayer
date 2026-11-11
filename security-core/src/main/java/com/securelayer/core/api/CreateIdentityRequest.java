package com.securelayer.core.api;

import com.securelayer.core.domain.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import java.util.Set;

public record CreateIdentityRequest(
        @NotBlank String username,
        @Email @NotBlank String email,
        @Size(min = 12, max = 256) String password,
        @NotEmpty Set<Role> roles) {
}
