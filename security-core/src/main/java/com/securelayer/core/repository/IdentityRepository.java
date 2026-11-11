package com.securelayer.core.repository;

import com.securelayer.core.domain.Identity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IdentityRepository extends JpaRepository<Identity, UUID> {
    Optional<Identity> findByTenantIdAndUsername(UUID tenantId, String username);

    List<Identity> findByTenantIdOrderByCreatedAtDesc(UUID tenantId);
}
