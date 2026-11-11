package com.securelayer.core.repository;

import com.securelayer.core.domain.Policy;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PolicyRepository extends JpaRepository<Policy, UUID> {
    Optional<Policy> findFirstByTenantIdAndNameAndActiveTrueOrderByVersionDesc(UUID tenantId, String name);

    Optional<Policy> findByTenantIdAndNameAndVersion(UUID tenantId, String name, int version);

    List<Policy> findByTenantIdAndName(UUID tenantId, String name);

    List<Policy> findByTenantIdOrderByCreatedAtDesc(UUID tenantId);
}
