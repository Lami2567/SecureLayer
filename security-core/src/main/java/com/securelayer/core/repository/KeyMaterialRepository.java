package com.securelayer.core.repository;

import com.securelayer.core.domain.KeyMaterial;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface KeyMaterialRepository extends JpaRepository<KeyMaterial, UUID> {
    Optional<KeyMaterial> findFirstByTenantIdAndAliasAndEnabledTrueOrderByKeyVersionDesc(UUID tenantId, String alias);

    List<KeyMaterial> findByTenantIdOrderByCreatedAtDesc(UUID tenantId);
}
