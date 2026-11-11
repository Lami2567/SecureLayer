package com.securelayer.core.repository;

import com.securelayer.core.domain.ApplicationRegistration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ApplicationRepository extends JpaRepository<ApplicationRegistration, UUID> {
    Optional<ApplicationRegistration> findByClientId(String clientId);

    Optional<ApplicationRegistration> findByTenantIdAndClientId(UUID tenantId, String clientId);

    List<ApplicationRegistration> findByTenantIdOrderByCreatedAtDesc(UUID tenantId);
}
