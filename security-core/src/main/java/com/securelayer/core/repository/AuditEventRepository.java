package com.securelayer.core.repository;

import com.securelayer.core.domain.AuditEvent;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditEventRepository extends JpaRepository<AuditEvent, UUID> {
    List<AuditEvent> findTop100ByTenantIdOrderByCreatedAtDesc(UUID tenantId);
}
