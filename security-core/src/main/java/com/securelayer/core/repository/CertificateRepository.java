package com.securelayer.core.repository;

import com.securelayer.core.domain.CertificateRecord;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CertificateRepository extends JpaRepository<CertificateRecord, UUID> {
    Optional<CertificateRecord> findByTenantIdAndFingerprintSha256(UUID tenantId, String fingerprintSha256);

    List<CertificateRecord> findByDeviceIdAndRevokedFalse(UUID deviceId);

    List<CertificateRecord> findByTenantIdOrderByCreatedAtDesc(UUID tenantId);
}
