package com.securelayer.core.repository;

import com.securelayer.core.domain.Device;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DeviceRepository extends JpaRepository<Device, UUID> {
    Optional<Device> findByTenantIdAndDeviceIdentifier(UUID tenantId, String deviceIdentifier);

    List<Device> findByTenantIdOrderByCreatedAtDesc(UUID tenantId);
}
