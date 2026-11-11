package com.securelayer.core.service;

import com.securelayer.core.api.DeviceAuthenticationResponse;
import java.security.cert.X509Certificate;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DeviceAuthenticationService {
    private final DeviceIdentityService deviceIdentityService;

    public DeviceAuthenticationService(DeviceIdentityService deviceIdentityService) {
        this.deviceIdentityService = deviceIdentityService;
    }

    @Transactional
    public DeviceAuthenticationResponse authenticate(UUID tenantId, String deviceIdentifier, X509Certificate certificate) {
        return deviceIdentityService.authenticate(tenantId, deviceIdentifier, certificate);
    }
}
