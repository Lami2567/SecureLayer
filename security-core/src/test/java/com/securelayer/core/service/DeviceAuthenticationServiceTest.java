package com.securelayer.core.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.securelayer.core.api.DeviceAuthenticationResponse;
import com.securelayer.core.domain.DeviceState;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class DeviceAuthenticationServiceTest {
    private final DeviceIdentityService deviceIdentityService = mock(DeviceIdentityService.class);
    private final DeviceAuthenticationService service = new DeviceAuthenticationService(deviceIdentityService);

    @Test
    void authenticatesOnlyThroughCertificateBoundIdentity() {
        UUID tenantId = UUID.randomUUID();
        UUID deviceId = UUID.randomUUID();
        X509Certificate certificate = mock(X509Certificate.class);
        when(deviceIdentityService.authenticate(tenantId, "device-1", certificate))
                .thenReturn(new DeviceAuthenticationResponse(true, deviceId, DeviceState.ACTIVE, "Authenticated", Instant.now().plusSeconds(3600)));

        DeviceAuthenticationResponse response = service.authenticate(tenantId, "device-1", certificate);

        assertThat(response.authenticated()).isTrue();
        assertThat(response.deviceId()).isEqualTo(deviceId);
        assertThat(response.state()).isEqualTo(DeviceState.ACTIVE);
    }
}
