package com.securelayer.core.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securelayer.core.crypto.SecureLayerCrypto;
import com.securelayer.core.domain.ApplicationRegistration;
import com.securelayer.core.domain.AuditEvent;
import com.securelayer.core.domain.CertificateRecord;
import com.securelayer.core.domain.Device;
import com.securelayer.core.domain.Identity;
import com.securelayer.core.domain.Policy;
import com.securelayer.core.domain.Role;
import com.securelayer.core.domain.Tenant;
import com.securelayer.core.repository.ApplicationRepository;
import com.securelayer.core.repository.AuditEventRepository;
import com.securelayer.core.repository.CertificateRepository;
import com.securelayer.core.repository.DeviceRepository;
import com.securelayer.core.repository.IdentityRepository;
import com.securelayer.core.repository.PolicyRepository;
import com.securelayer.core.repository.TenantRepository;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class PolicyEngineServiceTest {
    @Mock
    private TenantRepository tenants;
    @Mock
    private IdentityRepository identities;
    @Mock
    private DeviceRepository devices;
    @Mock
    private ApplicationRepository applications;
    @Mock
    private CertificateRepository certificates;
    @Mock
    private PolicyRepository policies;
    @Mock
    private AuditEventRepository auditEvents;
    @Mock
    private CertificateAuthorityService certificateAuthority;
    @Mock
    private SecureLayerCrypto crypto;

    private PolicyEngineService service;
    private Tenant tenant;
    private UUID tenantId;

    @BeforeEach
    void setUp() {
        service = new PolicyEngineService(tenants, identities, devices, applications, certificates, policies,
                auditEvents, certificateAuthority, crypto, new ObjectMapper());
        tenantId = UUID.randomUUID();
        tenant = new Tenant("acme");
        ReflectionTestUtils.setField(tenant, "id", tenantId);
        when(tenants.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(crypto.sha256(any())).thenReturn(new byte[] {1, 2, 3});
    }

    @Test
    void allowsWhenAllGenericConditionsMatch() {
        Identity identity = identity();
        Device device = device();
        ApplicationRegistration application = application();
        CertificateRecord certificate = certificate(device);
        Policy policy = new Policy(tenant, "default", 3, """
                {"rules":[{"effect":"ALLOW","conditions":{
                    "user":{"active":true},
                    "device":{"registered":true,"state":"ACTIVE"},
                    "application":{"approved":true},
                    "certificate":{"required":true,"valid":true},
                    "resource":"/banking/**",
                    "httpMethods":["GET"],
                    "roles":["ADMIN"],
                    "time":{"zone":"UTC","daysOfWeek":["FRIDAY"],"start":"09:00","end":"17:00"},
                    "ipNetworks":["10.0.0.0/8"],
                    "context":{"risk":"low"}
                }}]}
                """);
        when(policies.findFirstByTenantIdAndNameAndActiveTrueOrderByVersionDesc(tenantId, "default")).thenReturn(Optional.of(policy));
        when(identities.findByTenantIdAndUsername(tenantId, "alice")).thenReturn(Optional.of(identity));
        when(devices.findByTenantIdAndDeviceIdentifier(tenantId, "device-1")).thenReturn(Optional.of(device));
        when(applications.findByTenantIdAndClientId(tenantId, "banking-client")).thenReturn(Optional.of(application));
        when(certificates.findByTenantIdAndFingerprintSha256(tenantId, "cert-fp")).thenReturn(Optional.of(certificate));

        PolicyDecision decision = service.evaluate(new PolicyEvaluationRequest(tenantId, "default", null, "alice",
                null, "device-1", null, "banking-client", "/banking/accounts", "GET", Map.of("risk", "low"),
                Set.of(), Set.of(), "cert-fp", null, "10.2.3.4", Instant.parse("2026-10-09T12:00:00Z")));

        assertThat(decision.decision()).isEqualTo(PolicyDecisionType.ALLOW);
        assertThat(decision.allowed()).isTrue();
        assertThat(decision.policyVersion()).isEqualTo(3);
        verify(auditEvents).save(any(AuditEvent.class));
    }

    @Test
    void deniesByDefaultWhenNoActivePolicyExists() {
        when(policies.findFirstByTenantIdAndNameAndActiveTrueOrderByVersionDesc(tenantId, "missing")).thenReturn(Optional.empty());

        PolicyDecision decision = service.evaluate(new PolicyEvaluationRequest(tenantId, "missing", null, null,
                null, null, null, null, "/banking", "GET", Map.of(), Set.of(), Set.of(), null, null, null, Instant.now()));

        assertThat(decision.decision()).isEqualTo(PolicyDecisionType.DENY);
        assertThat(decision.allowed()).isFalse();
        verify(auditEvents).save(any(AuditEvent.class));
    }

    @Test
    void canRequireDeviceCertificateWithoutHardcodedApplicationLogic() {
        Policy policy = new Policy(tenant, "default", 1, """
                {"rules":[{"effect":"REQUIRE_DEVICE_CERTIFICATE","conditions":{
                    "resource":"/banking/**",
                    "httpMethods":["GET"],
                    "certificate":{"valid":false}
                }}]}
                """);
        when(policies.findFirstByTenantIdAndNameAndActiveTrueOrderByVersionDesc(tenantId, "default")).thenReturn(Optional.of(policy));

        PolicyDecision decision = service.evaluate(new PolicyEvaluationRequest(tenantId, "default", null, null,
                null, null, null, null, "/banking/accounts", "GET", Map.of(), Set.of(), Set.of(), null, null, null, Instant.now()));

        assertThat(decision.decision()).isEqualTo(PolicyDecisionType.REQUIRE_DEVICE_CERTIFICATE);
        assertThat(decision.allowed()).isFalse();
    }

    private Identity identity() {
        Identity identity = new Identity(tenant, "alice", "alice@example.com", "hash", Set.of(Role.ADMIN));
        ReflectionTestUtils.setField(identity, "id", UUID.randomUUID());
        return identity;
    }

    private Device device() {
        Device device = new Device(tenant, "Alice laptop", "device-1", null, "CN=device-1", "public-key-hash");
        ReflectionTestUtils.setField(device, "id", UUID.randomUUID());
        device.activate();
        return device;
    }

    private ApplicationRegistration application() {
        ApplicationRegistration application = new ApplicationRegistration(tenant, "Banking", "banking-client", "hash",
                Set.of("https://example.test/callback"), Set.of("banking:read"));
        ReflectionTestUtils.setField(application, "id", UUID.randomUUID());
        return application;
    }

    private CertificateRecord certificate(Device device) {
        CertificateRecord certificate = new CertificateRecord(tenant, device, "CN=device-1", "serial-1", "pem", "cert-fp",
                Instant.parse("2026-10-01T00:00:00Z"), Instant.parse("2026-12-01T00:00:00Z"));
        ReflectionTestUtils.setField(certificate, "id", UUID.randomUUID());
        return certificate;
    }
}
