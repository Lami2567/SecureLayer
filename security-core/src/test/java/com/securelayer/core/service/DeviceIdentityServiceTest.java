package com.securelayer.core.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.securelayer.core.api.DeviceAuthenticationResponse;
import com.securelayer.core.api.DeviceRegistrationResponse;
import com.securelayer.core.api.RegisterDeviceRequest;
import com.securelayer.core.crypto.SecureLayerCrypto;
import com.securelayer.core.domain.AuditEvent;
import com.securelayer.core.domain.CertificateRecord;
import com.securelayer.core.domain.Device;
import com.securelayer.core.domain.DeviceState;
import com.securelayer.core.domain.Tenant;
import com.securelayer.core.repository.AuditEventRepository;
import com.securelayer.core.repository.CertificateRepository;
import com.securelayer.core.repository.DeviceRepository;
import com.securelayer.core.repository.TenantRepository;
import java.io.StringWriter;
import java.security.KeyPair;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import javax.security.auth.x500.X500Principal;

class DeviceIdentityServiceTest {
    private final TenantRepository tenants = mock(TenantRepository.class);
    private final DeviceRepository devices = mock(DeviceRepository.class);
    private final CertificateRepository certificates = mock(CertificateRepository.class);
    private final AuditEventRepository auditEvents = mock(AuditEventRepository.class);
    private final SecureLayerCrypto crypto = new SecureLayerCrypto();
    private final CertificateAuthorityService certificateAuthority = new CertificateAuthorityService(crypto);
    private final DeviceIdentityService service = new DeviceIdentityService(
            tenants, devices, certificates, auditEvents, certificateAuthority, crypto);

    private final UUID tenantId = UUID.randomUUID();
    private final Tenant tenant = new Tenant("acme");

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(tenant, "id", tenantId);
        when(tenants.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(devices.save(any(Device.class))).thenAnswer(invocation -> {
            Device device = invocation.getArgument(0);
            ReflectionTestUtils.setField(device, "id", UUID.randomUUID());
            return device;
        });
        when(certificates.save(any(CertificateRecord.class))).thenAnswer(invocation -> {
            CertificateRecord certificate = invocation.getArgument(0);
            ReflectionTestUtils.setField(certificate, "id", UUID.randomUUID());
            return certificate;
        });
        when(auditEvents.save(any(AuditEvent.class))).thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void registrationIssuesActiveDeviceCertificate() throws Exception {
        KeyPair deviceKeyPair = crypto.generateEd25519KeyPair();

        DeviceRegistrationResponse response = service.register(tenantId,
                new RegisterDeviceRequest("Laptop", "device-1", csrPem(deviceKeyPair, "device-1")));

        assertThat(response.deviceId()).isNotNull();
        assertThat(response.certificateId()).isNotNull();
        assertThat(response.state()).isEqualTo(DeviceState.ACTIVE);
        assertThat(response.pemCertificate()).contains("BEGIN CERTIFICATE");
        assertThat(response.certificateFingerprintSha256()).isNotBlank();
        verify(auditEvents, atLeastOnce()).save(any(AuditEvent.class));
    }

    @Test
    void suspendedDeviceCannotAuthenticateWithValidCertificate() throws Exception {
        KeyPair deviceKeyPair = crypto.generateEd25519KeyPair();
        DeviceRegistrationResponse response = service.register(tenantId,
                new RegisterDeviceRequest("Laptop", "device-1", csrPem(deviceKeyPair, "device-1")));
        var certificate = certificateAuthority.parseCertificate(response.pemCertificate());
        Device suspended = new Device(tenant, "Laptop", "device-1", null, certificate.getSubjectX500Principal().getName(),
                certificateAuthority.publicKeySha256(certificate.getPublicKey()));
        ReflectionTestUtils.setField(suspended, "id", response.deviceId());
        suspended.suspend();
        CertificateRecord storedCertificate = new CertificateRecord(tenant, suspended, certificate.getSubjectX500Principal().getName(),
                certificate.getSerialNumber().toString(16), response.pemCertificate(), response.certificateFingerprintSha256(),
                certificate.getNotBefore().toInstant(), certificate.getNotAfter().toInstant());
        ReflectionTestUtils.setField(storedCertificate, "id", response.certificateId());
        when(devices.findByTenantIdAndDeviceIdentifier(tenantId, "device-1")).thenReturn(Optional.of(suspended));
        when(certificates.findByTenantIdAndFingerprintSha256(tenantId, response.certificateFingerprintSha256()))
                .thenReturn(Optional.of(storedCertificate));

        DeviceAuthenticationResponse authentication = service.authenticate(tenantId, "device-1", certificate);

        assertThat(authentication.authenticated()).isFalse();
        assertThat(authentication.state()).isEqualTo(DeviceState.SUSPENDED);
    }

    @Test
    void revokingDeviceRevokesActiveCertificates() {
        Device device = new Device(tenant, "Laptop", "device-1", null, "CN=device-1", "hash");
        ReflectionTestUtils.setField(device, "id", UUID.randomUUID());
        CertificateRecord certificate = new CertificateRecord(tenant, device, "CN=device-1", "01", "pem", "fingerprint",
                java.time.Instant.now(), java.time.Instant.now().plusSeconds(3600));
        when(devices.findById(device.getId())).thenReturn(Optional.of(device));
        when(certificates.findByDeviceIdAndRevokedFalse(device.getId())).thenReturn(List.of(certificate));

        service.revoke(tenantId, device.getId());

        assertThat(device.getState()).isEqualTo(DeviceState.REVOKED);
        assertThat(certificate.isRevoked()).isTrue();
    }

    private String csrPem(KeyPair keyPair, String commonName) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=" + commonName), keyPair.getPublic()).build(signer);
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(csr);
        }
        return writer.toString();
    }
}
