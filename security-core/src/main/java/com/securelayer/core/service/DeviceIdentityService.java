package com.securelayer.core.service;

import com.securelayer.core.api.DeviceAuthenticationResponse;
import com.securelayer.core.api.DeviceRegistrationResponse;
import com.securelayer.core.api.RegisterDeviceRequest;
import com.securelayer.core.api.RotateDeviceCertificateRequest;
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
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DeviceIdentityService {
    private final TenantRepository tenants;
    private final DeviceRepository devices;
    private final CertificateRepository certificates;
    private final AuditEventRepository auditEvents;
    private final CertificateAuthorityService certificateAuthority;
    private final SecureLayerCrypto crypto;

    public DeviceIdentityService(TenantRepository tenants, DeviceRepository devices, CertificateRepository certificates,
            AuditEventRepository auditEvents, CertificateAuthorityService certificateAuthority, SecureLayerCrypto crypto) {
        this.tenants = tenants;
        this.devices = devices;
        this.certificates = certificates;
        this.auditEvents = auditEvents;
        this.certificateAuthority = certificateAuthority;
        this.crypto = crypto;
    }

    @Transactional
    public DeviceRegistrationResponse register(UUID tenantId, RegisterDeviceRequest request) {
        Tenant tenant = tenant(tenantId);
        CertificateAuthorityService.DeviceCertificate issued = certificateAuthority.issueDeviceCertificate(
                request.certificateSigningRequestPem(), request.deviceIdentifier());
        String fingerprint = certificateAuthority.fingerprintSha256(issued.certificate());
        String publicKeyHash = certificateAuthority.publicKeySha256(issued.certificate().getPublicKey());
        Device device = devices.save(new Device(tenant, request.name(), request.deviceIdentifier(), null, issued.subject(), publicKeyHash));
        device.activate();
        CertificateRecord certificate = certificates.save(new CertificateRecord(tenant, device, issued.subject(), issued.serialNumber(),
                issued.pem(), fingerprint, issued.notBefore(), issued.notAfter()));
        audit(tenant, "device-registration", device.getId().toString(), "DEVICE_REGISTERED");
        audit(tenant, "certificate-issuance", certificate.getId().toString(), "DEVICE_CERTIFICATE_ISSUED");
        return response(device, certificate);
    }

    @Transactional
    public DeviceAuthenticationResponse authenticate(UUID tenantId, String deviceIdentifier, X509Certificate presentedCertificate) {
        if (presentedCertificate == null) {
            auditIfTenantExists(tenantId, "device-authentication", deviceIdentifier, "DEVICE_AUTHENTICATION_FAILED");
            return new DeviceAuthenticationResponse(false, null, null, "Client certificate is required", null);
        }
        Device device = devices.findByTenantIdAndDeviceIdentifier(tenantId, deviceIdentifier)
                .orElse(null);
        if (device == null) {
            auditIfTenantExists(tenantId, "device-authentication", deviceIdentifier, "DEVICE_AUTHENTICATION_FAILED");
            return new DeviceAuthenticationResponse(false, null, null, "Device is not registered", null);
        }
        if (!device.isEnabled() || device.getState() != DeviceState.ACTIVE) {
            audit(device.getTenant(), "device-authentication", device.getId().toString(), "DEVICE_AUTHENTICATION_FAILED");
            return new DeviceAuthenticationResponse(false, device.getId(), device.getState(), "Device is not active", null);
        }
        String fingerprint = certificateAuthority.fingerprintSha256(presentedCertificate);
        CertificateRecord certificate = certificates.findByTenantIdAndFingerprintSha256(tenantId, fingerprint).orElse(null);
        if (certificate == null || certificate.getDevice() == null || !certificate.getDevice().getId().equals(device.getId())) {
            audit(device.getTenant(), "device-authentication", device.getId().toString(), "DEVICE_AUTHENTICATION_FAILED");
            return new DeviceAuthenticationResponse(false, device.getId(), device.getState(), "Certificate is not bound to this device", null);
        }
        if (certificate.isRevoked()) {
            audit(device.getTenant(), "device-authentication", device.getId().toString(), "DEVICE_AUTHENTICATION_FAILED");
            return new DeviceAuthenticationResponse(false, device.getId(), device.getState(), "Certificate is revoked", certificate.getNotAfter());
        }
        Instant now = Instant.now();
        if (now.isBefore(certificate.getNotBefore()) || !now.isBefore(certificate.getNotAfter())) {
            audit(device.getTenant(), "device-authentication", device.getId().toString(), "DEVICE_AUTHENTICATION_FAILED");
            return new DeviceAuthenticationResponse(false, device.getId(), device.getState(), "Certificate is expired or not yet valid", certificate.getNotAfter());
        }
        String publicKeyHash = certificateAuthority.publicKeySha256(presentedCertificate.getPublicKey());
        if (!publicKeyHash.equals(device.getPublicKeySha256())) {
            audit(device.getTenant(), "device-authentication", device.getId().toString(), "DEVICE_AUTHENTICATION_FAILED");
            return new DeviceAuthenticationResponse(false, device.getId(), device.getState(), "Certificate public key does not match registered identity", certificate.getNotAfter());
        }
        audit(device.getTenant(), "device-authentication", device.getId().toString(), "DEVICE_AUTHENTICATED");
        return new DeviceAuthenticationResponse(true, device.getId(), device.getState(), "Authenticated", certificate.getNotAfter());
    }

    @Transactional
    public DeviceRegistrationResponse rotateCertificate(UUID tenantId, UUID deviceId, RotateDeviceCertificateRequest request) {
        Device device = device(deviceId);
        ensureTenant(tenantId, device);
        if (device.getState() != DeviceState.ACTIVE) {
            throw new IllegalStateException("Only active devices can rotate certificates");
        }
        certificates.findByDeviceIdAndRevokedFalse(deviceId).forEach(CertificateRecord::revoke);
        CertificateAuthorityService.DeviceCertificate issued = certificateAuthority.issueDeviceCertificate(
                request.certificateSigningRequestPem(), device.getDeviceIdentifier());
        String publicKeyHash = certificateAuthority.publicKeySha256(issued.certificate().getPublicKey());
        if (!publicKeyHash.equals(device.getPublicKeySha256())) {
            throw new IllegalArgumentException("Rotated certificate CSR must use the registered device key");
        }
        String fingerprint = certificateAuthority.fingerprintSha256(issued.certificate());
        CertificateRecord certificate = certificates.save(new CertificateRecord(device.getTenant(), device, issued.subject(), issued.serialNumber(),
                issued.pem(), fingerprint, issued.notBefore(), issued.notAfter()));
        audit(device.getTenant(), "certificate-rotation", certificate.getId().toString(), "DEVICE_CERTIFICATE_ROTATED");
        return response(device, certificate);
    }

    @Transactional
    public void suspend(UUID tenantId, UUID deviceId) {
        Device device = device(deviceId);
        ensureTenant(tenantId, device);
        device.suspend();
        audit(device.getTenant(), "device-suspend", device.getId().toString(), "DEVICE_SUSPENDED");
    }

    @Transactional
    public void enable(UUID tenantId, UUID deviceId) {
        Device device = device(deviceId);
        ensureTenant(tenantId, device);
        device.enable();
        audit(device.getTenant(), "device-enable", device.getId().toString(), "DEVICE_ENABLED");
    }

    @Transactional
    public void revoke(UUID tenantId, UUID deviceId) {
        Device device = device(deviceId);
        ensureTenant(tenantId, device);
        device.revoke();
        certificates.findByDeviceIdAndRevokedFalse(deviceId).forEach(CertificateRecord::revoke);
        audit(device.getTenant(), "device-revoke", device.getId().toString(), "DEVICE_REVOKED");
    }

    @Transactional
    public void revokeCertificate(UUID tenantId, UUID certificateId) {
        CertificateRecord certificate = certificates.findById(certificateId)
                .orElseThrow(() -> new NotFoundException("Certificate not found"));
        if (!certificate.getTenant().getId().equals(tenantId)) {
            throw new NotFoundException("Certificate not found");
        }
        certificate.revoke();
        audit(certificate.getTenant(), "certificate-revocation", certificate.getId().toString(), "DEVICE_CERTIFICATE_REVOKED");
    }

    @Transactional
    public boolean registeredActiveDeviceRequired(UUID tenantId, String deviceIdentifier, X509Certificate certificate) {
        return authenticate(tenantId, deviceIdentifier, certificate).authenticated();
    }

    @Transactional
    public DeviceAuthenticationResponse validateCertificate(UUID tenantId, String deviceIdentifier, String pemCertificate) {
        return authenticate(tenantId, deviceIdentifier, certificateAuthority.parseCertificate(pemCertificate));
    }

    private DeviceRegistrationResponse response(Device device, CertificateRecord certificate) {
        return new DeviceRegistrationResponse(device.getId(), certificate.getId(), device.getState(),
                certificate.getPemCertificate(), certificate.getFingerprintSha256(), certificate.getNotAfter());
    }

    private Tenant tenant(UUID tenantId) {
        return tenants.findById(tenantId).orElseThrow(() -> new NotFoundException("Tenant not found"));
    }

    private Device device(UUID deviceId) {
        return devices.findById(deviceId).orElseThrow(() -> new NotFoundException("Device not found"));
    }

    private void ensureTenant(UUID tenantId, Device device) {
        if (!device.getTenant().getId().equals(tenantId)) {
            throw new NotFoundException("Device not found");
        }
    }

    private void audit(Tenant tenant, String action, String resource, String subject) {
        byte[] hash = crypto.sha256((subject + ":" + action + ":" + resource).getBytes(StandardCharsets.UTF_8));
        auditEvents.save(new AuditEvent(tenant, subject, action, resource, hash, null));
    }

    private void auditIfTenantExists(UUID tenantId, String action, String resource, String subject) {
        tenants.findById(tenantId).ifPresent(tenant -> audit(tenant, action, resource, subject));
    }
}
