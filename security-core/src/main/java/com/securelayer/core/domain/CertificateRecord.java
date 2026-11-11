package com.securelayer.core.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "certificates")
public class CertificateRecord {
    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToOne
    @JoinColumn(name = "device_id")
    private Device device;

    @Column(nullable = false)
    private String subject;

    @Column(nullable = false)
    private String serialNumber;

    @Column(nullable = false)
    private String pemCertificate;

    @Column(nullable = false)
    private String fingerprintSha256;

    @Column(nullable = false)
    private Instant notBefore;

    @Column(nullable = false)
    private Instant notAfter;

    @Column(nullable = false)
    private boolean revoked;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    protected CertificateRecord() {
    }

    public CertificateRecord(Tenant tenant, String subject, String serialNumber, String pemCertificate, Instant notBefore, Instant notAfter) {
        this(tenant, null, subject, serialNumber, pemCertificate, "", notBefore, notAfter);
    }

    public CertificateRecord(Tenant tenant, Device device, String subject, String serialNumber, String pemCertificate,
            String fingerprintSha256, Instant notBefore, Instant notAfter) {
        this.tenant = tenant;
        this.device = device;
        this.subject = subject;
        this.serialNumber = serialNumber;
        this.pemCertificate = pemCertificate;
        this.fingerprintSha256 = fingerprintSha256;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }

    public UUID getId() { return id; }
    public Tenant getTenant() { return tenant; }
    public Device getDevice() { return device; }
    public String getSubject() { return subject; }
    public String getSerialNumber() { return serialNumber; }
    public String getPemCertificate() { return pemCertificate; }
    public String getFingerprintSha256() { return fingerprintSha256; }
    public Instant getNotBefore() { return notBefore; }
    public Instant getNotAfter() { return notAfter; }
    public boolean isRevoked() { return revoked; }
    public Instant getCreatedAt() { return createdAt; }

    public void revoke() {
        this.revoked = true;
    }
}
