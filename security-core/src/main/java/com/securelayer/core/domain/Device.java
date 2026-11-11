package com.securelayer.core.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "devices")
public class Device {
    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String deviceIdentifier;

    @Column
    private String credentialHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private DeviceState state = DeviceState.PENDING;

    @Column(nullable = false)
    private String certificateSubject;

    @Column(nullable = false)
    private String publicKeySha256;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    private Instant lastSeenAt;

    protected Device() {
    }

    public Device(Tenant tenant, String name, String deviceIdentifier, String credentialHash) {
        this(tenant, name, deviceIdentifier, credentialHash, "", "");
    }

    public Device(Tenant tenant, String name, String deviceIdentifier, String credentialHash, String certificateSubject, String publicKeySha256) {
        this.tenant = tenant;
        this.name = name;
        this.deviceIdentifier = deviceIdentifier;
        this.credentialHash = credentialHash;
        this.certificateSubject = certificateSubject;
        this.publicKeySha256 = publicKeySha256;
    }

    public UUID getId() { return id; }
    public Tenant getTenant() { return tenant; }
    public String getName() { return name; }
    public String getDeviceIdentifier() { return deviceIdentifier; }
    public String getCredentialHash() { return credentialHash; }
    public DeviceState getState() { return state; }
    public String getCertificateSubject() { return certificateSubject; }
    public String getPublicKeySha256() { return publicKeySha256; }
    public boolean isEnabled() { return enabled; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getLastSeenAt() { return lastSeenAt; }

    public void activate() {
        this.enabled = true;
        this.state = DeviceState.ACTIVE;
    }

    public void suspend() {
        this.enabled = false;
        this.state = DeviceState.SUSPENDED;
    }

    public void enable() {
        if (state != DeviceState.REVOKED) {
            this.enabled = true;
            this.state = DeviceState.ACTIVE;
        }
    }

    public void revoke() {
        this.enabled = false;
        this.state = DeviceState.REVOKED;
    }
}
