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
@Table(name = "key_materials")
public class KeyMaterial {
    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(nullable = false)
    private String alias;

    @Column(nullable = false)
    private String algorithm;

    @Column(nullable = false)
    private String usage;

    @Column(nullable = false)
    private byte[] encryptedKey;

    @Column(nullable = false)
    private byte[] nonce;

    @Column(nullable = false)
    private int keyVersion = 1;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    protected KeyMaterial() {
    }

    public KeyMaterial(Tenant tenant, String alias, String algorithm, String usage, byte[] encryptedKey, byte[] nonce) {
        this.tenant = tenant;
        this.alias = alias;
        this.algorithm = algorithm;
        this.usage = usage;
        this.encryptedKey = encryptedKey.clone();
        this.nonce = nonce.clone();
    }

    public UUID getId() { return id; }
    public Tenant getTenant() { return tenant; }
    public String getAlias() { return alias; }
    public String getAlgorithm() { return algorithm; }
    public String getUsage() { return usage; }
    public byte[] getEncryptedKey() { return encryptedKey.clone(); }
    public byte[] getNonce() { return nonce.clone(); }
    public int getKeyVersion() { return keyVersion; }
    public boolean isEnabled() { return enabled; }
    public Instant getCreatedAt() { return createdAt; }
}
