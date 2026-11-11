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
@Table(name = "audit_events")
public class AuditEvent {
    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(nullable = false)
    private String subject;

    @Column(nullable = false)
    private String action;

    @Column(nullable = false)
    private String resource;

    @Column(nullable = false)
    private byte[] eventHash;

    private byte[] signature;

    @Column(nullable = false)
    private String outcome = "RECORDED";

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    protected AuditEvent() {
    }

    public AuditEvent(Tenant tenant, String subject, String action, String resource, byte[] eventHash, byte[] signature) {
        this.tenant = tenant;
        this.subject = subject;
        this.action = action;
        this.resource = resource;
        this.eventHash = eventHash.clone();
        this.signature = signature == null ? null : signature.clone();
    }

    public UUID getId() { return id; }
    public Tenant getTenant() { return tenant; }
    public String getSubject() { return subject; }
    public String getAction() { return action; }
    public String getResource() { return resource; }
    public byte[] getEventHash() { return eventHash.clone(); }
    public byte[] getSignature() { return signature == null ? null : signature.clone(); }
    public String getOutcome() { return outcome; }
    public Instant getCreatedAt() { return createdAt; }
}
