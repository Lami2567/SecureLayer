package com.securelayer.core.domain;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "applications")
public class ApplicationRegistration {
    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, unique = true)
    private String clientId;

    @Column(nullable = false)
    private String clientSecretHash;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "application_redirect_uris", joinColumns = @JoinColumn(name = "application_id"))
    @Column(name = "redirect_uri", nullable = false)
    private Set<String> redirectUris = new LinkedHashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "application_scopes", joinColumns = @JoinColumn(name = "application_id"))
    @Column(name = "scope", nullable = false)
    private Set<String> scopes = new LinkedHashSet<>();

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    protected ApplicationRegistration() {
    }

    public ApplicationRegistration(Tenant tenant, String name, String clientId, String clientSecretHash, Set<String> redirectUris, Set<String> scopes) {
        this.tenant = tenant;
        this.name = name;
        this.clientId = clientId;
        this.clientSecretHash = clientSecretHash;
        this.redirectUris = new LinkedHashSet<>(redirectUris);
        this.scopes = new LinkedHashSet<>(scopes);
    }

    public UUID getId() { return id; }
    public Tenant getTenant() { return tenant; }
    public String getName() { return name; }
    public String getClientId() { return clientId; }
    public Set<String> getRedirectUris() { return redirectUris; }
    public Set<String> getScopes() { return scopes; }
    public boolean isEnabled() { return enabled; }
    public Instant getCreatedAt() { return createdAt; }
}
