package com.securelayer.core.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securelayer.core.api.CreateDeviceRequest;
import com.securelayer.core.api.CreateIdentityRequest;
import com.securelayer.core.api.CreatePolicyRequest;
import com.securelayer.core.api.CreateTenantRequest;
import com.securelayer.core.api.ImportCertificateRequest;
import com.securelayer.core.api.PolicyResponse;
import com.securelayer.core.api.RecordAuditRequest;
import com.securelayer.core.api.RegisterApplicationRequest;
import com.securelayer.core.api.StoreKeyRequest;
import com.securelayer.core.domain.ApplicationRegistration;
import com.securelayer.core.domain.AuditEvent;
import com.securelayer.core.domain.CertificateRecord;
import com.securelayer.core.domain.Device;
import com.securelayer.core.domain.Identity;
import com.securelayer.core.domain.KeyMaterial;
import com.securelayer.core.domain.Policy;
import com.securelayer.core.domain.Tenant;
import com.securelayer.core.repository.ApplicationRepository;
import com.securelayer.core.repository.AuditEventRepository;
import com.securelayer.core.repository.CertificateRepository;
import com.securelayer.core.repository.DeviceRepository;
import com.securelayer.core.repository.IdentityRepository;
import com.securelayer.core.repository.KeyMaterialRepository;
import com.securelayer.core.repository.PolicyRepository;
import com.securelayer.core.repository.TenantRepository;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AdminService {
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {
    };

    private final TenantRepository tenants;
    private final IdentityRepository identities;
    private final DeviceRepository devices;
    private final ApplicationRepository applications;
    private final PolicyRepository policies;
    private final CertificateRepository certificates;
    private final KeyMaterialRepository keyMaterials;
    private final AuditEventRepository auditEvents;
    private final SecretHashingService hashing;
    private final KeyEncryptionService keyEncryption;
    private final ObjectMapper objectMapper;

    public AdminService(TenantRepository tenants, IdentityRepository identities, DeviceRepository devices,
            ApplicationRepository applications, PolicyRepository policies, CertificateRepository certificates,
            KeyMaterialRepository keyMaterials, AuditEventRepository auditEvents, SecretHashingService hashing,
            KeyEncryptionService keyEncryption, ObjectMapper objectMapper) {
        this.tenants = tenants;
        this.identities = identities;
        this.devices = devices;
        this.applications = applications;
        this.policies = policies;
        this.certificates = certificates;
        this.keyMaterials = keyMaterials;
        this.auditEvents = auditEvents;
        this.hashing = hashing;
        this.keyEncryption = keyEncryption;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public Tenant createTenant(CreateTenantRequest request) {
        return tenants.save(new Tenant(request.name()));
    }

    @Transactional
    public Identity createIdentity(UUID tenantId, CreateIdentityRequest request) {
        Tenant tenant = tenant(tenantId);
        return identities.save(new Identity(tenant, request.username(), request.email(), hashing.hash(request.password()), request.roles()));
    }

    @Transactional
    public Device createDevice(UUID tenantId, CreateDeviceRequest request) {
        return devices.save(new Device(tenant(tenantId), request.name(), request.deviceIdentifier(), null));
    }

    @Transactional
    public ApplicationRegistration registerApplication(UUID tenantId, RegisterApplicationRequest request) {
        return applications.save(new ApplicationRegistration(tenant(tenantId), request.name(), request.clientId(),
                hashing.hash(request.clientSecret()), request.redirectUris(), request.scopes()));
    }

    @Transactional
    public Policy createPolicy(UUID tenantId, CreatePolicyRequest request) {
        try {
            return policies.save(new Policy(tenant(tenantId), request.name(), request.version(), objectMapper.writeValueAsString(request.document())));
        } catch (JsonProcessingException ex) {
            throw new IllegalArgumentException("Policy document must be valid JSON", ex);
        }
    }

    @Transactional
    public Policy activatePolicyVersion(UUID tenantId, String name, int version) {
        Policy target = policies.findByTenantIdAndNameAndVersion(tenantId, name, version)
                .orElseThrow(() -> new NotFoundException("Policy version not found"));
        policies.findByTenantIdAndName(tenantId, name).forEach(Policy::deactivate);
        target.activate();
        return target;
    }

    @Transactional
    public Policy deactivatePolicyVersion(UUID tenantId, String name, int version) {
        Policy target = policies.findByTenantIdAndNameAndVersion(tenantId, name, version)
                .orElseThrow(() -> new NotFoundException("Policy version not found"));
        target.deactivate();
        return target;
    }

    @Transactional(readOnly = true)
    public Policy activePolicy(UUID tenantId, String name) {
        return policies.findFirstByTenantIdAndNameAndActiveTrueOrderByVersionDesc(tenantId, name)
                .orElseThrow(() -> new NotFoundException("Active policy not found"));
    }

    @Transactional(readOnly = true)
    public PolicyResponse activePolicyResponse(UUID tenantId, String name) {
        Policy policy = activePolicy(tenantId, name);
        try {
            return new PolicyResponse(policy.getId(), policy.getName(), policy.getVersion(), objectMapper.readValue(policy.getDocument(), MAP_TYPE));
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Stored policy document is invalid", ex);
        }
    }

    @Transactional
    public CertificateRecord importCertificate(UUID tenantId, ImportCertificateRequest request) {
        return certificates.save(new CertificateRecord(tenant(tenantId), request.subject(), request.serialNumber(), request.pemCertificate(),
                request.notBefore(), request.notAfter()));
    }

    @Transactional
    public KeyMaterial storeKey(UUID tenantId, StoreKeyRequest request) {
        byte[] rawKey = Base64.getDecoder().decode(request.keyMaterialBase64());
        String aad = tenantId + ":" + request.alias();
        KeyEncryptionService.EncryptedKey encryptedKey = keyEncryption.encrypt(rawKey, aad);
        return keyMaterials.save(new KeyMaterial(tenant(tenantId), request.alias(), request.algorithm(), request.usage(),
                encryptedKey.ciphertext(), encryptedKey.nonce()));
    }

    @Transactional
    public AuditEvent recordAudit(UUID tenantId, RecordAuditRequest request) {
        byte[] hash = Base64.getDecoder().decode(request.eventHashBase64());
        byte[] signature = request.signatureBase64() == null || request.signatureBase64().isBlank()
                ? null : Base64.getDecoder().decode(request.signatureBase64());
        return auditEvents.save(new AuditEvent(tenant(tenantId), request.subject(), request.action(), request.resource(), hash, signature));
    }

    @Transactional
    public AuditEvent recordAudit(UUID tenantId, String subject, String action, String resource, byte[] hash, byte[] signature) {
        return auditEvents.save(new AuditEvent(tenant(tenantId), subject, action, resource, hash, signature));
    }

    private Tenant tenant(UUID tenantId) {
        return tenants.findById(tenantId).orElseThrow(() -> new NotFoundException("Tenant not found"));
    }
}
