package com.securelayer.core.api;

import com.securelayer.core.domain.ApplicationRegistration;
import com.securelayer.core.domain.AuditEvent;
import com.securelayer.core.domain.CertificateRecord;
import com.securelayer.core.domain.Device;
import com.securelayer.core.domain.Identity;
import com.securelayer.core.domain.KeyMaterial;
import com.securelayer.core.domain.Policy;
import com.securelayer.core.domain.Tenant;
import com.securelayer.core.service.AdminService;
import com.securelayer.core.service.DeviceIdentityService;
import com.securelayer.core.service.PolicyDecision;
import com.securelayer.core.service.PolicyEngineService;
import com.securelayer.core.service.PolicyEvaluationRequest;
import jakarta.validation.Valid;
import java.util.Map;
import java.net.URI;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin")
public class AdminController {
    private final AdminService adminService;
    private final DeviceIdentityService deviceIdentityService;
    private final PolicyEngineService policyEngineService;

    public AdminController(AdminService adminService, DeviceIdentityService deviceIdentityService, PolicyEngineService policyEngineService) {
        this.adminService = adminService;
        this.deviceIdentityService = deviceIdentityService;
        this.policyEngineService = policyEngineService;
    }

    @PostMapping("/tenants")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    ResponseEntity<IdResponse> createTenant(@Valid @RequestBody CreateTenantRequest request) {
        Tenant tenant = adminService.createTenant(request);
        return created("/api/v1/admin/tenants/" + tenant.getId(), tenant.getId());
    }

    @PostMapping("/tenants/{tenantId}/identities")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN')")
    ResponseEntity<IdResponse> createIdentity(@PathVariable UUID tenantId, @Valid @RequestBody CreateIdentityRequest request) {
        Identity identity = adminService.createIdentity(tenantId, request);
        return created("/api/v1/admin/tenants/" + tenantId + "/identities/" + identity.getId(), identity.getId());
    }

    @PostMapping("/tenants/{tenantId}/devices")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN','SECURITY_OPERATOR')")
    ResponseEntity<IdResponse> createDevice(@PathVariable UUID tenantId, @Valid @RequestBody CreateDeviceRequest request) {
        Device device = adminService.createDevice(tenantId, request);
        return created("/api/v1/admin/tenants/" + tenantId + "/devices/" + device.getId(), device.getId());
    }

    @PostMapping("/tenants/{tenantId}/device-registrations")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN','SECURITY_OPERATOR')")
    ResponseEntity<DeviceRegistrationResponse> registerDevice(@PathVariable UUID tenantId, @Valid @RequestBody RegisterDeviceRequest request) {
        DeviceRegistrationResponse response = deviceIdentityService.register(tenantId, request);
        return ResponseEntity.created(URI.create("/api/v1/admin/tenants/" + tenantId + "/devices/" + response.deviceId())).body(response);
    }

    @PostMapping("/tenants/{tenantId}/devices/{deviceId}/certificate-rotations")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN','SECURITY_OPERATOR')")
    DeviceRegistrationResponse rotateDeviceCertificate(@PathVariable UUID tenantId, @PathVariable UUID deviceId,
            @Valid @RequestBody RotateDeviceCertificateRequest request) {
        return deviceIdentityService.rotateCertificate(tenantId, deviceId, request);
    }

    @PostMapping("/tenants/{tenantId}/devices/{deviceId}/suspend")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN','SECURITY_OPERATOR')")
    ResponseEntity<Void> suspendDevice(@PathVariable UUID tenantId, @PathVariable UUID deviceId) {
        deviceIdentityService.suspend(tenantId, deviceId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/tenants/{tenantId}/devices/{deviceId}/enable")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN','SECURITY_OPERATOR')")
    ResponseEntity<Void> enableDevice(@PathVariable UUID tenantId, @PathVariable UUID deviceId) {
        deviceIdentityService.enable(tenantId, deviceId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/tenants/{tenantId}/devices/{deviceId}/revoke")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN','SECURITY_OPERATOR')")
    ResponseEntity<Void> revokeDevice(@PathVariable UUID tenantId, @PathVariable UUID deviceId) {
        deviceIdentityService.revoke(tenantId, deviceId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/tenants/{tenantId}/device-certificate-validations")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN','SECURITY_OPERATOR')")
    DeviceAuthenticationResponse validateDeviceCertificate(@PathVariable UUID tenantId,
            @Valid @RequestBody ValidateDeviceCertificateRequest request) {
        return deviceIdentityService.validateCertificate(tenantId, request.deviceIdentifier(), request.pemCertificate());
    }

    @PostMapping("/tenants/{tenantId}/applications")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN','DEVELOPER')")
    ResponseEntity<IdResponse> registerApplication(@PathVariable UUID tenantId, @Valid @RequestBody RegisterApplicationRequest request) {
        ApplicationRegistration application = adminService.registerApplication(tenantId, request);
        return created("/api/v1/admin/tenants/" + tenantId + "/applications/" + application.getId(), application.getId());
    }

    @PostMapping("/tenants/{tenantId}/policies")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN','SECURITY_OPERATOR')")
    ResponseEntity<IdResponse> createPolicy(@PathVariable UUID tenantId, @Valid @RequestBody CreatePolicyRequest request) {
        Policy policy = adminService.createPolicy(tenantId, request);
        return created("/api/v1/admin/tenants/" + tenantId + "/policies/" + policy.getId(), policy.getId());
    }

    @PostMapping("/tenants/{tenantId}/policies/{name}/versions/{version}/activate")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN','SECURITY_OPERATOR')")
    PolicyResponse activatePolicy(@PathVariable UUID tenantId, @PathVariable String name, @PathVariable int version) {
        Policy policy = adminService.activatePolicyVersion(tenantId, name, version);
        return new PolicyResponse(policy.getId(), policy.getName(), policy.getVersion(), Map.of("active", policy.isActive()));
    }

    @PostMapping("/tenants/{tenantId}/policies/{name}/versions/{version}/deactivate")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN','SECURITY_OPERATOR')")
    PolicyResponse deactivatePolicy(@PathVariable UUID tenantId, @PathVariable String name, @PathVariable int version) {
        Policy policy = adminService.deactivatePolicyVersion(tenantId, name, version);
        return new PolicyResponse(policy.getId(), policy.getName(), policy.getVersion(), Map.of("active", policy.isActive()));
    }

    @PostMapping("/tenants/{tenantId}/policy-evaluations")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN','DEVELOPER','SECURITY_OPERATOR')")
    PolicyDecision evaluatePolicy(@PathVariable UUID tenantId, @Valid @RequestBody EvaluatePolicyRequest request) {
        return policyEngineService.evaluate(new PolicyEvaluationRequest(tenantId, request.policyName(), request.userId(),
                request.username(), request.deviceId(), request.deviceIdentifier(), request.applicationId(), request.clientId(),
                request.requestedResource(), request.httpMethod(), request.requestContext(), request.principalScopes(),
                request.userRoles(), request.certificateFingerprintSha256(), null, request.ipAddress(), request.evaluatedAt()));
    }

    @GetMapping("/tenants/{tenantId}/policies/{name}/active")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN','DEVELOPER','SECURITY_OPERATOR')")
    PolicyResponse activePolicy(@PathVariable UUID tenantId, @PathVariable String name) {
        return adminService.activePolicyResponse(tenantId, name);
    }

    @PostMapping("/tenants/{tenantId}/certificates")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN','SECURITY_OPERATOR')")
    ResponseEntity<IdResponse> importCertificate(@PathVariable UUID tenantId, @Valid @RequestBody ImportCertificateRequest request) {
        CertificateRecord certificate = adminService.importCertificate(tenantId, request);
        return created("/api/v1/admin/tenants/" + tenantId + "/certificates/" + certificate.getId(), certificate.getId());
    }

    @PostMapping("/tenants/{tenantId}/certificates/{certificateId}/revoke")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN','SECURITY_OPERATOR')")
    ResponseEntity<Void> revokeCertificate(@PathVariable UUID tenantId, @PathVariable UUID certificateId) {
        deviceIdentityService.revokeCertificate(tenantId, certificateId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/tenants/{tenantId}/keys")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN','SECURITY_OPERATOR')")
    ResponseEntity<IdResponse> storeKey(@PathVariable UUID tenantId, @Valid @RequestBody StoreKeyRequest request) {
        KeyMaterial key = adminService.storeKey(tenantId, request);
        return created("/api/v1/admin/tenants/" + tenantId + "/keys/" + key.getId(), key.getId());
    }

    @PostMapping("/tenants/{tenantId}/audit-events")
    @PreAuthorize("hasAnyRole('SUPER_ADMIN','ADMIN','SECURITY_OPERATOR')")
    ResponseEntity<IdResponse> recordAudit(@PathVariable UUID tenantId, @Valid @RequestBody RecordAuditRequest request) {
        AuditEvent auditEvent = adminService.recordAudit(tenantId, request);
        return created("/api/v1/admin/tenants/" + tenantId + "/audit-events/" + auditEvent.getId(), auditEvent.getId());
    }

    private ResponseEntity<IdResponse> created(String location, UUID id) {
        return ResponseEntity.created(URI.create(location)).body(new IdResponse(id));
    }
}
