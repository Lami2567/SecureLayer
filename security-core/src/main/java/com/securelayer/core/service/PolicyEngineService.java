package com.securelayer.core.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securelayer.core.crypto.SecureLayerCrypto;
import com.securelayer.core.domain.ApplicationRegistration;
import com.securelayer.core.domain.AuditEvent;
import com.securelayer.core.domain.CertificateRecord;
import com.securelayer.core.domain.Device;
import com.securelayer.core.domain.DeviceState;
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
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.DayOfWeek;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PolicyEngineService {
    private final TenantRepository tenants;
    private final IdentityRepository identities;
    private final DeviceRepository devices;
    private final ApplicationRepository applications;
    private final CertificateRepository certificates;
    private final PolicyRepository policies;
    private final AuditEventRepository auditEvents;
    private final CertificateAuthorityService certificateAuthority;
    private final SecureLayerCrypto crypto;
    private final ObjectMapper objectMapper;

    public PolicyEngineService(TenantRepository tenants, IdentityRepository identities, DeviceRepository devices,
            ApplicationRepository applications, CertificateRepository certificates, PolicyRepository policies,
            AuditEventRepository auditEvents, CertificateAuthorityService certificateAuthority, SecureLayerCrypto crypto,
            ObjectMapper objectMapper) {
        this.tenants = tenants;
        this.identities = identities;
        this.devices = devices;
        this.applications = applications;
        this.certificates = certificates;
        this.policies = policies;
        this.auditEvents = auditEvents;
        this.certificateAuthority = certificateAuthority;
        this.crypto = crypto;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public PolicyDecision evaluate(PolicyEvaluationRequest request) {
        String policyName = request.effectivePolicyName();
        Optional<Policy> activePolicy = policies.findFirstByTenantIdAndNameAndActiveTrueOrderByVersionDesc(request.tenantId(), policyName);
        if (activePolicy.isEmpty()) {
            PolicyDecision decision = PolicyDecision.deny(policyName, 0, "No active policy matched");
            auditDecision(request, decision);
            return decision;
        }
        Policy policy = activePolicy.get();
        try {
            EvaluationFacts facts = facts(request);
            PolicyDecision decision = evaluatePolicy(policy, request, facts);
            auditDecision(request, decision);
            return decision;
        } catch (Exception ex) {
            PolicyDecision decision = PolicyDecision.deny(policy.getName(), policy.getVersion(), "Policy evaluation failed");
            auditDecision(request, decision);
            return decision;
        }
    }

    @Transactional
    public PolicyDecision authorize(UUID tenantId, String policyName, Collection<String> principalScopes, String action, String resource) {
        return evaluate(new PolicyEvaluationRequest(tenantId, policyName, null, null, null, null, null, null,
                resource, action, Map.of(), principalScopes, Set.of(), null, null, null, Instant.now()));
    }

    @Transactional
    public PolicyDecision authorizeRegisteredDevice(UUID tenantId, String deviceIdentifier, X509Certificate certificate,
            String policyName, Collection<String> principalScopes, String action, String resource) {
        return evaluate(new PolicyEvaluationRequest(tenantId, policyName, null, null, null, deviceIdentifier, null, null,
                resource, action, Map.of(), principalScopes, Set.of(), null, certificate, null, Instant.now()));
    }

    private PolicyDecision evaluatePolicy(Policy policy, PolicyEvaluationRequest request, EvaluationFacts facts) throws Exception {
        JsonNode document = objectMapper.readTree(policy.getDocument());
        PolicyDecision legacy = evaluateLegacyPolicy(policy, request, document);
        if (legacy != null) {
            return legacy;
        }
        JsonNode rules = document.path("rules");
        if (!rules.isArray()) {
            return PolicyDecision.deny(policy.getName(), policy.getVersion(), "Policy has no rules");
        }
        for (JsonNode rule : rules) {
            if (conditionsMatch(rule.path("conditions"), request, facts)) {
                PolicyDecisionType decision = decisionType(rule.path("effect").asText("DENY"));
                return PolicyDecision.of(decision, policy.getName(), policy.getVersion(), reason(rule, decision));
            }
        }
        return PolicyDecision.deny(policy.getName(), policy.getVersion(), "No policy rule matched");
    }

    private PolicyDecision evaluateLegacyPolicy(Policy policy, PolicyEvaluationRequest request, JsonNode document) {
        JsonNode allow = document.path("allow");
        if (!allow.isArray()) {
            return null;
        }
        for (JsonNode rule : allow) {
            boolean actionMatches = matchesText(rule.path("action"), request.httpMethod());
            boolean resourceMatches = matchesText(rule.path("resource"), request.requestedResource());
            if (actionMatches && resourceMatches) {
                return PolicyDecision.of(PolicyDecisionType.ALLOW, policy.getName(), policy.getVersion(), "Legacy allow rule matched");
            }
        }
        return PolicyDecision.deny(policy.getName(), policy.getVersion(), "No legacy allow rule matched");
    }

    private boolean conditionsMatch(JsonNode conditions, PolicyEvaluationRequest request, EvaluationFacts facts) {
        if (conditions == null || conditions.isMissingNode() || conditions.isNull()) {
            return true;
        }
        return userMatches(conditions.path("user"), facts)
                && deviceMatches(conditions.path("device"), facts)
                && applicationMatches(conditions.path("application"), facts)
                && certificateMatches(conditions.path("certificate"), facts)
                && rolesMatch(conditions.path("roles"), facts)
                && matchesText(conditions.path("resource"), request.requestedResource())
                && methodsMatch(conditions.path("httpMethods"), request.httpMethod())
                && contextMatches(conditions.path("context"), request.requestContext())
                && timeMatches(conditions.path("time"), request.effectiveEvaluationTime())
                && ipMatches(conditions.path("ipNetworks"), request.ipAddress());
    }

    private boolean userMatches(JsonNode condition, EvaluationFacts facts) {
        if (condition.isMissingNode()) {
            return true;
        }
        if (condition.path("required").asBoolean(false) && facts.identity() == null) {
            return false;
        }
        if (condition.has("active") && condition.path("active").asBoolean() != facts.userActive()) {
            return false;
        }
        if (condition.hasNonNull("id") && (facts.identity() == null || !condition.path("id").asText().equals(facts.identity().getId().toString()))) {
            return false;
        }
        if (condition.hasNonNull("username") && (facts.identity() == null || !condition.path("username").asText().equals(facts.identity().getUsername()))) {
            return false;
        }
        return true;
    }

    private boolean deviceMatches(JsonNode condition, EvaluationFacts facts) {
        if (condition.isMissingNode()) {
            return true;
        }
        if (condition.path("registered").asBoolean(false) && facts.device() == null) {
            return false;
        }
        if (condition.has("active") && condition.path("active").asBoolean() != facts.deviceActive()) {
            return false;
        }
        if (condition.hasNonNull("state") && (facts.device() == null
                || !condition.path("state").asText().equals(facts.device().getState().name()))) {
            return false;
        }
        if (condition.hasNonNull("id") && (facts.device() == null || !condition.path("id").asText().equals(facts.device().getId().toString()))) {
            return false;
        }
        if (condition.hasNonNull("deviceIdentifier") && (facts.device() == null
                || !condition.path("deviceIdentifier").asText().equals(facts.device().getDeviceIdentifier()))) {
            return false;
        }
        return true;
    }

    private boolean applicationMatches(JsonNode condition, EvaluationFacts facts) {
        if (condition.isMissingNode()) {
            return true;
        }
        if (condition.path("required").asBoolean(false) && facts.application() == null) {
            return false;
        }
        if (condition.has("approved") && condition.path("approved").asBoolean() != facts.applicationApproved()) {
            return false;
        }
        if (condition.hasNonNull("clientId") && (facts.application() == null
                || !condition.path("clientId").asText().equals(facts.application().getClientId()))) {
            return false;
        }
        if (condition.hasNonNull("id") && (facts.application() == null
                || !condition.path("id").asText().equals(facts.application().getId().toString()))) {
            return false;
        }
        return true;
    }

    private boolean certificateMatches(JsonNode condition, EvaluationFacts facts) {
        if (condition.isMissingNode()) {
            return true;
        }
        if (condition.path("required").asBoolean(false) && facts.certificate() == null) {
            return false;
        }
        if (condition.has("valid") && condition.path("valid").asBoolean() != facts.certificateValid()) {
            return false;
        }
        if (condition.hasNonNull("status")) {
            String status = condition.path("status").asText();
            if (!status.equals(facts.certificateValid() ? "VALID" : "INVALID")) {
                return false;
            }
        }
        return true;
    }

    private boolean rolesMatch(JsonNode rolesCondition, EvaluationFacts facts) {
        if (rolesCondition.isMissingNode()) {
            return true;
        }
        Set<String> required = textSet(rolesCondition);
        if (required.isEmpty()) {
            return true;
        }
        return facts.roles().stream().anyMatch(required::contains);
    }

    private boolean methodsMatch(JsonNode methodsCondition, String method) {
        if (methodsCondition.isMissingNode()) {
            return true;
        }
        return textSet(methodsCondition).stream().anyMatch(candidate -> "*".equals(candidate) || candidate.equalsIgnoreCase(nullToEmpty(method)));
    }

    private boolean contextMatches(JsonNode condition, Map<String, Object> context) {
        if (condition.isMissingNode()) {
            return true;
        }
        Map<String, Object> safeContext = context == null ? Map.of() : context;
        var fields = condition.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> expected = fields.next();
            Object actual = safeContext.get(expected.getKey());
            if (actual == null || !expected.getValue().asText().equals(String.valueOf(actual))) {
                return false;
            }
        }
        return true;
    }

    private boolean timeMatches(JsonNode condition, Instant evaluatedAt) {
        if (condition.isMissingNode()) {
            return true;
        }
        ZoneId zone = ZoneId.of(condition.path("zone").asText("UTC"));
        ZonedDateTime dateTime = evaluatedAt.atZone(zone);
        JsonNode days = condition.path("daysOfWeek");
        if (days.isArray() && !textSet(days).contains(dateTime.getDayOfWeek().name())) {
            return false;
        }
        if (condition.hasNonNull("start") && dateTime.toLocalTime().isBefore(LocalTime.parse(condition.path("start").asText()))) {
            return false;
        }
        if (condition.hasNonNull("end") && dateTime.toLocalTime().isAfter(LocalTime.parse(condition.path("end").asText()))) {
            return false;
        }
        return true;
    }

    private boolean ipMatches(JsonNode networks, String ipAddress) {
        if (networks.isMissingNode()) {
            return true;
        }
        if (ipAddress == null || ipAddress.isBlank()) {
            return false;
        }
        return textSet(networks).stream().anyMatch(network -> ipInNetwork(ipAddress, network));
    }

    private boolean matchesText(JsonNode condition, String value) {
        if (condition.isMissingNode()) {
            return true;
        }
        return textSet(condition).stream().anyMatch(candidate -> globMatches(candidate, nullToEmpty(value)));
    }

    private Set<String> textSet(JsonNode node) {
        Set<String> values = new LinkedHashSet<>();
        if (node.isArray()) {
            node.forEach(value -> values.add(normalized(value.asText())));
        } else if (!node.isMissingNode() && !node.isNull()) {
            values.add(normalized(node.asText()));
        }
        return values;
    }

    private String normalized(String value) {
        return value == null ? "" : value.trim();
    }

    private boolean globMatches(String pattern, String value) {
        if ("*".equals(pattern)) {
            return true;
        }
        if (pattern.endsWith("/**")) {
            String prefix = pattern.substring(0, pattern.length() - 3);
            return value.equals(prefix) || value.startsWith(prefix + "/");
        }
        String regex = pattern.replace(".", "\\.").replace("*", ".*");
        return value.matches(regex);
    }

    private boolean ipInNetwork(String ipAddress, String network) {
        try {
            if (!network.contains("/")) {
                return ipAddress.equals(network);
            }
            String[] parts = network.split("/", 2);
            byte[] addressBytes = InetAddress.getByName(ipAddress).getAddress();
            byte[] networkBytes = InetAddress.getByName(parts[0]).getAddress();
            if (addressBytes.length != networkBytes.length) {
                return false;
            }
            int prefixLength = Integer.parseInt(parts[1]);
            int bitLength = addressBytes.length * 8;
            BigInteger address = new BigInteger(1, addressBytes);
            BigInteger networkAddress = new BigInteger(1, networkBytes);
            BigInteger mask = BigInteger.ONE.shiftLeft(bitLength).subtract(BigInteger.ONE)
                    .shiftRight(prefixLength).not().and(BigInteger.ONE.shiftLeft(bitLength).subtract(BigInteger.ONE));
            return address.and(mask).equals(networkAddress.and(mask));
        } catch (Exception ex) {
            return false;
        }
    }

    private EvaluationFacts facts(PolicyEvaluationRequest request) {
        Identity identity = resolveIdentity(request).orElse(null);
        Device device = resolveDevice(request).orElse(null);
        ApplicationRegistration application = resolveApplication(request).orElse(null);
        CertificateRecord certificate = resolveCertificate(request, device).orElse(null);
        Set<String> roles = new LinkedHashSet<>();
        if (identity != null) {
            identity.getRoles().stream().map(Role::name).forEach(roles::add);
        }
        if (request.userRoles() != null) {
            request.userRoles().forEach(role -> roles.add(role.replace("ROLE_", "")));
        }
        boolean userActive = identity != null && identity.isEnabled();
        boolean deviceActive = device != null && device.isEnabled() && device.getState() == DeviceState.ACTIVE;
        boolean applicationApproved = application != null && application.isEnabled();
        boolean certificateValid = certificate != null && !certificate.isRevoked()
                && !request.effectiveEvaluationTime().isBefore(certificate.getNotBefore())
                && request.effectiveEvaluationTime().isBefore(certificate.getNotAfter())
                && (device == null || certificate.getDevice() == null || certificate.getDevice().getId().equals(device.getId()));
        return new EvaluationFacts(identity, device, application, certificate, roles, userActive, deviceActive,
                applicationApproved, certificateValid);
    }

    private Optional<Identity> resolveIdentity(PolicyEvaluationRequest request) {
        if (request.userId() != null) {
            return identities.findById(request.userId()).filter(identity -> identity.getTenant().getId().equals(request.tenantId()));
        }
        if (request.username() != null && !request.username().isBlank()) {
            return identities.findByTenantIdAndUsername(request.tenantId(), request.username());
        }
        return Optional.empty();
    }

    private Optional<Device> resolveDevice(PolicyEvaluationRequest request) {
        if (request.deviceId() != null) {
            return devices.findById(request.deviceId()).filter(device -> device.getTenant().getId().equals(request.tenantId()));
        }
        if (request.deviceIdentifier() != null && !request.deviceIdentifier().isBlank()) {
            return devices.findByTenantIdAndDeviceIdentifier(request.tenantId(), request.deviceIdentifier());
        }
        return Optional.empty();
    }

    private Optional<ApplicationRegistration> resolveApplication(PolicyEvaluationRequest request) {
        if (request.applicationId() != null) {
            return applications.findById(request.applicationId())
                    .filter(application -> application.getTenant().getId().equals(request.tenantId()));
        }
        if (request.clientId() != null && !request.clientId().isBlank()) {
            return applications.findByTenantIdAndClientId(request.tenantId(), request.clientId());
        }
        return Optional.empty();
    }

    private Optional<CertificateRecord> resolveCertificate(PolicyEvaluationRequest request, Device device) {
        if (request.certificateFingerprintSha256() != null && !request.certificateFingerprintSha256().isBlank()) {
            return certificates.findByTenantIdAndFingerprintSha256(request.tenantId(), request.certificateFingerprintSha256());
        }
        if (request.deviceCertificate() != null) {
            String fingerprint = certificateAuthority.fingerprintSha256(request.deviceCertificate());
            return certificates.findByTenantIdAndFingerprintSha256(request.tenantId(), fingerprint);
        }
        if (device != null) {
            return certificates.findByDeviceIdAndRevokedFalse(device.getId()).stream().findFirst();
        }
        return Optional.empty();
    }

    private PolicyDecisionType decisionType(String value) {
        try {
            return PolicyDecisionType.valueOf(value.toUpperCase(Locale.ROOT));
        } catch (RuntimeException ex) {
            return PolicyDecisionType.DENY;
        }
    }

    private String reason(JsonNode rule, PolicyDecisionType decision) {
        return rule.path("reason").asText("Policy rule returned " + decision.name());
    }

    private void auditDecision(PolicyEvaluationRequest request, PolicyDecision decision) {
        tenants.findById(request.tenantId()).ifPresent(tenant -> {
            String subject = request.username() != null ? request.username() : nullToEmpty(request.userId());
            if (subject.isBlank()) {
                subject = "anonymous";
            }
            String resource = nullToEmpty(request.requestedResource());
            String payload = subject + ":policy-decision:" + resource + ":" + decision.decision() + ":"
                    + decision.policyName() + ":" + decision.policyVersion();
            byte[] hash = crypto.sha256(payload.getBytes(StandardCharsets.UTF_8));
            auditEvents.save(new AuditEvent(tenant, subject, "policy-decision", resource, hash, null));
        });
    }

    private String nullToEmpty(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private record EvaluationFacts(
            Identity identity,
            Device device,
            ApplicationRegistration application,
            CertificateRecord certificate,
            Set<String> roles,
            boolean userActive,
            boolean deviceActive,
            boolean applicationApproved,
            boolean certificateValid) {
    }
}
