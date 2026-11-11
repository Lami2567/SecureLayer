package com.securelayer.gateway.proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.securelayer.gateway.config.SecureLayerProperties;
import com.securelayer.gateway.error.ApiError;
import com.securelayer.gateway.logging.SecurityEventLogger;
import com.securelayer.gateway.security.ClientCertificateExtractor;
import com.securelayer.gateway.security.RequestIntegrityService;
import com.securelayer.gateway.security.SecureLayerControlPlaneClient;
import com.securelayer.gateway.security.SecureLayerDecision;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

class GatewayProxyControllerTest {

    private SecureLayerProperties properties;
    private RequestIntegrityService integrityService;
    private ClientCertificateExtractor certificateExtractor;
    private SecureLayerControlPlaneClient controlPlaneClient;
    private SecurityEventLogger securityLogger;
    private GatewayProxyController controller;

    @BeforeEach
    void setUp() {
        properties = new SecureLayerProperties(
                "test",
                new SecureLayerProperties.Security("https://issuer.example.com", "api"),
                new SecureLayerProperties.Audit(true, "SHA-256", "Ed25519"),
                new SecureLayerProperties.Gateway(true, "tenant-1", "test-policy", "http://localhost:9999",
                        true, false, "X-Message-Sha256", "X-SecureLayer-Client-Id",
                        "X-SecureLayer-Device-Id", "X-SecureLayer-Client-Certificate"),
                new SecureLayerProperties.ControlPlane("http://localhost:8081", "token")
        );

        integrityService = mock(RequestIntegrityService.class);
        certificateExtractor = mock(ClientCertificateExtractor.class);
        controlPlaneClient = mock(SecureLayerControlPlaneClient.class);
        securityLogger = mock(SecurityEventLogger.class);

        controller = new GatewayProxyController(
                properties,
                integrityService,
                certificateExtractor,
                controlPlaneClient,
                securityLogger
        );
    }

    @Test
    void deniesRequestWhenIntegrityCheckFails() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/banking/accounts");
        when(request.getMethod()).thenReturn("GET");

        when(integrityService.verify(any(), any(), any(), eq(true)))
                .thenReturn(RequestIntegrityService.IntegrityResult.failed("Hash mismatch"));

        ResponseEntity<?> response = controller.protectAndProxy(request, null, new byte[0]);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getBody()).isInstanceOf(ApiError.class);
        ApiError error = (ApiError) response.getBody();
        assertThat(error.code()).isEqualTo("REQUEST_INTEGRITY_FAILED");
    }

    @Test
    void deniesRequestByDefaultWhenPolicyDenies() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/banking/accounts");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeaderNames()).thenReturn(Collections.emptyEnumeration());

        when(integrityService.verify(any(), any(), any(), eq(true)))
                .thenReturn(RequestIntegrityService.IntegrityResult.verified("hash"));
        when(controlPlaneClient.evaluatePolicy(any()))
                .thenReturn(SecureLayerDecision.deny("Only active devices allowed"));

        ResponseEntity<?> response = controller.protectAndProxy(request, null, new byte[0]);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        ApiError error = (ApiError) response.getBody();
        assertThat(error.code()).isEqualTo("POLICY_DENIED");
        assertThat(error.message()).isEqualTo("Only active devices allowed");
    }

    @Test
    void deniesRequestWhenDeviceCertificateIsRequiredAndInvalid() throws Exception {
        SecureLayerProperties certProperties = new SecureLayerProperties(
                "test",
                properties.security(),
                properties.audit(),
                new SecureLayerProperties.Gateway(true, "tenant-1", "test-policy", "http://localhost:9999",
                        false, true, "X-Message-Sha256", "X-SecureLayer-Client-Id",
                        "X-SecureLayer-Device-Id", "X-SecureLayer-Client-Certificate"),
                properties.controlPlane()
        );

        GatewayProxyController certController = new GatewayProxyController(
                certProperties, integrityService, certificateExtractor, controlPlaneClient, securityLogger);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn("/banking/accounts");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("X-SecureLayer-Device-Id")).thenReturn("dev-1");
        when(certificateExtractor.extractPem(any(), any())).thenReturn("CERT_PEM");

        when(integrityService.verify(any(), any(), any(), eq(false)))
                .thenReturn(RequestIntegrityService.IntegrityResult.verified("hash"));
        when(controlPlaneClient.validateDeviceCertificate(eq("tenant-1"), eq("dev-1"), eq("CERT_PEM")))
                .thenReturn(new SecureLayerControlPlaneClient.CertificateValidation(false, "dev-1", "REVOKED", "Certificate revoked", null));

        ResponseEntity<?> response = certController.protectAndProxy(request, null, new byte[0]);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        ApiError error = (ApiError) response.getBody();
        assertThat(error.code()).isEqualTo("DEVICE_CERTIFICATE_DENIED");
    }
}
