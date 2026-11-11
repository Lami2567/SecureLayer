package com.securelayer.gateway.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securelayer.gateway.config.SecureLayerProperties;
import com.securelayer.gateway.logging.SecurityEventLogger;
import com.securelayer.gateway.security.ClientCertificateExtractor;
import com.securelayer.gateway.security.RequestIntegrityService;
import com.securelayer.gateway.security.SecureLayerControlPlaneClient;
import com.securelayer.gateway.security.SecureLayerDecision;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.DelegatingServletInputStream;

class SecureLayerGatewayFilterTest {

    private SecureLayerProperties properties;
    private RequestIntegrityService integrityService;
    private ClientCertificateExtractor certificateExtractor;
    private SecureLayerControlPlaneClient controlPlaneClient;
    private SecurityEventLogger securityLogger;
    private SecureLayerGatewayFilter filter;

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

        filter = new SecureLayerGatewayFilter(
                properties,
                integrityService,
                certificateExtractor,
                controlPlaneClient,
                securityLogger,
                new ObjectMapper().findAndRegisterModules()
        );
    }

    @Test
    void allowsRequestAndInvokesFilterChainWhenPolicyAllows() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        when(request.getRequestURI()).thenReturn("/orders");
        when(request.getMethod()).thenReturn("GET");
        when(request.getInputStream()).thenReturn(new DelegatingServletInputStream(new ByteArrayInputStream(new byte[0])));

        when(integrityService.verify(any(), any(), any(), eq(true)))
                .thenReturn(RequestIntegrityService.IntegrityResult.verified("hash"));
        when(controlPlaneClient.evaluatePolicy(any()))
                .thenReturn(SecureLayerDecision.allow("default", 1));

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        verify(request).setAttribute(eq(SecureLayerGatewayFilter.DECISION_ATTRIBUTE), any());
    }

    @Test
    void blocksRequestWithoutInvokingFilterChainWhenPolicyDenies() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        StringWriter responseWriter = new StringWriter();

        when(request.getRequestURI()).thenReturn("/admin");
        when(request.getMethod()).thenReturn("POST");
        when(request.getInputStream()).thenReturn(new DelegatingServletInputStream(new ByteArrayInputStream(new byte[0])));
        when(response.getWriter()).thenReturn(new PrintWriter(responseWriter));

        when(integrityService.verify(any(), any(), any(), eq(true)))
                .thenReturn(RequestIntegrityService.IntegrityResult.verified("hash"));
        when(controlPlaneClient.evaluatePolicy(any()))
                .thenReturn(SecureLayerDecision.deny("Admin role required"));

        filter.doFilter(request, response, chain);

        verify(chain, never()).doFilter(any(), any());
        verify(response).setStatus(HttpServletResponse.SC_FORBIDDEN);
        assertThat(responseWriter.toString()).contains("POLICY_DENIED");
    }
}
