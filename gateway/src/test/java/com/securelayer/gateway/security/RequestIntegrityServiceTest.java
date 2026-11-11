package com.securelayer.gateway.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

class RequestIntegrityServiceTest {
    private final RequestIntegrityService service = new RequestIntegrityService();

    @Test
    void verifiesMatchingSha256Header() {
        byte[] body = "hello".getBytes();
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("X-Message-Sha256")).thenReturn(service.sha256(body));

        RequestIntegrityService.IntegrityResult result = service.verify(request, body, "X-Message-Sha256", true);

        assertThat(result.verified()).isTrue();
        assertThat(result.provided()).isTrue();
        assertThat(result.hashBase64()).isEqualTo(service.sha256(body));
    }

    @Test
    void deniesMissingRequiredHeader() {
        HttpServletRequest request = mock(HttpServletRequest.class);

        RequestIntegrityService.IntegrityResult result = service.verify(request, new byte[0], "X-Message-Sha256", true);

        assertThat(result.verified()).isFalse();
        assertThat(result.reason()).isEqualTo("Missing request integrity header");
    }

    @Test
    void deniesTamperedBody() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("X-Message-Sha256")).thenReturn(service.sha256("hello".getBytes()));

        RequestIntegrityService.IntegrityResult result = service.verify(request, "tampered".getBytes(), "X-Message-Sha256", true);

        assertThat(result.verified()).isFalse();
        assertThat(result.reason()).isEqualTo("Request body hash mismatch");
    }

    @Test
    void deniesMalformedBase64HeaderWithoutThrowing() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("X-Message-Sha256")).thenReturn("not-base64");

        RequestIntegrityService.IntegrityResult result = service.verify(request, new byte[0], "X-Message-Sha256", true);

        assertThat(result.verified()).isFalse();
        assertThat(result.reason()).isEqualTo("Request integrity header is not valid base64");
    }
}
