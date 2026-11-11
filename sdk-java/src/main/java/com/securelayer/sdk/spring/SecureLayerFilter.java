package com.securelayer.sdk.spring;

import com.securelayer.sdk.RequestVerificationResult;
import com.securelayer.sdk.SecureLayerClient;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import org.springframework.web.filter.OncePerRequestFilter;

public class SecureLayerFilter extends OncePerRequestFilter {
    public static final String VERIFICATION_ATTRIBUTE = "securelayer.verification";
    private final SecureLayerClient client;
    private final boolean enforce;

    public SecureLayerFilter(SecureLayerClient client) {
        this(client, false);
    }

    public SecureLayerFilter(SecureLayerClient client, boolean enforce) {
        this.client = client;
        this.enforce = enforce;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        Map<String, String> headers = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames != null) {
            while (headerNames.hasMoreElements()) {
                String name = headerNames.nextElement();
                headers.put(name.toLowerCase(), request.getHeader(name));
            }
        }

        // If request has SecureLayer headers, verify them
        if (headers.containsKey("x-request-id") && headers.containsKey("x-request-timestamp")) {
            String method = request.getMethod();
            String path = request.getRequestURI();

            // Perform verification
            RequestVerificationResult result = client.verifyRequest(method, path, headers, new byte[0]);
            request.setAttribute(VERIFICATION_ATTRIBUTE, result);

            if (enforce && !result.verified()) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":\"" + result.reason() + "\",\"code\":\"SECURELAYER_VERIFICATION_FAILED\"}");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
