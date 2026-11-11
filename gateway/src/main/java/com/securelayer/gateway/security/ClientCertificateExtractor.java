package com.securelayer.gateway.security;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import org.springframework.stereotype.Component;

@Component
public class ClientCertificateExtractor {
    private static final String JAKARTA_CERTIFICATE_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";
    private static final String LEGACY_CERTIFICATE_ATTRIBUTE = "javax.servlet.request.X509Certificate";

    public String extractPem(HttpServletRequest request, String certificateHeader) {
        Object certificates = request.getAttribute(JAKARTA_CERTIFICATE_ATTRIBUTE);
        if (certificates == null) {
            certificates = request.getAttribute(LEGACY_CERTIFICATE_ATTRIBUTE);
        }
        if (certificates instanceof X509Certificate[] chain && chain.length > 0) {
            return toPem(chain[0]);
        }

        String forwardedCertificate = request.getHeader(certificateHeader);
        if (forwardedCertificate == null || forwardedCertificate.isBlank()) {
            return null;
        }
        return URLDecoder.decode(forwardedCertificate, StandardCharsets.UTF_8);
    }

    private String toPem(X509Certificate certificate) {
        try {
            String encoded = java.util.Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                    .encodeToString(certificate.getEncoded());
            return "-----BEGIN CERTIFICATE-----\n" + encoded + "\n-----END CERTIFICATE-----\n";
        } catch (Exception ex) {
            throw new IllegalArgumentException("Unable to encode client certificate", ex);
        }
    }
}
