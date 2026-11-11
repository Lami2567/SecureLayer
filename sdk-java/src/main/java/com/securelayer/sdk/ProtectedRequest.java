package com.securelayer.sdk;

import java.util.Map;

public record ProtectedRequest(
        String method,
        String path,
        Map<String, String> headers,
        byte[] body,
        String bodyHash,
        String signature,
        String requestId,
        String timestamp
) {}
