package com.securelayer.core.grpc;

import com.google.protobuf.MessageLite;
import com.securelayer.core.crypto.CryptoEngine;
import com.securelayer.core.crypto.CryptoResult;
import com.securelayer.core.crypto.ReplayCheck;
import io.grpc.ForwardingServerCallListener;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import java.time.Instant;
import java.util.Base64;
import net.devh.boot.grpc.server.interceptor.GrpcGlobalServerInterceptor;

@GrpcGlobalServerInterceptor
public class ProtocolSecurityInterceptor implements ServerInterceptor {
    static final Metadata.Key<String> REQUEST_ID_HEADER = Metadata.Key.of("x-request-id", Metadata.ASCII_STRING_MARSHALLER);
    static final Metadata.Key<String> TIMESTAMP_HEADER = Metadata.Key.of("x-request-timestamp", Metadata.ASCII_STRING_MARSHALLER);
    static final Metadata.Key<String> MESSAGE_HASH_HEADER = Metadata.Key.of("x-message-sha256", Metadata.ASCII_STRING_MARSHALLER);

    private final CryptoEngine cryptoEngine;

    public ProtocolSecurityInterceptor(CryptoEngine cryptoEngine) {
        this.cryptoEngine = cryptoEngine;
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call, Metadata headers,
            ServerCallHandler<ReqT, RespT> next) {
        String methodName = call.getMethodDescriptor().getFullMethodName();
        if (methodName.startsWith("grpc.health.v1.Health/") || methodName.startsWith("grpc.reflection.")) {
            return next.startCall(call, headers);
        }
        String requestId = headers.get(REQUEST_ID_HEADER);
        String timestamp = headers.get(TIMESTAMP_HEADER);
        if (requestId == null || requestId.isBlank() || timestamp == null || timestamp.isBlank()) {
            call.close(Status.INVALID_ARGUMENT.withDescription("x-request-id and x-request-timestamp are required"), new Metadata());
            return new ServerCall.Listener<>() {
            };
        }
        Instant issuedAt;
        try {
            issuedAt = Instant.parse(timestamp);
        } catch (RuntimeException ex) {
            call.close(Status.INVALID_ARGUMENT.withDescription("x-request-timestamp must be an ISO-8601 instant"), new Metadata());
            return new ServerCall.Listener<>() {
            };
        }
        CryptoResult<Void> freshness = cryptoEngine.verifyFreshRequest(new ReplayCheck(requestId, issuedAt));
        if (!freshness.success()) {
            call.close(Status.PERMISSION_DENIED.withDescription(freshness.error().message()), new Metadata());
            return new ServerCall.Listener<>() {
            };
        }
        String expectedHash = headers.get(MESSAGE_HASH_HEADER);
        ServerCall.Listener<ReqT> listener = next.startCall(call, headers);
        if (expectedHash == null || expectedHash.isBlank()) {
            return listener;
        }
        return new ForwardingServerCallListener.SimpleForwardingServerCallListener<>(listener) {
            @Override
            public void onMessage(ReqT message) {
                if (message instanceof MessageLite protobufMessage && !hashMatches(protobufMessage, expectedHash)) {
                    call.close(Status.PERMISSION_DENIED.withDescription("Message SHA-256 integrity check failed"), new Metadata());
                    return;
                }
                super.onMessage(message);
            }
        };
    }

    private boolean hashMatches(MessageLite message, String expectedBase64) {
        CryptoResult<byte[]> hash = cryptoEngine.sha256(message.toByteArray());
        if (!hash.success()) {
            return false;
        }
        byte[] expected;
        try {
            expected = Base64.getDecoder().decode(expectedBase64);
        } catch (IllegalArgumentException ex) {
            return false;
        }
        return java.security.MessageDigest.isEqual(hash.value(), expected);
    }
}
