package com.securelayer.core.grpc;

import com.securelayer.core.service.DeviceAuthenticationService;
import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.UUID;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLPeerUnverifiedException;
import net.devh.boot.grpc.server.interceptor.GrpcGlobalServerInterceptor;

@GrpcGlobalServerInterceptor
public class DeviceAuthenticationInterceptor implements ServerInterceptor {
    public static final Context.Key<UUID> TENANT_ID = Context.key("securelayerTenantId");
    public static final Context.Key<String> DEVICE_ID = Context.key("securelayerDeviceId");
    private static final Metadata.Key<String> TENANT_HEADER = Metadata.Key.of("x-tenant-id", Metadata.ASCII_STRING_MARSHALLER);
    private static final Metadata.Key<String> DEVICE_HEADER = Metadata.Key.of("x-device-id", Metadata.ASCII_STRING_MARSHALLER);

    private final DeviceAuthenticationService authenticationService;

    public DeviceAuthenticationInterceptor(DeviceAuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call, Metadata headers,
            ServerCallHandler<ReqT, RespT> next) {
        String methodName = call.getMethodDescriptor().getFullMethodName();
        if (methodName.startsWith("grpc.health.v1.Health/") || methodName.startsWith("grpc.reflection.")) {
            return next.startCall(call, headers);
        }
        String tenant = headers.get(TENANT_HEADER);
        String device = headers.get(DEVICE_HEADER);
        X509Certificate certificate = peerCertificate(call);
        if (tenant == null || device == null || certificate == null) {
            call.close(Status.UNAUTHENTICATED.withDescription("mTLS device certificate, tenant id, and device id are required"), new Metadata());
            return new ServerCall.Listener<>() {
            };
        }
        UUID tenantId;
        try {
            tenantId = UUID.fromString(tenant);
        } catch (IllegalArgumentException ex) {
            call.close(Status.UNAUTHENTICATED.withDescription("Invalid tenant identifier"), new Metadata());
            return new ServerCall.Listener<>() {
            };
        }
        var authentication = authenticationService.authenticate(tenantId, device, certificate);
        if (!authentication.authenticated()) {
            call.close(Status.UNAUTHENTICATED.withDescription(authentication.reason()), new Metadata());
            return new ServerCall.Listener<>() {
            };
        }
        Context context = Context.current().withValue(TENANT_ID, tenantId).withValue(DEVICE_ID, device);
        return Contexts.interceptCall(context, call, headers, next);
    }

    private <ReqT, RespT> X509Certificate peerCertificate(ServerCall<ReqT, RespT> call) {
        SSLSession sslSession = call.getAttributes().get(Grpc.TRANSPORT_ATTR_SSL_SESSION);
        if (sslSession == null) {
            return null;
        }
        try {
            Certificate[] certificates = sslSession.getPeerCertificates();
            if (certificates.length > 0 && certificates[0] instanceof X509Certificate certificate) {
                return certificate;
            }
        } catch (SSLPeerUnverifiedException ex) {
            return null;
        }
        return null;
    }
}
