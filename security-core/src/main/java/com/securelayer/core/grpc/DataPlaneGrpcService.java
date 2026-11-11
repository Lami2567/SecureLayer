package com.securelayer.core.grpc;

import com.securelayer.core.service.PolicyDecision;
import com.securelayer.core.service.PolicyEngineService;
import com.securelayer.proto.v1.AuthorizeRequest;
import com.securelayer.proto.v1.AuthorizeResponse;
import com.securelayer.proto.v1.DataPlaneServiceGrpc;
import com.securelayer.proto.v1.SecurityDecision;
import com.securelayer.proto.v1.SecurityDecisionType;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.util.UUID;
import net.devh.boot.grpc.server.service.GrpcService;

@GrpcService
public class DataPlaneGrpcService extends DataPlaneServiceGrpc.DataPlaneServiceImplBase {
    private final PolicyEngineService policyEngine;

    public DataPlaneGrpcService(PolicyEngineService policyEngine) {
        this.policyEngine = policyEngine;
    }

    @Override
    public void authorize(AuthorizeRequest request, StreamObserver<AuthorizeResponse> responseObserver) {
        try {
            UUID tenantId = UUID.fromString(request.getTenant().getTenantId());
            PolicyDecision decision = policyEngine.authorize(tenantId, "default", request.getPrincipal().getScopesList(),
                    request.getAction(), request.getResource());
            responseObserver.onNext(AuthorizeResponse.newBuilder()
                    .setAllowed(decision.allowed())
                    .setPolicyName(decision.policyName())
                    .setPolicyVersion(decision.policyVersion())
                    .setDecision(SecurityDecision.newBuilder()
                            .setAllowed(decision.allowed())
                            .setDecision(mapDecision(decision.decision()))
                            .setPolicyName(decision.policyName())
                            .setPolicyVersion(decision.policyVersion())
                            .setReason(decision.reason() == null ? "" : decision.reason())
                            .build())
                    .build());
            responseObserver.onCompleted();
        } catch (Exception ex) {
            responseObserver.onError(Status.PERMISSION_DENIED.withDescription(ex.getMessage()).asRuntimeException());
        }
    }

    private SecurityDecisionType mapDecision(com.securelayer.core.service.PolicyDecisionType decision) {
        return switch (decision) {
            case ALLOW -> SecurityDecisionType.ALLOW;
            case DENY -> SecurityDecisionType.DENY;
            case REQUIRE_MFA -> SecurityDecisionType.REQUIRE_MFA;
            case REQUIRE_DEVICE_CERTIFICATE -> SecurityDecisionType.REQUIRE_DEVICE_CERTIFICATE;
        };
    }
}
