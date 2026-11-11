package com.securelayer.core.grpc;

import com.google.protobuf.ByteString;
import com.securelayer.core.domain.Policy;
import com.securelayer.core.service.AdminService;
import com.securelayer.proto.v1.ControlPlaneServiceGrpc;
import com.securelayer.proto.v1.GetPolicyRequest;
import com.securelayer.proto.v1.GetPolicyResponse;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;
import net.devh.boot.grpc.server.service.GrpcService;

@GrpcService
public class ControlPlaneGrpcService extends ControlPlaneServiceGrpc.ControlPlaneServiceImplBase {
    private final AdminService adminService;

    public ControlPlaneGrpcService(AdminService adminService) {
        this.adminService = adminService;
    }

    @Override
    public void getPolicy(GetPolicyRequest request, StreamObserver<GetPolicyResponse> responseObserver) {
        try {
            UUID tenantId = UUID.fromString(request.getTenant().getTenantId());
            Policy policy = adminService.activePolicy(tenantId, request.getPolicyName());
            byte[] document = policy.getDocument().getBytes(StandardCharsets.UTF_8);
            responseObserver.onNext(GetPolicyResponse.newBuilder()
                    .setPolicyName(policy.getName())
                    .setVersion(policy.getVersion())
                    .setPolicyDocument(ByteString.copyFrom(document))
                    .setPolicyHashSha256(ByteString.copyFrom(MessageDigest.getInstance("SHA-256").digest(document)))
                    .setPolicy(com.securelayer.proto.v1.Policy.newBuilder()
                            .setPolicyId(policy.getId().toString())
                            .setName(policy.getName())
                            .setVersion(policy.getVersion())
                            .setDocumentJson(ByteString.copyFrom(document))
                            .setActive(policy.isActive())
                            .setPolicyHashSha256(ByteString.copyFrom(MessageDigest.getInstance("SHA-256").digest(document)))
                            .build())
                    .build());
            responseObserver.onCompleted();
        } catch (Exception ex) {
            responseObserver.onError(Status.NOT_FOUND.withDescription(ex.getMessage()).asRuntimeException());
        }
    }
}
