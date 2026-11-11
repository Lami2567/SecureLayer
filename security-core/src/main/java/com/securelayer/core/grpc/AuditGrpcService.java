package com.securelayer.core.grpc;

import com.securelayer.core.domain.AuditEvent;
import com.securelayer.core.service.AdminService;
import com.securelayer.proto.v1.AuditServiceGrpc;
import com.securelayer.proto.v1.RecordAuditEventRequest;
import com.securelayer.proto.v1.RecordAuditEventResponse;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import java.util.UUID;
import net.devh.boot.grpc.server.service.GrpcService;

@GrpcService
public class AuditGrpcService extends AuditServiceGrpc.AuditServiceImplBase {
    private final AdminService adminService;

    public AuditGrpcService(AdminService adminService) {
        this.adminService = adminService;
    }

    @Override
    public void recordAuditEvent(RecordAuditEventRequest request, StreamObserver<RecordAuditEventResponse> responseObserver) {
        try {
            UUID tenantId = UUID.fromString(request.getTenant().getTenantId());
            AuditEvent event = adminService.recordAudit(tenantId, request.getPrincipal().getSubject(), request.getAction(), request.getResource(),
                    request.getEventHashSha256().toByteArray(), request.getEd25519Signature().toByteArray());
            responseObserver.onNext(RecordAuditEventResponse.newBuilder().setAuditEventId(event.getId().toString()).build());
            responseObserver.onCompleted();
        } catch (Exception ex) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(ex.getMessage()).asRuntimeException());
        }
    }
}
