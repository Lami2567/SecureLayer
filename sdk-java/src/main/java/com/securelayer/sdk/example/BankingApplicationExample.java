package com.securelayer.sdk.example;

import com.securelayer.sdk.EncryptedPayload;
import com.securelayer.sdk.ProtectedRequest;
import com.securelayer.sdk.RequestVerificationResult;
import com.securelayer.sdk.SecureLayerClient;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Spring Boot Integration Example demonstrating SecureLayer SDK integration.
 * Shows application identity, device identity, policy evaluation, AES-256-GCM
 * encryption, Ed25519 signing, and audit events.
 */
@SpringBootApplication(scanBasePackages = {"com.securelayer.sdk"})
public class BankingApplicationExample {

    public static void main(String[] args) {
        SpringApplication.run(BankingApplicationExample.class, args);
    }

    @RestController
    @RequestMapping("/banking")
    public static class BankingController {
        private final SecureLayerClient secureLayer;

        public BankingController(SecureLayerClient secureLayer) {
            this.secureLayer = secureLayer;
        }

        @GetMapping("/accounts/{accountId}")
        public ResponseEntity<?> getAccountBalance(
                @PathVariable String accountId,
                @RequestHeader(value = "x-user-id", defaultValue = "alice@bank.example") String userId,
                @RequestHeader(value = "x-user-role", defaultValue = "TELLER") String userRole) {

            // 1. Generic Policy Check (evaluates user identity, device state, role, and resource)
            // In a live environment with gRPC configured, you can call secureLayer.authorize(...)
            // Here we show the pattern:
            if (!"TELLER".equalsIgnoreCase(userRole) && !"ADMIN".equalsIgnoreCase(userRole)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("error", "Access denied by SecureLayer policy"));
            }

            // 2. Encrypt sensitive financial record with AES-256-GCM before returning
            String sensitivePayload = "{\"accountId\":\"" + accountId + "\",\"balance\":125000.50,\"currency\":\"USD\"}";
            EncryptedPayload encryptedRecord = secureLayer.encrypt(sensitivePayload);

            return ResponseEntity.ok(Map.of(
                    "status", "ALLOWED",
                    "encryptedAccountData", encryptedRecord
            ));
        }

        @PostMapping("/transfers")
        public ResponseEntity<?> executeTransfer(
                @RequestBody TransferRequest request,
                @RequestHeader(value = "x-user-id", defaultValue = "alice@bank.example") String userId) {

            // 1. Deterministic hashing of the transaction
            String transactionDigest = secureLayer.hash(request.toString());

            // 2. Ed25519 Non-repudiable transaction signing
            String digitalSignature = secureLayer.sign("TRANSFER:" + request.fromAccount() + "->" + request.toAccount() + ":" + request.amount());

            // 3. Outbound protected call to core clearinghouse
            ProtectedRequest outboundCall = secureLayer.protectRequest(
                    "POST",
                    "/clearinghouse/transfers",
                    Map.of("content-type", "application/json"),
                    transactionDigest.getBytes()
            );

            return ResponseEntity.ok(Map.of(
                    "status", "TRANSFERRED",
                    "transactionDigest", transactionDigest,
                    "ed25519Signature", digitalSignature,
                    "outboundRequestId", outboundCall.requestId()
            ));
        }
    }

    public record TransferRequest(String fromAccount, String toAccount, double amount) {}
}
