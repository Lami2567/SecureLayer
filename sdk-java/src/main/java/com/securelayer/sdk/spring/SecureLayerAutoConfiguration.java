package com.securelayer.sdk.spring;

import com.securelayer.sdk.ApplicationIdentity;
import com.securelayer.sdk.DeviceIdentity;
import com.securelayer.sdk.SecureLayer;
import com.securelayer.sdk.SecureLayerClient;
import java.time.Duration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@ConditionalOnClass(SecureLayerClient.class)
@EnableConfigurationProperties(SecureLayerProperties.class)
public class SecureLayerAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public SecureLayerClient secureLayerClient(SecureLayerProperties properties) {
        SecureLayerClient.Builder builder = SecureLayerClient.builder()
                .tenantId(properties.getTenantId())
                .clockSkewTolerance(Duration.ofSeconds(properties.getClockSkewSeconds()));

        if (properties.getClientId() != null) {
            builder.application(ApplicationIdentity.of(properties.getClientId(), properties.getApplicationName()));
        }

        if (properties.getDeviceIdentifier() != null) {
            builder.device(DeviceIdentity.of(properties.getDeviceIdentifier(), properties.getCertificatePem()));
        }

        if (properties.getPrivateKeyPem() != null && !properties.getPrivateKeyPem().isBlank()) {
            builder.privateKeyPem(properties.getPrivateKeyPem());
        }

        if (properties.getPublicKeyPem() != null && !properties.getPublicKeyPem().isBlank()) {
            builder.publicKeyPem(properties.getPublicKeyPem());
        }

        if (properties.getEncryptionKeyBase64() != null && !properties.getEncryptionKeyBase64().isBlank()) {
            builder.encryptionKeyBase64(properties.getEncryptionKeyBase64());
        }

        if (properties.getHmacKeyBase64() != null && !properties.getHmacKeyBase64().isBlank()) {
            builder.hmacKeyBase64(properties.getHmacKeyBase64());
        }

        if (properties.getGrpcHost() != null && properties.getGrpcPort() > 0) {
            builder.grpcTarget(properties.getGrpcHost(), properties.getGrpcPort());
        }

        SecureLayerClient client = builder.build();
        SecureLayer.initialize(client);
        return client;
    }
}
