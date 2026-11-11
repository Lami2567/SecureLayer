package com.securelayer.core.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.securelayer.core.crypto.SecureLayerCrypto;
import java.io.StringWriter;
import java.security.KeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import javax.security.auth.x500.X500Principal;

class CertificateAuthorityServiceTest {
    private final SecureLayerCrypto crypto = new SecureLayerCrypto();
    private final CertificateAuthorityService certificateAuthority = new CertificateAuthorityService(crypto);

    @Test
    void issuesCertificateFromCsrWithoutReceivingPrivateKey() throws Exception {
        KeyPair deviceKeyPair = crypto.generateEd25519KeyPair();

        CertificateAuthorityService.DeviceCertificate certificate = certificateAuthority.issueDeviceCertificate(
                csrPem(deviceKeyPair, "device-1"), "device-1");

        assertThat(certificate.pem()).contains("BEGIN CERTIFICATE");
        assertThat(certificate.certificate().getPublicKey().getEncoded()).isEqualTo(deviceKeyPair.getPublic().getEncoded());
        assertThat(certificate.notAfter()).isAfter(certificate.notBefore());
    }

    @Test
    void rejectsInvalidProofOfPossession() {
        assertThatThrownBy(() -> certificateAuthority.issueDeviceCertificate("not a csr", "device-1"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private String csrPem(KeyPair keyPair, String commonName) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=" + commonName), keyPair.getPublic()).build(signer);
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(csr);
        }
        return writer.toString();
    }
}
