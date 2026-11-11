package com.securelayer.core.service;

import com.securelayer.core.crypto.SecureLayerCrypto;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;

@Service
public class CertificateAuthorityService {
    private static final Duration DEVICE_CERTIFICATE_TTL = Duration.ofDays(90);
    private static final X500Name ISSUER = new X500Name("CN=SecureLayer Device CA,O=SecureLayer");

    private final SecureLayerCrypto crypto;
    private final KeyPair caKeyPair;

    public CertificateAuthorityService(SecureLayerCrypto crypto) {
        this.crypto = crypto;
        this.caKeyPair = crypto.generateEd25519KeyPair();
    }

    public DeviceCertificate issueDeviceCertificate(String csrPem, String deviceIdentifier) {
        try {
            PKCS10CertificationRequest csr = parseCsr(csrPem);
            PublicKey publicKey = new JcaPEMKeyConverter().setProvider("BC").getPublicKey(csr.getSubjectPublicKeyInfo());
            if (!csr.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(publicKey))) {
                throw new IllegalArgumentException("CSR proof of possession is invalid");
            }
            Instant notBefore = Instant.now();
            Instant notAfter = notBefore.plus(DEVICE_CERTIFICATE_TTL);
            BigInteger serial = new BigInteger(160, java.security.SecureRandom.getInstanceStrong()).abs();
            X500Name subject = new X500Name("CN=" + escapeDn(deviceIdentifier) + ",OU=Devices,O=SecureLayer");
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    ISSUER,
                    serial,
                    Date.from(notBefore),
                    Date.from(notAfter),
                    subject,
                    publicKey)
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                    .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            ContentSigner signer = new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(caKeyPair.getPrivate());
            X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC")
                    .getCertificate(builder.build(signer));
            certificate.verify(caKeyPair.getPublic(), "BC");
            return new DeviceCertificate(certificate, toPem(certificate), subject.toString(), serial.toString(16), notBefore, notAfter);
        } catch (IOException | OperatorCreationException | PKCSException | GeneralSecurityException ex) {
            throw new IllegalArgumentException("Unable to issue device certificate", ex);
        }
    }

    public X509Certificate parseCertificate(String pemCertificate) {
        try (PEMParser parser = new PEMParser(new StringReader(pemCertificate))) {
            Object parsed = parser.readObject();
            if (parsed instanceof X509CertificateHolder holder) {
                return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
            }
            throw new IllegalArgumentException("PEM did not contain an X.509 certificate");
        } catch (IOException | GeneralSecurityException ex) {
            throw new IllegalArgumentException("Invalid X.509 certificate", ex);
        }
    }

    public String fingerprintSha256(X509Certificate certificate) {
        try {
            return java.util.HexFormat.of().formatHex(crypto.sha256(certificate.getEncoded()));
        } catch (CertificateEncodingException ex) {
            throw new IllegalArgumentException("Unable to fingerprint certificate", ex);
        }
    }

    public String publicKeySha256(PublicKey publicKey) {
        return java.util.HexFormat.of().formatHex(crypto.sha256(publicKey.getEncoded()));
    }

    private PKCS10CertificationRequest parseCsr(String csrPem) throws IOException {
        try (PEMParser parser = new PEMParser(new StringReader(csrPem))) {
            Object parsed = parser.readObject();
            if (parsed instanceof PKCS10CertificationRequest csr) {
                return csr;
            }
            throw new IllegalArgumentException("PEM did not contain a certificate signing request");
        }
    }

    private String toPem(X509Certificate certificate) throws IOException {
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(certificate);
        }
        return writer.toString();
    }

    private String escapeDn(String value) {
        return value.replace("\\", "\\\\").replace(",", "\\,").replace("+", "\\+").replace("\"", "\\\"");
    }

    public record DeviceCertificate(
            X509Certificate certificate,
            String pem,
            String subject,
            String serialNumber,
            Instant notBefore,
            Instant notAfter) {
    }
}
