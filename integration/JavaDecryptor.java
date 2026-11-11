import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class JavaDecryptor {
    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.err.println("Usage: java JavaDecryptor.java <keyBase64> <nonceBase64> <ciphertextBase64> <authTagBase64>");
            System.exit(1);
        }
        byte[] keyBytes = Base64.getDecoder().decode(args[0]);
        byte[] nonceBytes = Base64.getDecoder().decode(args[1]);
        byte[] cipherBytes = Base64.getDecoder().decode(args[2]);
        byte[] tagBytes = Base64.getDecoder().decode(args[3]);

        byte[] combined = new byte[cipherBytes.length + tagBytes.length];
        System.arraycopy(cipherBytes, 0, combined, 0, cipherBytes.length);
        System.arraycopy(tagBytes, 0, combined, cipherBytes.length, tagBytes.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonceBytes);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

        byte[] decrypted = cipher.doFinal(combined);
        System.out.println("JAVA_DECRYPTED:" + new String(decrypted, StandardCharsets.UTF_8));
    }
}
