import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AESEncryptionApp {

    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage: AESEncryptionApp <encrypt|decrypt> <value> <encryption key>");
            return;
        }

        String action = args[0];
        String value = args[1];
        String encryptionKey = args[2];

        if (action.equalsIgnoreCase("encrypt")) {
            String encryptedValue = AESEncrypt(value, encryptionKey);

            if (encryptedValue != null) {
                System.out.println("Encrypted value: " + encryptedValue);
            } else {
                System.out.println("Encryption failed.");
            }
        } else if (action.equalsIgnoreCase("decrypt")) {
            String decryptedValue = AESDecrypt(value, encryptionKey);

            if (decryptedValue != null) {
                System.out.println("Decrypted value: " + decryptedValue);
            } else {
                System.out.println("Decryption failed.");
            }
        } else {
            System.out.println("Invalid action. Use 'encrypt' or 'decrypt'.");
        }
    }

    public static String AESEncrypt(String lpwszSource, String lpwszKey) {
        try {
            // Hash the encryption key using SHA-256
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] keyHash = sha256.digest(lpwszKey.getBytes(StandardCharsets.UTF_16LE));

            // Encrypt lpwszSource with AES in ECB mode
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyHash, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            byte[] sourceBytes = lpwszSource.getBytes(StandardCharsets.UTF_16LE);
            byte[] encrypted = cipher.doFinal(sourceBytes);

            // Base64 encode the encrypted data
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            return null;
        }
    }

    public static String AESDecrypt(String lpwszSource, String lpwszKey) {
        try {
            // Hash the encryption key using SHA-256
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] keyHash = sha256.digest(lpwszKey.getBytes(StandardCharsets.UTF_16LE));

            // Base64 decode the encrypted data
            byte[] encryptedBytes = Base64.getDecoder().decode(lpwszSource);

            // Decrypt lpwszSource with AES in ECB mode
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyHash, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            byte[] decrypted = cipher.doFinal(encryptedBytes);

            // Convert decrypted bytes back to string
            return new String(decrypted, StandardCharsets.UTF_16LE).trim();
        } catch (Exception e) {
            return null;
        }
    }
}
