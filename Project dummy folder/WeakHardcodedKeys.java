import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class HardcodedKeyAES {

    public static void main(String[] args) throws Exception {
        // Hardcoded, weak AES key
        String hardcodedKey = "1234567890123456"; // 16 bytes, easy to guess
        SecretKeySpec secretKey = new SecretKeySpec(hardcodedKey.getBytes(), "AES");

        // Sample plaintext
        String plaintext = "ConfidentialData";
        System.out.println("Plaintext: " + plaintext);

        // Encrypt the plaintext
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

        System.out.println("Ciphertext (hex): " + bytesToHex(ciphertext));

        // Simulating the predictable nature of hardcoded keys
        System.out.println("Warning: Hardcoded keys can lead to easy compromise.");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}