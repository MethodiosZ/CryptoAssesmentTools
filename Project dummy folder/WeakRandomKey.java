import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random;

public class WeakRandomKey {

    public static void main(String[] args) throws Exception {
        // Weak random number generator
        Random random = new Random(12345L); // Fixed seed for reproducibility

        // Generate a weak AES key using java.util.Random
        byte[] weakKeyBytes = new byte[16];
        for (int i = 0; i < weakKeyBytes.length; i++) {
            weakKeyBytes[i] = (byte) random.nextInt(256);
        }

        SecretKeySpec weakKey = new SecretKeySpec(weakKeyBytes, "AES");
        System.out.println("Generated Weak Key (hex): " + bytesToHex(weakKeyBytes));

        // Encrypt some plaintext
        String plaintext = "SensitiveData";
        System.out.println("Plaintext: " + plaintext);

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, weakKey);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

        System.out.println("Ciphertext (hex): " + bytesToHex(ciphertext));

        System.out.println("Warning: Using java.util.Random for key generation makes keys predictable!");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}