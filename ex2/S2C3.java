import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

public class S2C3 {

    public static void main(String[] args) throws Exception {
        byte[] key = generateRandomKey();
        byte[] plaintext = new byte[64]; // 64 bytes of plaintext (16 bytes * 4 blocks)
        Arrays.fill(plaintext, (byte) 'A'); // Fill plaintext with 'A'

        byte[] ciphertext = encrypt(plaintext, key, true); // Encrypt with ECB
        System.out.println("Detected mode: " + detectMode(ciphertext));

        ciphertext = encrypt(plaintext, key, false); // Encrypt with CBC
        System.out.println("Detected mode: " + detectMode(ciphertext));
    }

    public static byte[] generateRandomKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }

    public static byte[] encrypt(byte[] plaintext, byte[] key, boolean useECB) throws Exception {
        Cipher cipher = Cipher.getInstance(useECB ? "AES/ECB/PKCS5Padding" : "AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        if (useECB) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        } else {
            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[16];
            random.nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new javax.crypto.spec.IvParameterSpec(iv));
        }
        return cipher.doFinal(plaintext);
    }

    public static String detectMode(byte[] ciphertext) {
        int blockSize = 16;
        for (int i = 0; i < ciphertext.length - blockSize; i += blockSize) {
            byte[] block1 = Arrays.copyOfRange(ciphertext, i, i + blockSize);
            byte[] block2 = Arrays.copyOfRange(ciphertext, i + blockSize, i + 2 * blockSize);
            if (Arrays.equals(block1, block2)) {
                return "ECB";
            }
        }
        return "CBC";
    }
}
