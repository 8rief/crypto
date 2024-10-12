import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class S2C4 {

    private static final int BLOCK_SIZE = 16;
    private static final byte[] UNKNOWN_STRING = "Your unknown string here".getBytes();

    public static void main(String[] args) throws Exception {
        byte[] key = generateRandomKey();
        byte[] decrypted = decryptECB(key);
        System.out.println(new String(decrypted));
    }

    public static byte[] generateRandomKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        return secretKey.getEncoded();
    }

    public static byte[] encrypt(byte[] plaintext, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decryptECB(byte[] key) throws Exception {
        byte[] decrypted = new byte[UNKNOWN_STRING.length];
        for (int i = 0; i < UNKNOWN_STRING.length; i++) {
            byte[] block = new byte[BLOCK_SIZE];
            Arrays.fill(block, (byte) 'A');
            byte[] encryptedBlock = encrypt(block, key);
            for (int j = 0; j < 256; j++) {
                block[BLOCK_SIZE - 1] = (byte) j;
                byte[] testBlock = encrypt(block, key);
                if (Arrays.equals(Arrays.copyOfRange(testBlock, 0, BLOCK_SIZE), Arrays.copyOfRange(encryptedBlock, 0, BLOCK_SIZE))) {
                    decrypted[i] = (byte) j;
                    break;
                }
            }
        }
        return decrypted;
    }
}
