import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class S2C2 {

    public static byte[] padPKCS7(byte[] buffer, int blockSize) {
        int padding = blockSize - (buffer.length % blockSize);
        byte[] paddedBuffer = Arrays.copyOf(buffer, buffer.length + padding);
        Arrays.fill(paddedBuffer, buffer.length, paddedBuffer.length, (byte) padding);
        return paddedBuffer;
    }

    public static byte[] unpadPKCS7(byte[] buffer) {
        int padding = buffer[buffer.length - 1];
        for (int i = buffer.length - padding; i < buffer.length; i++) {
            if (buffer[i] != padding) {
                return buffer;
            }
        }
        return Arrays.copyOf(buffer, buffer.length - padding);
    }

    public static byte[] aes128ECBEncrypt(byte[] buffer, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(buffer);
    }

    public static byte[] aes128ECBDecrypt(byte[] buffer, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(buffer);
    }

    public static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    public static byte[] aes128CBCEncrypt(byte[] buffer, byte[] key, byte[] iv) throws Exception {
        byte[] plaintext = padPKCS7(buffer, 16);
        byte[] ciphertext = new byte[plaintext.length];
        byte[] prevBlock = iv;

        for (int i = 0; i < plaintext.length; i += 16) {
            byte[] block = Arrays.copyOfRange(plaintext, i, i + 16);
            block = xor(block, prevBlock);
            block = aes128ECBEncrypt(block, key);
            System.arraycopy(block, 0, ciphertext, i, 16);
            prevBlock = block;
        }

        return ciphertext;
    }

    public static byte[] aes128CBCDecrypt(byte[] ciphertext, byte[] key, byte[] iv) throws Exception {
        byte[] plaintext = new byte[ciphertext.length];
        byte[] prevBlock = iv;

        for (int i = 0; i < ciphertext.length; i += 16) {
            byte[] block = Arrays.copyOfRange(ciphertext, i, i + 16);
            byte[] decryptedBlock = aes128ECBDecrypt(block, key);
            decryptedBlock = xor(decryptedBlock, prevBlock);
            System.arraycopy(decryptedBlock, 0, plaintext, i, 16);
            prevBlock = block;
        }

        return unpadPKCS7(plaintext);
    }

    public static void main(String[] args) throws Exception {
        byte[] plaintext = "Hello my name is Michael".getBytes();
        byte[] iv = new byte[16];
        byte[] key = "YELLOW SUBMARINE".getBytes();

        System.out.println("Original plaintext: " + new String(plaintext));

        byte[] encrypted = aes128CBCEncrypt(plaintext, key, iv);
        System.out.println("Encrypted ciphertext: " + Arrays.toString(encrypted));

        byte[] decrypted = aes128CBCDecrypt(encrypted, key, iv);
        System.out.println("Decrypted plaintext: " + new String(decrypted));

        assert Arrays.equals(decrypted, plaintext);
        System.out.println("Assertion passed: Decrypted text matches the original plaintext.");
    }
}
