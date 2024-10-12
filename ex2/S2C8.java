import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Base64;

public class S2C8 {

    private static final byte[] key = new byte[] {(byte) 0xc6, (byte) 0xfe, (byte) 0xe2, 0x2f, (byte) 0x97, 0x72, 0x7c, 0x2f, (byte) 0xea, 0x59, (byte) 0xc5, 0x43, (byte) 0xbf, 0x69, (byte) 0x99, (byte) 0x97};
    private static final SecureRandom secureRandom = new SecureRandom();

    public static void main(String[] args) throws Exception {
        int padlen = 18;
        byte[] userdata = new byte[padlen];
        Arrays.fill(userdata, (byte) 'A');
        byte[] suffix = ":admin<true".getBytes();
        byte[] combined = new byte[userdata.length + suffix.length];
        System.arraycopy(userdata, 0, combined, 0, userdata.length);
        System.arraycopy(suffix, 0, combined, userdata.length, suffix.length);

        System.out.println("Original User Data: " + new String(userdata));
        System.out.println("Combined Data: " + new String(combined));

        byte[] encrypted = encrypt(combined);
        System.out.println("Encrypted Data (Base64): " + Base64.getEncoder().encodeToString(encrypted));

        // Modify encrypted data to flip bits
        encrypted[padlen + 30] ^= 1;
        encrypted[padlen + 36] ^= 1;
        System.out.println("Modified Encrypted Data (Base64): " + Base64.getEncoder().encodeToString(encrypted));

        // Check if the decryption result indicates admin
        boolean isAdmin = isAdmin(encrypted);
        System.out.println("Is Admin: " + isAdmin);
    }

    public static byte[] encrypt(byte[] userdata) throws Exception {
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);

        String prefix = "comment1=cooking MCs;userdata=";
        String suffix = ";comment2= like a pound of bacon";
        byte[] prefixBytes = prefix.getBytes();
        byte[] suffixBytes = suffix.getBytes();
        byte[] data = new byte[prefixBytes.length + userdata.length + suffixBytes.length];

        System.arraycopy(prefixBytes, 0, data, 0, prefixBytes.length);
        System.arraycopy(userdata, 0, data, prefixBytes.length, userdata.length);
        System.arraycopy(suffixBytes, 0, data, prefixBytes.length + userdata.length, suffixBytes.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] paddedData = pad(Arrays.copyOf(new byte[16], 16 + data.length));
        System.arraycopy(data, 0, paddedData, 16, data.length);

        return cipher.doFinal(paddedData);
    }

    public static Map<String, String> decrypt(byte[] data) throws Exception {
        byte[] iv = Arrays.copyOfRange(data, 0, 16);
        byte[] ciphertext = Arrays.copyOfRange(data, 16, data.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decrypted = unpad(cipher.doFinal(ciphertext));

        String decryptedString = new String(decrypted);
        System.out.println("Decrypted String: " + decryptedString);
        String[] parts = decryptedString.split(";");
        Map<String, String> result = new HashMap<>();
        for (String part : parts) {
            String[] kv = part.split("=", 2);
            if (kv.length == 2) {
                result.put(kv[0], kv[1]);
            }
        }

        return result;
    }

    public static boolean isAdmin(byte[] data) throws Exception {
        Map<String, String> decrypted = decrypt(data);
        return "true".equals(decrypted.get("admin"));
    }

    public static byte[] pad(byte[] data) {
        int padding = 16 - (data.length % 16);
        byte[] paddedData = Arrays.copyOf(data, data.length + padding);
        Arrays.fill(paddedData, data.length, data.length + padding, (byte) padding);
        return paddedData;
    }

    public static byte[] unpad(byte[] data) throws Exception {
        int padding = data[data.length - 1];
        if (padding < 1 || padding > 16) {
            throw new IllegalArgumentException("Invalid padding");
        }
        for (int i = data.length - padding; i < data.length; i++) {
            if (data[i] != padding) {
                throw new IllegalArgumentException("Invalid padding");
            }
        }
        return Arrays.copyOf(data, data.length - padding);
    }
}
