import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class S2C5 {
    private static final String ALGORITHM = "AES/ECB/PKCS5Padding";
    private static SecretKey key;

    public static void main(String[] args) throws Exception {
        // Generate a random key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        key = keyGen.generateKey();

        String profile = "foo@bar.com";
        byte[] encryptedProfile = encryptUnderKey(profile);
        System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encryptedProfile));

        String decryptedProfile = decryptUnderKey(encryptedProfile);
        System.out.println("Decrypted: " + decryptedProfile);
    }

    public static Map<String, String> parse(String unparsed) {
        String[] keyValues = unparsed.split("&");
        Map<String, String> map = new HashMap<>();

        for (String keyValue : keyValues) {
            String[] parts = keyValue.split("=");
            map.put(parts[0], parts[1]);
        }
        return map;
    }

    public static String encodeProfile(String profile) {
        profile = profile.replace("&", "").replace("=", "");

        String email = "email=" + profile;
        String role = "role=user";
        String uid = "uid=10";

        return email + "&" + uid + "&" + role;
    }

    public static byte[] encryptUnderKey(String profile) throws Exception {
        String plaintext = encodeProfile(profile);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext.getBytes("UTF-8"));
    }

    public static String decryptUnderKey(byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes, "UTF-8");
    }
}
