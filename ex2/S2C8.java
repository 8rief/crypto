import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class S2C8 {
    public static void main(String[] args) throws Exception {
        String plaintext = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

        // Generate a random key and IV
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        byte[] iv = new byte[16];
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Encrypt the plaintext
        byte[] encrypted = encrypt(plaintext, secretKey, ivSpec);

        // Perform bit flipping attack
        encrypted[32] ^= 1; // Flip a bit in the ciphertext
        String manipulatedDecrypted = decrypt(encrypted, secretKey, ivSpec);
        System.out.println("Manipulated Decrypted: " + manipulatedDecrypted);
    }

    public static byte[] encrypt(String input, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(input.getBytes());
    }

    public static String decrypt(byte[] input, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return new String(cipher.doFinal(input));
    }
}
