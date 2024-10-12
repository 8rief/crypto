public class S1C3 {
    public static void main(String[] args) {
        byte[] ciphertext1 = "Test message".getBytes();
        byte[] ciphertext2 = "Crdc7zrddvpr".getBytes();
        byte key = 23;

        byte[] result1 = singleXOR(ciphertext1, key);
        byte[] result2 = singleXOR(ciphertext2, key);

        System.out.println(new String(result1));
        System.out.println(new String(result2));
    }

    public static byte[] singleXOR(byte[] ciphertext, byte key) {
        byte[] plain = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            plain[i] = (byte) (ciphertext[i] ^ key);
        }
        return plain;
    }
}
