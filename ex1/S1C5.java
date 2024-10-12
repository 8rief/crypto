import java.util.ArrayList;
import java.util.List;

public class S1C5 {
    public static void main(String[] args) {
        byte[] data = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".getBytes();
        byte[] key = "ICE".getBytes();

        byte[] encrypted = repeatingXOR(data, key);
        String hexString = bytesToHex(encrypted);

        for (String group : groups(hexString, 25)) {
            System.out.println(group);
        }
    }

    public static byte[] repeatingXOR(byte[] data, byte[] key) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return result;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static List<String> groups(String data, int n) {
        List<String> result = new ArrayList<>();
        for (int i = 0; i < data.length(); i += n) {
            result.add(data.substring(i, Math.min(data.length(), i + n)));
        }
        return result;
    }
}
