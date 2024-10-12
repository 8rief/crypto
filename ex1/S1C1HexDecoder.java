import java.util.HashMap;
import java.util.Map;

public class S1C1HexDecoder {
    private static final String HEX_DIGITS = "0123456789abcdef";
    private static final Map<Character, Integer> lookup = new HashMap<>();

    static {
        for (int i = 0; i < HEX_DIGITS.length(); i++) {
            lookup.put(HEX_DIGITS.charAt(i), i);
        }
    }

    public static byte[] hexDecode(String text) {
        int length = text.length();
        byte[] result = new byte[length / 2];

        for (int i = 0; i < length; i += 2) {
            int first = lookup.get(text.charAt(i));
            int second = lookup.get(text.charAt(i + 1));
            result[i / 2] = (byte) ((first << 4) | second);
        }

        return result;
    }

    public static void main(String[] args) {
        String hexString = "48656c6c6f";
        byte[] decodedBytes = hexDecode(hexString);

        // 输出解码后的字节数组
        for (byte b : decodedBytes) {
            System.out.print((char) b);
        }
    }
}
