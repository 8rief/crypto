import java.util.HashMap;
import java.util.Map;

public class S1C2 {
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

    public static byte[] xorBuffers(byte[] buf1, byte[] buf2) {
        byte[] result = new byte[buf1.length];
        for (int i = 0; i < buf1.length; i++) {
            result[i] = (byte) (buf1[i] ^ buf2[i]);
        }
        return result;
    }

    public static void main(String[] args) {
        byte[] buffer1 = hexDecode("1c0111001f010100061a024b53535009181c");
        byte[] buffer2 = hexDecode("686974207468652062756c6c277320657965");

        byte[] xorResult = xorBuffers(buffer1, buffer2);

        // 输出结果为十六进制字符串
        StringBuilder hexResult = new StringBuilder();
        for (byte b : xorResult) {
            hexResult.append(String.format("%02x", b));
        }

        System.out.println(hexResult.toString());
    }
}
