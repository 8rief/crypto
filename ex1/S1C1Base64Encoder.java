import java.util.ArrayList;
import java.util.List;

public class S1C1Base64Encoder {
    private static final String VALUES = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    public static void main(String[] args) {
        byte[] data = "Hello".getBytes();
        String encoded = base64Encode(data);
        System.out.println(encoded);
    }

    public static String base64Encode(byte[] data) {
        StringBuilder res = new StringBuilder();

        for (String b64 : groups(b64Groups(data), 4)) {
            res.append(b64);
            for (int i = 0; i < 4 - b64.length(); i++) {
                res.append('=');
            }
        }

        return res.toString();
    }

    private static List<String> b64Groups(byte[] data) {
        List<String> digits = binaryDigits(data);
        List<String> b64Groups = new ArrayList<>();

        for (String num : groups(digits, 6)) {
            int index = Integer.parseInt(num, 2);
            b64Groups.add(String.valueOf(VALUES.charAt(index)));
        }

        return b64Groups;
    }

    private static List<String> binaryDigits(byte[] data) {
        List<String> digits = new ArrayList<>();

        for (byte b : data) {
            for (int i = 7; i >= 0; i--) {
                int bit = (b >> i) & 1;
                digits.add(String.valueOf(bit));
            }
        }

        return digits;
    }

    private static List<String> groups(List<String> data, int n) {
        List<String> group = new ArrayList<>();
        List<String> result = new ArrayList<>();

        for (String x : data) {
            group.add(x);
            if (group.size() == n) {
                result.add(String.join("", group));
                group.clear();
            }
        }

        if (!group.isEmpty()) {
            result.add(String.join("", group));
        }

        return result;
    }
}
