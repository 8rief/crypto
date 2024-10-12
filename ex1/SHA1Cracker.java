import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

public class SHA1Cracker {
    private static final String TARGET_HASH = "67ae1a64661ac8b4494666f58c4822408dd0a3e4";
    private static final List<char[]> CHAR_OPTIONS = Arrays.asList(
            new char[]{'Q', 'q'}, new char[]{'W', 'w'}, new char[]{'%', '5'}, new char[]{'8', '('},
            new char[]{'=', '0'}, new char[]{'I', 'i'}, new char[]{'*', '+'}, new char[]{'n', 'N'}
    );
    private static boolean found = false;  // 添加一个标志位

    public static void main(String[] args) {
        long startTime = System.currentTimeMillis();  // 记录开始时间

        char[] guess = new char[8];
        tryAllCombinations(guess, 0);

        long endTime = System.currentTimeMillis();  // 记录结束时间
        System.out.println("运行时间: " + (endTime - startTime) + " 毫秒");
    }

    private static void tryAllCombinations(char[] guess, int position) {
        if (found) return;  // 如果已经找到密码，直接返回

        if (position == guess.length) {
            for (String permutation : getPermutations(new String(guess))) {
                if (sha1Hash(permutation).equals(TARGET_HASH)) {
                    System.out.println("密码是: " + permutation);
                    found = true;  // 设置标志位
                    return;
                }
            }
            return;
        }

        for (char c : CHAR_OPTIONS.get(position)) {
            guess[position] = c;
            tryAllCombinations(guess, position + 1);
        }
    }

    private static List<String> getPermutations(String str) {
        if (str.length() == 1) {
            return Arrays.asList(str);
        }
        List<String> permutations = new java.util.ArrayList<>();
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            String remaining = str.substring(0, i) + str.substring(i + 1);
            for (String permutation : getPermutations(remaining)) {
                permutations.add(c + permutation);
            }
        }
        return permutations;
    }

    private static String sha1Hash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] result = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : result) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
