import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class S1C4 {
    private static final int KEY_RANGE = 255;

    public static void main(String[] args) {
        try {
            // 获取数据
            String urlString = "https://cryptopals.com/static/challenge-data/4.txt";
            List<String> data = fetchData(urlString);

            // 解码数据
            List<byte[]> decodedData = new ArrayList<>();
            for (String line : data) {
                decodedData.add(hexDecode(line));
            }

            // 生成候选明文
            List<byte[]> candidates = new ArrayList<>();
            for (byte[] ciphertext : decodedData) {
                for (int key = 0; key < KEY_RANGE; key++) {
                    candidates.add(singleXOR(ciphertext, (byte) key));
                }
            }

            // 找到最佳候选明文
            byte[] bestCandidate = findBestCandidate(candidates);
            System.out.println(new String(bestCandidate));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static List<String> fetchData(String urlString) throws Exception {
        @SuppressWarnings("deprecation")
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");

        List<String> data = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                data.add(line);
            }
        }
        return data;
    }

    private static byte[] hexDecode(String text) {
        int length = text.length();
        byte[] result = new byte[length / 2];

        for (int i = 0; i < length; i += 2) {
            int first = Character.digit(text.charAt(i), 16);
            int second = Character.digit(text.charAt(i + 1), 16);
            result[i / 2] = (byte) ((first << 4) | second);
        }

        return result;
    }

    private static byte[] singleXOR(byte[] ciphertext, byte key) {
        byte[] plain = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            plain[i] = (byte) (ciphertext[i] ^ key);
        }
        return plain;
    }

    private static byte[] findBestCandidate(List<byte[]> candidates) {
        byte[] bestCandidate = null;
        double bestScore = Double.NEGATIVE_INFINITY;

        for (byte[] candidate : candidates) {
            double score = englishScore(candidate);
            if (score > bestScore) {
                bestScore = score;
                bestCandidate = candidate;
            }
        }

        return bestCandidate;
    }

    private static double englishScore(byte[] text) {
        // 简单的英文评分函数，可以根据需要改进
        String englishLetters = "ETAOIN SHRDLU";
        double score = 0;

        for (byte b : text) {
            char c = (char) b;
            if (englishLetters.indexOf(Character.toUpperCase(c)) != -1) {
                score++;
            }
        }

        return score;
    }
}
