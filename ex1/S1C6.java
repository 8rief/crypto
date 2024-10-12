import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class S1C6 {

    private static final Map<Character, Double> englishLetterFreq = new HashMap<>();
    static {
        englishLetterFreq.put('A', 0.0651738);
        englishLetterFreq.put('B', 0.0124248);
        englishLetterFreq.put('C', 0.0217339);
        englishLetterFreq.put('D', 0.0349835);
        englishLetterFreq.put('E', 0.1041442);
        englishLetterFreq.put('F', 0.0197881);
        englishLetterFreq.put('G', 0.0158610);
        englishLetterFreq.put('H', 0.0492888);
        englishLetterFreq.put('I', 0.0558094);
        englishLetterFreq.put('J', 0.0009033);
        englishLetterFreq.put('K', 0.0050529);
        englishLetterFreq.put('L', 0.0331490);
        englishLetterFreq.put('M', 0.0202124);
        englishLetterFreq.put('N', 0.0564513);
        englishLetterFreq.put('O', 0.0596302);
        englishLetterFreq.put('P', 0.0137645);
        englishLetterFreq.put('Q', 0.0008606);
        englishLetterFreq.put('R', 0.0497563);
        englishLetterFreq.put('S', 0.0515760);
        englishLetterFreq.put('T', 0.0729357);
        englishLetterFreq.put('U', 0.0225134);
        englishLetterFreq.put('V', 0.0082903);
        englishLetterFreq.put('W', 0.0171272);
        englishLetterFreq.put('X', 0.0013692);
        englishLetterFreq.put('Y', 0.0145984);
        englishLetterFreq.put('Z', 0.0007836);
        englishLetterFreq.put(' ', 0.1918182);
        englishLetterFreq.put('~', 0.0000001);
    }

    public static Map<Character, Integer> countLetters(String message) {
        Map<Character, Integer> letterCount = new HashMap<>();
        for (char c : "ABCDEFGHIJKLMNOPQRSTUVWXYZ ~".toCharArray()) {
            letterCount.put(c, 0);
        }
        for (char letter : message.toUpperCase().toCharArray()) {
            letterCount.put(letter, letterCount.getOrDefault(letter, 0) + 1);
        }
        return letterCount;
    }

    public static Map<Character, Double> messageFrequency(String message) {
        Map<Character, Integer> letterCount = countLetters(message);
        Map<Character, Double> letterFrequencies = new HashMap<>();
        int totalLetters = letterCount.values().stream().mapToInt(Integer::intValue).sum();
        for (Map.Entry<Character, Integer> entry : letterCount.entrySet()) {
            letterFrequencies.put(entry.getKey(), entry.getValue() / (double) totalLetters);
        }
        return letterFrequencies;
    }

    public static double getChi2(String message) {
        Map<Character, Double> letterFrequencies = messageFrequency(message);
        double chi2 = 0;
        for (Map.Entry<Character, Double> entry : letterFrequencies.entrySet()) {
            double expectedFrequency = englishLetterFreq.getOrDefault(entry.getKey(), 0.0000001);//0.0000001 is the frequency of '~'——————default value
            double difference = entry.getValue() - expectedFrequency;
            chi2 += difference * difference / expectedFrequency;
        }
        return chi2;
    }
  
    public static byte[] singleByteXOR(byte[] xorBytes, byte key) {
        byte[] xorResult = new byte[xorBytes.length];
        for (int i = 0; i < xorBytes.length; i++) {
            xorResult[i] = (byte) (xorBytes[i] ^ key);
        }
        return xorResult;
    }

    public static int singleByteXORBF(byte[] cipherBytes) {
        Map<Integer, Double> chiScores = new HashMap<>();
        for (int key = 0; key < 256; key++) {
            byte[] xorBytes = singleByteXOR(cipherBytes, (byte) key);
            String xorResult = new String(xorBytes);
            chiScores.put(key, getChi2(xorResult));
        }
        return chiScores.entrySet().stream().min(Map.Entry.comparingByValue()).get().getKey();
    }


    public static byte[] repeatingKeyXOR(byte[] initialBytes, byte[] keyBytes) {
        byte[] finalBytes = new byte[initialBytes.length];
        for (int i = 0; i < initialBytes.length; i++) {
            finalBytes[i] = (byte) (initialBytes[i] ^ keyBytes[i % keyBytes.length]);
        }
        return finalBytes;
    }

    public static int popcount(long x) {
        x -= (x >> 1) & 0x5555555555555555L;
        x = (x & 0x3333333333333333L) + ((x >> 2) & 0x3333333333333333L);
        x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0fL;
        return (int) ((x * 0x0101010101010101L) >> 56);
    }

    public static int hammingDistance(byte[] bytearray1, byte[] bytearray2) {
        if (bytearray1.length != bytearray2.length) {
            System.out.println("Cannot compute Hamming distance: \"" + new String(bytearray1) + "\" is not the same length as \"" + new String(bytearray2) + "\"!");
            return -1;
        }
        int distance = 0;
        for (int i = 0; i < bytearray1.length; i++) {
            distance += popcount(bytearray1[i] ^ bytearray2[i]);
        }
        return distance;
    }

    public static double normalizedHammingDistance(byte[] bytearray1, byte[] bytearray2) {
        int hDistance = hammingDistance(bytearray1, bytearray2);
        return hDistance / (double) bytearray1.length;
    }

    public static void breakRepeatingXOR(byte[] cipherBytes, int numKeySizes) {
        System.out.println("Breaking repeating XOR cipher...");
        Map<Integer, Double> keysizeNHDs = new HashMap<>();
        for (int i = 2; i < 41; i++) {
            int numBlocks = (int) Math.ceil(cipherBytes.length / (double) i);
            byte[] firstBlock = new byte[i];
            System.arraycopy(cipherBytes, 0, firstBlock, 0, i);
            double totalHammingDistance = 0;
            for (int j = 1; j < numBlocks; j++) {
                byte[] nextBlock = new byte[i];
                System.arraycopy(cipherBytes, i * j, nextBlock, 0, Math.min(i, cipherBytes.length - i * j));
                if (firstBlock.length == nextBlock.length) {
                    totalHammingDistance += normalizedHammingDistance(firstBlock, nextBlock);
                }
            }
            keysizeNHDs.put(i, totalHammingDistance / numBlocks);
        }
        for (int i = 0; i < numKeySizes; i++) {
            int keysize = keysizeNHDs.entrySet().stream().min(Map.Entry.comparingByValue()).get().getKey();
            double keysizeNHD = keysizeNHDs.get(keysize);
            System.out.println("Trying key length " + keysize + ", with normalized Hamming distance " + keysizeNHD);
            byte[][] blocks = new byte[(int) Math.ceil(cipherBytes.length / (double) keysize)][keysize];
            for (int j = 0; j < blocks.length; j++) {
                System.arraycopy(cipherBytes, j * keysize, blocks[j], 0, Math.min(keysize, cipherBytes.length - j * keysize));
            }
            byte[][] transposedBlocks = new byte[keysize][(int) Math.ceil((double) cipherBytes.length / keysize)];
            for (int j = 0; j < blocks.length; j++) {
                for (int k = 0; k < keysize; k++) {
                    if (j * keysize + k < cipherBytes.length) {
                        transposedBlocks[k][j] = blocks[j][k];
                    }
                }
            }

            byte[] keyBytes = new byte[keysize];
            for (int j = 0; j < keysize; j++) {
                keyBytes[j] = (byte) singleByteXORBF(transposedBlocks[j]);
            }

            StringBuilder keyString = new StringBuilder();
            for (byte keyChar : keyBytes) {
                keyString.append((char) keyChar);
            }
            System.out.println("Best key: " + keyString.toString());

            byte[] plainBytes = repeatingKeyXOR(cipherBytes, keyBytes);
            System.out.println("Plaintext: " + new String(plainBytes));

            keysizeNHDs.remove(keysize);
        }
    }

    public static void hammingDistanceTest() {
        System.out.println("Testing Hamming distance function...");
        String string1 = "this is a test";
        String string2 = "wokka wokka!!!";
        byte[] stringBytes1 = string1.getBytes();
        byte[] stringBytes2 = string2.getBytes();
        int hDistance = hammingDistance(stringBytes1, stringBytes2);
        System.out.println("Hamming distance between \"" + string1 + "\" and \"" + string2 + "\": " + hDistance);
    }

    public static void main(String[] args) throws Exception {
        String base64Data = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("Challenge6Data.txt")));
        byte[] encryptedBytes = Base64.getDecoder().decode(base64Data.replaceAll("\\s", ""));
        breakRepeatingXOR(encryptedBytes, 1);
    }
}