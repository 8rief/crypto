import java.math.BigInteger;
import java.security.SecureRandom;

public class ImpRSA {
    private final static SecureRandom random = new SecureRandom();
    private final static int BIT_LENGTH = 512;

    public static void main(String[] args) {
        BigInteger p = BigInteger.probablePrime(BIT_LENGTH, random);
        BigInteger q = BigInteger.probablePrime(BIT_LENGTH, random);

        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        BigInteger e = BigInteger.valueOf(3);

        BigInteger d = modInverse(e, phi);

        System.out.println("Public key: [e=" + e + ", n=" + n + "]");
        System.out.println("Private key: [d=" + d + ", n=" + n + "]");

        BigInteger message = BigInteger.valueOf(42);
        BigInteger encrypted = message.modPow(e, n);
        BigInteger decrypted = encrypted.modPow(d, n);

        System.out.println("Original message: " + message);
        System.out.println("Encrypted message: " + encrypted);
        System.out.println("Decrypted message: " + decrypted);

        String text = "Hello, World!";
        String hexString = stringToHex(text);
        BigInteger textAsNumber = new BigInteger(hexString, 16);
        BigInteger encryptedText = textAsNumber.modPow(e, n);
        BigInteger decryptedText = encryptedText.modPow(d, n);
        String decryptedString = hexToString(decryptedText.toString(16));

        System.out.println("Original text: " + text);
        System.out.println("Encrypted text (as number): " + encryptedText);
        System.out.println("Decrypted text: " + decryptedString);
    }

    // 转十六进制
    public static String stringToHex(String str) {
        StringBuilder hex = new StringBuilder();
        for (char c : str.toCharArray()) {
            hex.append(Integer.toHexString(c));
        }
        return hex.toString();
    }

    // 转字符串
    public static String hexToString(String hex) {
        StringBuilder str = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            str.append((char) Integer.parseInt(hex.substring(i, i + 2), 16));
        }
        return str.toString();
    }

    private static BigInteger modInverse(BigInteger a, BigInteger m) {
        BigInteger[] result = extendedGCD(a, m);
        if (!result[0].equals(BigInteger.ONE)) {
            throw new ArithmeticException("Modular inverse does not exist");
        }
        return result[1].mod(m);
    }
    
    private static BigInteger[] extendedGCD(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return new BigInteger[]{a, BigInteger.ONE, BigInteger.ZERO};
        }
        BigInteger[] vals = extendedGCD(b, a.mod(b));
        BigInteger d = vals[0];
        BigInteger x = vals[2];
        BigInteger y = vals[1].subtract(a.divide(b).multiply(vals[2]));
        return new BigInteger[]{d, x, y};
    }
    
}
