
public class RSA1 {

    private static int gcd(int a, int b) {
        while (b != 0) {
            int temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    private static boolean isCoprime(int a, int b) {
        
        return gcd(a, b) == 1;
    }

    public static void main(String[] args) {
        int p = 1009;
        int q = 3643;

        int phi = (p - 1) * (q - 1);

        int best = Integer.MAX_VALUE;
        long sum = 0;

        for (int encryption = 0; encryption < phi; encryption++) {
            if (!isCoprime(encryption, phi)) {
                continue;
            }

            int badP = gcd(p - 1, encryption - 1) + 1;
            int badQ = gcd(q - 1, encryption - 1) + 1;
            int numPlaintext = badP * badQ;

            if (best == numPlaintext) {
                sum += encryption;
            } else if (best > numPlaintext) {
                best = numPlaintext;
                sum = encryption;
            }
        }

        System.out.println(sum);
    }
}
