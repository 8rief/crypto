import java.util.*;

public class RSA {
    public static void main(String[] args) {
        int p = 1009;
        int q = 3643;
        long n = (long) p * q;
        long phi = (p - 1) * (q - 1);
        List<Integer> validEs = new ArrayList<>();
        Map<Integer, Integer> unconcealedMessageCount = new HashMap<>();

        // Find all valid values of e
        for (int e = 2; e < phi; e++) {
            if (gcd(e, phi) == 1) {
                validEs.add(e);
            }
        }

        // Calculate the number of unconcealed messages for each valid e
        for (int e : validEs) {
            int count = 0;
            for (long m = 0; m < n; m++) {
                if (modularExponentiation(m, e, n) == m) {
                    count++;
                }
            }
            unconcealedMessageCount.put(e, count);
        }

        // Find the minimum number of unconcealed messages
        int minUnconcealed = Collections.min(unconcealedMessageCount.values());
        long sumOfEs = 0;

        // Sum all e values that have the minimum number of unconcealed messages
        for (Map.Entry<Integer, Integer> entry : unconcealedMessageCount.entrySet()) {
            if (entry.getValue() == minUnconcealed) {
                sumOfEs += entry.getKey();
            }
        }

        System.out.println("Sum of all values of e: " + sumOfEs);
    }

    // Function to compute gcd
    private static long gcd(long a, long b) {
        while (b != 0) {
            long temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    // Function for modular exponentiation
    private static long modularExponentiation(long base, long exponent, long modulus) {
        if (modulus == 1) return 0;
        long result = 1;
        base = base % modulus;
        while (exponent > 0) {
            if ((exponent & 1) == 1) {
                result = (result * base) % modulus;
            }
            exponent = exponent >> 1;
            base = (base * base) % modulus;
        }
        return result;
    }
}
