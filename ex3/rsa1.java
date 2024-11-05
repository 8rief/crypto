import java.util.*;

public class rsa1 {
    public static void main(String[] args) {
        int p = 1009;
        int q = 3643;
        long n = (long) p * q;
        long phi = (p - 1) * (q - 1);

        // Find all valid values of e
        List<Integer> validEs = new ArrayList<>();
        for (int e = 2; e < phi; e++) {
            if (gcd(e, phi) == 1) {
                validEs.add(e);
            }
        }

        // Find the minimum number of unconcealed messages and the sum of corresponding e values
        long sumOfEs = 0;
        int minUnconcealed = Integer.MAX_VALUE;
        for (int e : validEs) {
            int unconcealedCount = countUnconcealedMessages(e, p, q);
            if (unconcealedCount < minUnconcealed) {
                minUnconcealed = unconcealedCount;
                sumOfEs = e; // reset sum
            } else if (unconcealedCount == minUnconcealed) {
                sumOfEs += e; // add to sum
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

    // Count unconcealed messages for given e
    private static int countUnconcealedMessages(int e, int p, int q) {
        int count = 0;
        for (int m = 0; m < p; m++) {
            if (Math.pow(m, e) % p == m) {
                count++;
            }
        }
        for (int m = 0; m < q; m++) {
            if (Math.pow(m, e) % q == m) {
                count++;
            }
        }
        return count;
    }
}
