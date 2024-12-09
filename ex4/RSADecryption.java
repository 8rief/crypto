import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import java.io.*;

/**
 * RSADecryption 类实现了多种针对 RSA 加密的攻击方法，包括公共模数攻击、
 * 因数碰撞法、低加密指数攻击、费马分解法和 Pollard p-1 分解法。
 * 该类读取名为 Frame0 到 Frame20 的文件，每个文件包含模数 (N)、公钥指数 (E) 和密文 (C)。
 * 最终将输出 Frame0 到 Frame20 的解密结果，如果未成功解密，则对应 Frame 的结果为空白。
 */
public class RSADecryption {

    /**
     * 扩展欧几里得算法，用于求解 ax + by = gcd(a, b) 的系数 x 和 y
     *
     * @param a BigInteger
     * @param b BigInteger
     * @return 包含 gcd(a, b)、x、y 的数组
     */
    public static BigInteger[] egcd(BigInteger a, BigInteger b) {
        if (a.equals(BigInteger.ZERO)) {
            return new BigInteger[]{b, BigInteger.ZERO, BigInteger.ONE};
        } else {
            BigInteger[] result = egcd(b.mod(a), a);
            BigInteger gcd = result[0];
            BigInteger x = result[2].subtract(b.divide(a).multiply(result[1]));
            BigInteger y = result[1];
            return new BigInteger[]{gcd, x, y};
        }
    }

    /**
     * 公共模数攻击：寻找具有相同模数的不同加密实例，利用扩展欧几里得算法求解明文
     *
     * @param ns 模数数组（16进制字符串）
     * @param es 指数数组（16进制字符串）
     * @param cs 密文数组（16进制字符串）
     * @return 解密后的明文（String）
     */
    public static String sameModulus(String[] ns, String[] es, String[] cs) {
        for (int i = 0; i < 21; i++) {
            for (int j = i + 1; j < 21; j++) {
                if (ns[i].equals(ns[j])) {
                    System.out.println("Same modulus found! (Frame " + i + ", Frame " + j + ")");
                    BigInteger e1 = new BigInteger(es[i], 16);
                    BigInteger e2 = new BigInteger(es[j], 16);
                    BigInteger n = new BigInteger(ns[i], 16);
                    BigInteger c1 = new BigInteger(cs[i], 16);
                    BigInteger c2 = new BigInteger(cs[j], 16);

                    BigInteger[] s = egcd(e1, e2);
                    BigInteger s1 = s[1];
                    BigInteger s2 = s[2];

                    // 求模反元素
                    if (s1.signum() < 0) {
                        s1 = s1.negate();
                        c1 = c1.modInverse(n);
                    }
                    if (s2.signum() < 0) {
                        s2 = s2.negate();
                        c2 = c2.modInverse(n);
                    }

                    // m = c1^s1 * c2^s2 mod n
                    BigInteger m = c1.modPow(s1, n).multiply(c2.modPow(s2, n)).mod(n);

                    // 将 m 转换为字节数组，并转为字符串
                    String plaintext = hexToString(m.toString(16));
                    return plaintext;
                }
            }
        }
        return "";
    }

    /**
     * 因数碰撞法：寻找具有共同因数的模数，并利用这些因数解密明文
     *
     * @param ns 模数数组（16进制字符串）
     * @param es 指数数组（16进制字符串）
     * @param cs 密文数组（16进制字符串）
     * @return 解密后的明文列表（List<String>）
     */
    public static List<String> sameFactor(String[] ns, String[] es, String[] cs) {
        List<String> plaintext = new ArrayList<>();
        List<Integer> index = new ArrayList<>();
        BigInteger p_of_frame = BigInteger.ONE;

        // 寻找具有共同因数的模数对
        for (int i = 0; i < 21; i++) {
            for (int j = i + 1; j < 21; j++) {
                if (new BigInteger(ns[i], 16).equals(new BigInteger(ns[j], 16))) {
                    continue;
                }
                BigInteger gcd = new BigInteger(ns[i], 16).gcd(new BigInteger(ns[j], 16));
                if (gcd.compareTo(BigInteger.ONE) > 0) {
                    System.out.println("Common factor found between Frame" + i + " and Frame" + j);
                    index.add(i);
                    index.add(j);
                    p_of_frame = gcd;
                }
            }
        }

        if (index.size() < 2) {
            return plaintext;
        }

        // 分别计算两个模数的 q 值
        BigInteger q_of_frame1 = new BigInteger(ns[index.get(0)], 16).divide(p_of_frame);
        BigInteger q_of_frame18 = new BigInteger(ns[index.get(1)], 16).divide(p_of_frame);
        //System.out.println("p_of_frame: " + p_of_frame);
        //System.out.println("q_of_frame1: " + q_of_frame1 + ", q_of_frame18: " + q_of_frame18);

        // 计算 phi 值
        BigInteger phi_of_frame1 = p_of_frame.subtract(BigInteger.ONE).multiply(q_of_frame1.subtract(BigInteger.ONE));
        BigInteger phi_of_frame18 = p_of_frame.subtract(BigInteger.ONE).multiply(q_of_frame18.subtract(BigInteger.ONE));

        // 计算私钥 d
        BigInteger d_of_frame1 = new BigInteger(es[index.get(0)], 16).modInverse(phi_of_frame1);
        BigInteger d_of_frame18 = new BigInteger(es[index.get(1)], 16).modInverse(phi_of_frame18);

        // 解密明文
        BigInteger plaintext_of_frame1 = new BigInteger(cs[index.get(0)], 16).modPow(d_of_frame1, new BigInteger(ns[index.get(0)], 16));
        BigInteger plaintext_of_frame18 = new BigInteger(cs[index.get(1)], 16).modPow(d_of_frame18, new BigInteger(ns[index.get(1)], 16));

        // 将明文转换为字符串
        String final_plain1 = hexToString(plaintext_of_frame1.toString(16));
        String final_plain2 = hexToString(plaintext_of_frame18.toString(16));

        plaintext.add(final_plain1);
        plaintext.add(final_plain2);

        return plaintext;
    }

    /**
     * 使用中国剩余定理（Chinese Remainder Theorem）来合并多个同余方程
     *
     * @param items List of pairs (c, n)
     * @return 数组，包含 x 和 N
     */
    public static BigInteger[] chineseRemainderTheorem(List<Pair<BigInteger, BigInteger>> items) {
        BigInteger N = BigInteger.ONE;
        for (Pair<BigInteger, BigInteger> item : items) {
            N = N.multiply(item.getSecond());
        }

        BigInteger result = BigInteger.ZERO;
        for (Pair<BigInteger, BigInteger> item : items) {
            BigInteger a = item.getFirst();
            BigInteger n = item.getSecond();
            BigInteger m = N.divide(n);
            BigInteger[] s = egcd(m, n);
            BigInteger inverse = s[1];
            if (inverse.signum() < 0) {
                inverse = inverse.add(n);
            }
            result = result.add(a.multiply(inverse).multiply(m));
        }

        return new BigInteger[]{result.mod(N), N};
    }

    /**
     * 低加密指数攻击，针对 e=3 的情况
     *
     * @param ns 模数数组（16进制字符串）
     * @param cs 密文数组（16进制字符串）
     * @return 解密后的明文（String）
     */
    public static String lowE3(String[] ns, String[] cs) {
        List<Pair<BigInteger, BigInteger>> sessions = Arrays.asList(
                new Pair<>(new BigInteger(cs[7], 16), new BigInteger(ns[7], 16)),
                new Pair<>(new BigInteger(cs[11], 16), new BigInteger(ns[11], 16)),
                new Pair<>(new BigInteger(cs[15], 16), new BigInteger(ns[15], 16))
        );

        BigInteger[] crt = chineseRemainderTheorem(sessions);
        BigInteger x = crt[0];
        // 直接开三次方根
        BigInteger plaintext = integerRoot(x, 3);
        // 检查是否为精确的三次方根
        if (plaintext.pow(3).equals(x)) {
            return hexToString(plaintext.toString(16));
        } else {
            return "";
        }
    }

    /**
     * 低加密指数攻击，针对 e=5 的情况
     *
     * @param ns 模数数组（16进制字符串）
     * @param cs 密文数组（16进制字符串）
     * @return 解密后的明文（String）
     */
    public static String lowE5(String[] ns, String[] cs) {
        List<Pair<BigInteger, BigInteger>> sessions = Arrays.asList(
                new Pair<>(new BigInteger(cs[3], 16), new BigInteger(ns[3], 16)),
                new Pair<>(new BigInteger(cs[8], 16), new BigInteger(ns[8], 16)),
                new Pair<>(new BigInteger(cs[12], 16), new BigInteger(ns[12], 16)),
                new Pair<>(new BigInteger(cs[16], 16), new BigInteger(ns[16], 16)),
                new Pair<>(new BigInteger(cs[20], 16), new BigInteger(ns[20], 16))
        );

        BigInteger[] crt = chineseRemainderTheorem(sessions);
        BigInteger x = crt[0];
        // 直接开五次方根
        BigInteger plaintext = integerRoot(x, 5);
        // 检查是否为精确的五次方根
        if (plaintext.pow(5).equals(x)) {
            return hexToString(plaintext.toString(16));
        } else {
            return "";
        }
    }

    /**
     * 定义费马分解法，适用于 p 和 q 相近的情况
     *
     * @param n BigInteger
     * @return p 的值（BigInteger）
     */
    public static BigInteger fermatFactor(BigInteger n) {
        BigInteger a = integerCeilSqrt(n);
        BigInteger b2 = a.multiply(a).subtract(n);
        while (!isPerfectSquare(b2)) {
            a = a.add(BigInteger.ONE);
            b2 = a.multiply(a).subtract(n);
        }
        BigInteger b = integerSqrt(b2);
        return a.subtract(b); // 返回 p = a - b
    }

    /**
     * 使用费马分解法分解模数 N，并解密相应的密文
     *
     * @param ns 模数数组（16进制字符串）
     * @param es 指数数组（16进制字符串）
     * @param cs 密文数组（16进制字符串）
     * @return 解密后的明文列表（List<String>）
     */
    public static List<String> fermatResolve(String[] ns, String[] es, String[] cs) {
        List<String> plaintext = new ArrayList<>();
        int i=10;
            
            BigInteger N = new BigInteger(ns[i], 16);
            System.out.println("Attempting Fermat factorization for Frame" + i);
            BigInteger p = fermatFactor(N);
            //System.out.println("p of Frame" + i + " is: " + p);
            BigInteger q = N.divide(p);
            BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
            BigInteger e = new BigInteger(es[i], 16);
            BigInteger d = e.modInverse(phi);
            BigInteger c = new BigInteger(cs[i], 16);
            BigInteger m = c.modPow(d, N);
            String decrypted = hexToString(m.toString(16));
            plaintext.add(decrypted);
        
        return plaintext;
    }

    /**
     * 定义 Pollard p-1 分解法，适用于 p-1 或 q-1 能够被小素数整除的情况
     *
     * @param n BigInteger
     * @return 找到的 p 的值（BigInteger）
     */
    public static BigInteger pollardPminus1(BigInteger n) {
        BigInteger B = BigInteger.valueOf(1 << 20); // 设置 B 的值为 2^20
        BigInteger a = BigInteger.valueOf(2);
        for (BigInteger i = BigInteger.valueOf(2); i.compareTo(B) <= 0; i = i.add(BigInteger.ONE)) {
            a = a.modPow(i, n);
            BigInteger d = a.subtract(BigInteger.ONE).gcd(n);
            if (d.compareTo(BigInteger.ONE) > 0 && d.compareTo(n) < 0) {
                return d;
            }
        }
        return BigInteger.ONE;
    }

    /**
     * 使用 Pollard p-1 分解法分解模数 N，并解密相应的密文
     *
     * @param ns 模数数组（16进制字符串）
     * @param es 指数数组（16进制字符串）
     * @param cs 密文数组（16进制字符串）
     * @return 解密后的明文列表（List<String>）
     */
    public static List<String> pollardResolve(String[] ns, String[] es, String[] cs) {
        List<Integer> indexList = Arrays.asList(2, 6, 19);
        List<String> plaintext = new ArrayList<>();
        for (Integer i : indexList) {
            if (ns[i].isEmpty()) {
                plaintext.add("");
                continue;
            }
            BigInteger N = new BigInteger(ns[i], 16);
            BigInteger c = new BigInteger(cs[i], 16);
            BigInteger e = new BigInteger(es[i], 16);
            System.out.println("Attempting Pollard p-1 factorization for Frame" + i);
            BigInteger p = pollardPminus1(N);
            if (p.equals(BigInteger.ONE)) {
                System.out.println("Pollard p-1 failed to factor Frame" + i);
                plaintext.add("");
                continue;
            }
            System.out.println("p of Frame" + i + " is: " + p);
            BigInteger q = N.divide(p);
            BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
            BigInteger d = e.modInverse(phi);
            BigInteger m = c.modPow(d, N);
            // 检查是否为有效的解
            if (m.compareTo(BigInteger.ZERO) > 0) {
                String decrypted = hexToString(m.toString(16));
                plaintext.add(decrypted);
            } else {
                plaintext.add("");
            }
        }
        return plaintext;
    }

    /**
     * 将十六进制字符串转换为 ASCII 字符串
     *
     * @param hex 十六进制字符串
     * @return ASCII 字符串
     */
    public static String hexToString(String hex) {
        if (hex.length() % 2 != 0) {
            hex = "0" + hex;
        }
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            String str = hex.substring(i, i + 2);
            try {
                output.append((char) Integer.parseInt(str, 16));
            } catch (NumberFormatException e) {
                // 如果无法解析为字符，则忽略
            }
        }
        return output.toString();
    }

    /**
     * 计算整数的平方根
     *
     * @param n BigInteger
     * @return 平方根的 BigInteger 值
     */
    public static BigInteger integerSqrt(BigInteger n) {
        BigInteger a = BigInteger.ONE;
        BigInteger b = n.shiftRight(5).add(BigInteger.valueOf(8));
        while (a.compareTo(b) < 0) {
            BigInteger mid = a.add(b).shiftRight(1);
            if (mid.multiply(mid).compareTo(n) > 0) {
                b = mid;
            } else {
                a = mid.add(BigInteger.ONE);
            }
        }
        return a.subtract(BigInteger.ONE);
    }

    /**
     * 计算整数的 k 次根
     *
     * @param n BigInteger
     * @param k 次数
     * @return k 次根的 BigInteger 值
     */
    public static BigInteger integerRoot(BigInteger n, int k) {
        BigInteger low = BigInteger.ZERO;
        BigInteger high = n;
        while (low.compareTo(high) < 0) {
            BigInteger mid = low.add(high).shiftRight(1);
            BigInteger midPow = mid.pow(k);
            if (midPow.compareTo(n) < 0) {
                low = mid.add(BigInteger.ONE);
            } else {
                high = mid;
            }
        }
        return low;
    }

    /**
     * 检查一个 BigInteger 是否是完美平方
     *
     * @param n BigInteger
     * @return 如果是完美平方，返回 true，否则返回 false
     */
    public static boolean isPerfectSquare(BigInteger n) {
        BigInteger sqrt = integerSqrt(n);
        return sqrt.multiply(sqrt).equals(n);
    }

    /**
     * 计算整数的向上取整平方根
     *
     * @param n BigInteger
     * @return 向上取整后的平方根
     */
    public static BigInteger integerCeilSqrt(BigInteger n) {
        BigInteger sqrt = integerSqrt(n);
        if (sqrt.multiply(sqrt).equals(n)) {
            return sqrt;
        } else {
            return sqrt.add(BigInteger.ONE);
        }
    }

    /**
     * 辅助 Pair 类，用于存储一对对象
     *
     * @param <F> 第一对象类型
     * @param <S> 第二对象类型
     */
    public static class Pair<F, S> {
        private F first;
        private S second;

        public Pair(F first, S second) {
            super();
            this.first = first;
            this.second = second;
        }

        public F getFirst() {
            return first;
        }

        public void setFirst(F first) {
            this.first = first;
        }

        public S getSecond() {
            return second;
        }

        public void setSecond(S second) {
            this.second = second;
        }
    }

    /**
     * 低加密指数攻击的辅助方法，用于打印中间解密过程
     *
     * @param ns 模数数组（16进制字符串）
     * @param cs 密文数组（16进制字符串）
     */
    public static void bruceE3(String[] ns, String[] cs) {
        List<Integer> bruceRange = Arrays.asList(7, 11, 15);
        for (int frameIndex : bruceRange) {
            BigInteger c = new BigInteger(cs[frameIndex], 16);
            BigInteger n = new BigInteger(ns[frameIndex], 16);
            //System.out.println("This is Frame" + frameIndex);
            for (int j = 0; j < 20; j++) {
                BigInteger testValue = c.add(BigInteger.valueOf(j).multiply(n));
                BigInteger root = integerRoot(testValue, 3);
                if (root.pow(3).equals(testValue)) {
                   // System.out.println("This is test" + j);
                    System.out.println(hexToString(root.toString(16)));
                }
            }
        }
    }

    /**
     * 主方法，执行所有攻击方法并输出解密结果
     *
     * @param args 命令行参数
     */
    public static void main(String[] args) throws IOException {
        // 获取当前目录
        String currentDir = System.getProperty("user.dir");

        // 初始化模数、指数和密文数组
        String[] ns = new String[21];
        String[] es = new String[21];
        String[] cs = new String[21];

        // 读取 Frame0 到 Frame20 的内容
        for (int i = 0; i < 21; i++) {
            String filePath = currentDir + "/Frame" + i;
            String content = "";
            try {
                content = new String(Files.readAllBytes(Paths.get(filePath))).trim();
            } catch (IOException e) {
                System.out.println("Failed to read Frame" + i + ". Skipping.");
            }
            if (content.length() < 768) {
                System.out.println("Frame" + i + " 内容不足 768 个字符。");
                ns[i] = "";
                es[i] = "";
                cs[i] = "";
                continue;
            }
            ns[i] = content.substring(0, 256);
            es[i] = content.substring(256, 512);
            cs[i] = content.substring(512, 768);
        }

        // 初始化解密结果数组
        String[] decryptedFrames = new String[21];
        Arrays.fill(decryptedFrames, "");

        // 使用公共模数攻击的方法还原出 Frame0 和 Frame4
        String plaintext0_and_4 = sameModulus(ns, es, cs);
        if (!plaintext0_and_4.isEmpty()) {
            decryptedFrames[0] = plaintext0_and_4;
            decryptedFrames[4] = plaintext0_and_4;
        }
        System.out.println("Frame0 and Frame4: " + plaintext0_and_4);

        // 使用因数碰撞法还原出 Frame1 和 Frame18
        List<String> plaintext1_and_18 = sameFactor(ns, es, cs);
        if (plaintext1_and_18.size() >= 2) {
            decryptedFrames[1] = plaintext1_and_18.get(0);
            decryptedFrames[18] = plaintext1_and_18.get(1);
        }
        System.out.println("Frame1 and Frame18: " + plaintext1_and_18);

        // 使用低加密指数攻击的方法还原 Frame3, Frame8, Frame12, Frame16, Frame20
        String plaintext3_8_12_16_20 = lowE5(ns, cs);
        if (!plaintext3_8_12_16_20.isEmpty()) {
            decryptedFrames[3] = plaintext3_8_12_16_20;
            decryptedFrames[8] = plaintext3_8_12_16_20;
            decryptedFrames[12] = plaintext3_8_12_16_20;
            decryptedFrames[16] = plaintext3_8_12_16_20;
            decryptedFrames[20] = plaintext3_8_12_16_20;
        }
        System.out.println("Frame3, Frame8, Frame12, Frame16, Frame20: " + plaintext3_8_12_16_20);

        // 低加密指数攻击的中间过程
        //System.out.println("bruce start!");
        bruceE3(ns, cs);
       // System.out.println("bruce finished!");

    /*    // 使用低加密指数攻击的方法还原 Frame7, Frame11, Frame15 
    //失败了，跳过
        String plaintext7_11_15 = lowE3(ns, cs);
        if (!plaintext7_11_15.isEmpty()) {
            decryptedFrames[7] = plaintext7_11_15;
            decryptedFrames[11] = plaintext7_11_15;
            decryptedFrames[15] = plaintext7_11_15;
        }
        System.out.println("Frame7, Frame11, Frame15: " + plaintext7_11_15);
 */
        // 使用费马分解法爆破得出 Frame10 和 Frame12 的模数 N 并解密
        List<String> plaintext10 = fermatResolve(ns, es, cs);
            decryptedFrames[10] = plaintext10.get(0);
            System.out.println("Frame10" + ": " + decryptedFrames[10]);
        

        // 使用 Pollard p-1 分解法爆破得出 Frame2, Frame6, Frame19 的模数 N 并解密
        List<String> plaintext2_6_19 = pollardResolve(ns, es, cs);
        if (plaintext2_6_19.size() >= 3) {
            decryptedFrames[2] = plaintext2_6_19.get(0);
            decryptedFrames[6] = plaintext2_6_19.get(1);
            decryptedFrames[19] = plaintext2_6_19.get(2);
        }
        System.out.println("Frame2, Frame6, Frame19: " + plaintext2_6_19);


        // 输出所有 Frame 的解密结果
        System.out.println("\n===== Decrypted Frames =====");
        for (int i = 0; i < 21; i++) {
            System.out.println("Frame" + i + ": " + decryptedFrames[i]);
        }

        // 最终的秘密
        String final_secret = decryptedFrames[0] + decryptedFrames[1] + decryptedFrames[2] + decryptedFrames[3]
                + decryptedFrames[4] + decryptedFrames[6] + decryptedFrames[7] + decryptedFrames[8]
                + decryptedFrames[10] + decryptedFrames[11] + decryptedFrames[12] + decryptedFrames[15]
                + decryptedFrames[16] + decryptedFrames[18] + decryptedFrames[19] + decryptedFrames[20];
        System.out.println("\nFinal Secret: " + final_secret);
    }

    /**
     * 将分解出的 p 和 q 用于解密相应的密文
     *
     * @param ns 模数数组（16进制字符串）
     * @param es 指数数组（16进制字符串）
     * @param cs 密文数组（16进制字符串）
     * @return 解密后的明文列表（List<String>）
     */
    public static List<String> pollardResolveFull(String[] ns, String[] es, String[] cs) {
        return pollardResolve(ns, es, cs);
    }
}
