import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EPassport {

    private static final String C = "9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI";
    private static final String K = "12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4";

    public static void main(String[] args) throws Exception {
        String preK = pre(K);
        String kSeed = getKSeed(preK);
       
        String key = getKey(kSeed);
        String decryptedText = getP(C, key);
        System.out.println(decryptedText);
    }

    // 预处理密钥，计算校验位
    private static String pre(String k) {
        char[] kArr = k.toCharArray();
        int[] weights = {7, 3, 1, 7, 3, 1};
        int sum = 0;
        for (int i = 21; i < 27; i++) {
            sum = (sum + Character.getNumericValue(kArr[i]) * weights[i - 21]) % 10;
        }
        kArr[27] = Character.forDigit(sum, 10);
        return new String(kArr);
    }

    // 生成种子密钥
    private static String getKSeed(String k) throws NoSuchAlgorithmException {
        String mrzImt = k.substring(0, 10) + k.substring(13, 20) + k.substring(21, 28);
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] hash = sha1.digest(mrzImt.getBytes());
        return bytesToHex(hash).substring(0, 32);
    }

    // 生成Kab密钥
    private static String getKab(String k) {
        StringBuilder kab = new StringBuilder();
        String binaryK = new java.math.BigInteger(k, 16).toString(2);
        // 确保二进制字符串长度为64位
        while (binaryK.length() < 64) {
            binaryK = "0" + binaryK;
        }
        for (int i = 0; i < binaryK.length(); i += 8) {
            String segment = binaryK.substring(i, i + 7);
            kab.append(segment);
            // 奇偶校验
            kab.append(segment.chars().filter(ch -> ch == '1').count() % 2 == 0 ? '1' : '0');
        }
        return new java.math.BigInteger(kab.toString(), 2).toString(16);
    }

    // 生成最终密钥
    private static String getKey(String k) throws NoSuchAlgorithmException {
        k = k + "00000001";
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] hash = sha1.digest(hexStringToByteArray(k));
        return getKab(bytesToHex(hash).substring(0, 16)) + getKab(bytesToHex(hash).substring(16, 32));
    }

    // 解密函数
    private static String getP(String C, String k) throws Exception {
        byte[] decodedC = Base64.getDecoder().decode(C);
        Cipher aes = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(hexStringToByteArray(k), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
        aes.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return new String(aes.doFinal(decodedC));
    }

    // 将字节数组转换为十六进制字符串
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // 将十六进制字符串转换为字节数组
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
