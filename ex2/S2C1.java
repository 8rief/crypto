import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class S2C1 {

    public static void main(String[] args) {
        byte[] buffer = "YELLOW SUBMARINE".getBytes(StandardCharsets.UTF_8);
        byte[] paddedBuffer = padPKCS7(buffer, 20);
        System.out.println(Arrays.toString(paddedBuffer));
    }

    public static byte[] padPKCS7(byte[] buffer, int blockSize) {
        int padding;
        if (buffer.length % blockSize != 0) {
            padding = (buffer.length / blockSize + 1) * blockSize - buffer.length;
        } else {
            padding = 0;
        }

        // Padding size must be less than a byte
        assert 0 <= padding && padding <= 255;

        byte[] newBuffer = Arrays.copyOf(buffer, buffer.length + padding);
        Arrays.fill(newBuffer, buffer.length, newBuffer.length, (byte) padding);
        return newBuffer;
    }
}
