
import java.util.Arrays;
public class S2C7 {

    public static void main(String[] args) {
        byte[] paddedData = pad("YELLOW SUBMARINE".getBytes(), 20);
        System.out.println("Padded data: " + Arrays.toString(paddedData));

        byte[] unpaddedData = unpad(paddedData);
        System.out.println("Unpadded data: " + new String(unpaddedData));
    }

    public static byte[] pad(byte[] data, int blockSize) {
        int paddingSize = blockSize - (data.length % blockSize);
        byte[] paddedData = new byte[data.length + paddingSize];
        System.arraycopy(data, 0, paddedData, 0, data.length);
        for (int i = data.length; i < paddedData.length; i++) {
            paddedData[i] = (byte) paddingSize;
        }
        return paddedData;
    }

    public static byte[] unpad(byte[] data) {
        int paddingSize = data[data.length - 1];
        byte[] unpaddedData = new byte[data.length - paddingSize];
        System.arraycopy(data, 0, unpaddedData, 0, unpaddedData.length);
        return unpaddedData;
    }
}
