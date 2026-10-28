package hbea;

import java.nio.charset.StandardCharsets;

public final class BitUtils {
    private BitUtils() {} // Utility class

    // Applies a 1-based permutation table to input bits
    public static int[] permute(int[] in, int[] table) {
        int[] out = new int[table.length];
        for (int i = 0; i < table.length; i++) {
            out[i] = in[table[i] - 1];
        }
        return out;
    }

    // XORs two bit arrays of equal length
    public static int[] xor(int[] a, int[] b) {
        if (a == null || b == null) {
            throw new IllegalArgumentException("Inputs to xor cannot be null.");
        }
        if (a.length != b.length) {
            throw new IllegalArgumentException("Arrays must have the same length for XOR operation.");
        }
        int[] result = new int[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }

    // Converts byte array to 8-bit int representations
    public static int[] bytesToBits(byte[] bytes) {
        int[] bits = new int[bytes.length * 8];
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xFF;
            for (int j = 0; j < 8; j++) {
                bits[i * 8 + j] = (b >>> (7 - j)) & 1;
            }
        }
        return bits;
    }

    // Converts bit array back to byte array
    public static byte[] bitsToBytes(int[] bits) {
        byte[] bytes = new byte[bits.length / 8];
        for (int i = 0; i < bytes.length; i++) {
            int b = 0;
            for (int j = 0; j < 8; j++) {
                b = (b << 1) | bits[i * 8 + j];
            }
            bytes[i] = (byte) b;
        }
        return bytes;
    }

    // Converts bit array to Uppercase Hex String
    public static String toHex(int[] bits) {
        byte[] bytes = bitsToBytes(bits);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    // Converts Hex String to bit array
    public static int[] fromHex(String hex) {
        int len = hex.length();
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return bytesToBits(bytes);
    }
}