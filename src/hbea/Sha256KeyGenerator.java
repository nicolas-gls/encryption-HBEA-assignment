package hbea;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha256KeyGenerator implements KeyGenerator {

    @Override
    public int[][] generateKeySegments(String seed) {
        String trimmedSeed = seed.trim().toLowerCase();
        byte[] utf8Bytes = trimmedSeed.getBytes(StandardCharsets.UTF_8);

        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available.", e);
        }
        byte[] hash = digest.digest(utf8Bytes);
        int[] keyBits256 = BitUtils.bytesToBits(hash);

        int[][] keySegments = new int[SEGMENTS][SEGMENT_BITS];
        for (int i = 0; i < SEGMENTS; i++) {
            System.arraycopy(keyBits256, i * SEGMENT_BITS, keySegments[i], 0, SEGMENT_BITS);
        }
        return keySegments;
    }
}