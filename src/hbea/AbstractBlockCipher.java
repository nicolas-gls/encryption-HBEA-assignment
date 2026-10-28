package hbea;

import java.nio.charset.StandardCharsets;

public abstract class AbstractBlockCipher implements Cipher {

    // Overloaded method requirement
    public int[] encrypt(int[] bits256) {
        int[] resultBits = new int[256];
        for (int i = 0; i < 4; i++) {
            int[] block = new int[64];
            System.arraycopy(bits256, i * 64, block, 0, 64);
            int[] encryptedBlock = encryptBlock(block);
            System.arraycopy(encryptedBlock, 0, resultBits, i * 64, 64);
        }
        return resultBits;
    }

    @Override
    public String encrypt(String plaintext) throws InvalidMessageException {
        validate(plaintext);
        String padded = pad(plaintext);
        byte[] bytes = padded.getBytes(StandardCharsets.UTF_8);
        int[] bits256 = BitUtils.bytesToBits(bytes);

        int[] cipherBits = encrypt(bits256);
        return BitUtils.toHex(cipherBits);
    }

    @Override
    public String decrypt(String cipherHex) {
        int[] cipherBits = BitUtils.fromHex(cipherHex);
        int[] plainBits = new int[256];

        for (int i = 0; i < 4; i++) {
            int[] block = new int[64];
            System.arraycopy(cipherBits, i * 64, block, 0, 64);
            int[] decryptedBlock = decryptBlock(block);
            System.arraycopy(decryptedBlock, 0, plainBits, i * 64, 64);
        }

        byte[] plainBytes = BitUtils.bitsToBytes(plainBits);
        String paddedStr = new String(plainBytes, StandardCharsets.UTF_8);
        return unpad(paddedStr);
    }

    protected abstract int[] encryptBlock(int[] block64);
    protected abstract int[] decryptBlock(int[] block64);

    private void validate(String message) throws InvalidMessageException {
        if (message == null || message.isEmpty()) {
            throw new InvalidMessageException("Message cannot be null or empty.");
        }
        if (message.length() > 32) {
            throw new InvalidMessageException("Message cannot exceed 32 characters.");
        }
        for (char c : message.toCharArray()) {
            if (c < 32 || c > 126) {
                throw new InvalidMessageException("Message contains non-printable ASCII character: '" + c + "'");
            }
        }
    }

    private String pad(String message) {
        StringBuilder sb = new StringBuilder(message);
        while (sb.length() < 32) {
            sb.append('\0');
        }
        return sb.toString();
    }

    private String unpad(String message) {
        int nulIndex = message.indexOf('\0');
        if (nulIndex != -1) {
            return message.substring(0, nulIndex);
        }
        return message;
    }
}