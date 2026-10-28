package hbea;

public class XorCipher extends AbstractBlockCipher {

    private final int[] key64;

    public XorCipher(String email) {
        Sha256KeyGenerator keyGen = new Sha256KeyGenerator();
        int[][] keySegments = keyGen.generateKeySegments(email);

        // Combine KS1 and KS2 (first 64 bits)
        this.key64 = new int[64];
        System.arraycopy(keySegments[0], 0, key64, 0, 32);
        System.arraycopy(keySegments[1], 0, key64, 32, 32);
    }

    @Override
    public String getName() {
        return "XOR Simple Cipher";
    }

    @Override
    protected int[] encryptBlock(int[] block64) {
        return BitUtils.xor(block64, key64);
    }

    @Override
    protected int[] decryptBlock(int[] block64) {
        return BitUtils.xor(block64, key64);
    }
}