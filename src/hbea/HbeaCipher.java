package hbea;

public class HbeaCipher extends AbstractBlockCipher {

    private final int[][] roundKeys; // 8 x 48 bits
    private final RoundFunction f;

    public HbeaCipher(String email) {
        this(email, new Sha256KeyGenerator(), new DesRoundFunction());
    }

    public HbeaCipher(String email, KeyGenerator keyGen, RoundFunction roundFunction) {
        this.f = roundFunction;
        int[][] keySegments = keyGen.generateKeySegments(email);
        this.roundKeys = new int[8][48];

        for (int i = 0; i < 8; i++) {
            this.roundKeys[i] = BitUtils.permute(keySegments[i], HbeaTables.E);
        }
    }

    @Override
    public String getName() {
        return "HBEA (Hybrid Block Encryption Algorithm)";
    }

    @Override
    protected int[] encryptBlock(int[] block64) {
        return runBlockRounds(block64, false);
    }

    @Override
    protected int[] decryptBlock(int[] block64) {
        return runBlockRounds(block64, true);
    }

    private int[] runBlockRounds(int[] block64, boolean reverseKeys) {
        // Initial Permutation
        int[] x = BitUtils.permute(block64, HbeaTables.IP);

        int[] L = new int[32];
        int[] R = new int[32];
        System.arraycopy(x, 0, L, 0, 32);
        System.arraycopy(x, 32, R, 0, 32);

        // 8 Feistel Rounds
        for (int round = 1; round <= 8; round++) {
            int[] rk = reverseKeys ? roundKeys[8 - round] : roundKeys[round - 1];

            int[] nextL = R;
            int[] fOut = f.apply(R, rk);
            int[] nextR = BitUtils.xor(L, fOut);

            L = nextL;
            R = nextR;
        }

        // Pre-output swap: R8 + L8
        int[] preOutput = new int[64];
        System.arraycopy(R, 0, preOutput, 0, 32);
        System.arraycopy(L, 0, preOutput, 32, 32);

        // Final Permutation
        return BitUtils.permute(preOutput, HbeaTables.IP_INV);
    }
}