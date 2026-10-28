package hbea;

public class DesRoundFunction implements RoundFunction {

    @Override
    public int[] apply(int[] right32, int[] roundKey48) {
        // 1. Expand 32 -> 48 bits
        int[] expandedR = BitUtils.permute(right32, HbeaTables.E);

        // 2. XOR with Round Key (48 bits)
        int[] xored = BitUtils.xor(expandedR, roundKey48);

        // 3. S-Boxes lookup (48 -> 32 bits)
        int[] sOutput32 = new int[32];
        for (int g = 0; g < 8; g++) {
            int b1 = xored[g * 6];
            int b2 = xored[g * 6 + 1];
            int b3 = xored[g * 6 + 2];
            int b4 = xored[g * 6 + 3];
            int b5 = xored[g * 6 + 4];
            int b6 = xored[g * 6 + 5];

            int row = (b1 << 1) | b6;
            int col = (b2 << 3) | (b3 << 2) | (b4 << 1) | b5;

            int val = HbeaTables.S_BOXES[g][row][col];

            sOutput32[g * 4]     = (val >>> 3) & 1;
            sOutput32[g * 4 + 1] = (val >>> 2) & 1;
            sOutput32[g * 4 + 2] = (val >>> 1) & 1;
            sOutput32[g * 4 + 3] = val & 1;
        }

        // 4. Permutation P (32 -> 32 bits)
        return BitUtils.permute(sOutput32, HbeaTables.P);
    }
}