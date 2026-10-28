package hbea;

public class Main {

    public static void main(String[] args) {
        String email = "ndgrass.ieu2024@student.ie.edu";
        String message = "Meet me at the library at 5 PM!!";

        System.out.println("=================================================");
        System.out.println("            HBEA TEST VECTORS CHECK              ");
        System.out.println("=================================================");

        // Task 1 & Task 2 Verification
        Sha256KeyGenerator keyGen = new Sha256KeyGenerator();
        int[][] ks = keyGen.generateKeySegments(email);

        System.out.println("Seed: " + email);
        System.out.println("SHA-256 Key:");
        int[] fullKey = new int[256];
        for (int i = 0; i < 8; i++) {
            System.arraycopy(ks[i], 0, fullKey, i * 32, 32);
        }
        System.out.println(BitUtils.toHex(fullKey));

        System.out.println("\nKey Segments:");
        System.out.print("KS1...KS4: ");
        for (int i = 0; i < 4; i++) System.out.print(BitUtils.toHex(ks[i]) + " ");
        System.out.print("\nKS5...KS8: ");
        for (int i = 4; i < 8; i++) System.out.print(BitUtils.toHex(ks[i]) + " ");
        System.out.println();

        int[] rk1 = BitUtils.permute(ks[0], HbeaTables.E);
        System.out.println("\nRK1 = E(KS1): " + BitUtils.toHex(rk1));

        // Task 4 Verification (Block 1)
        byte[] msgBytes = message.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        int[] msgBits = BitUtils.bytesToBits(msgBytes);
        int[] block1 = new int[64];
        System.arraycopy(msgBits, 0, block1, 0, 64);

        System.out.println("\nBlock 1 (\"Meet me \"): " + BitUtils.toHex(block1));

        int[] ipBlock1 = BitUtils.permute(block1, HbeaTables.IP);
        System.out.println("IP(Block 1):          " + BitUtils.toHex(ipBlock1));

        int[] L0 = new int[32];
        int[] R0 = new int[32];
        System.arraycopy(ipBlock1, 0, L0, 0, 32);
        System.arraycopy(ipBlock1, 32, R0, 0, 32);
        System.out.println("L0 = " + BitUtils.toHex(L0) + "   R0 = " + BitUtils.toHex(R0));

        int[] eR0 = BitUtils.permute(R0, HbeaTables.E);
        System.out.println("E(R0):             " + BitUtils.toHex(eR0));

        int[] xorRk1 = BitUtils.xor(eR0, rk1);
        System.out.println("E(R0) XOR RK1:     " + BitUtils.toHex(xorRk1));

        // S-Box step
        DesRoundFunction roundFunc = new DesRoundFunction();
        // Extract S-box output manually for vector check
        int[] sOutput32 = new int[32];
        for (int g = 0; g < 8; g++) {
            int b1 = xorRk1[g * 6];
            int b2 = xorRk1[g * 6 + 1];
            int b3 = xorRk1[g * 6 + 2];
            int b4 = xorRk1[g * 6 + 3];
            int b5 = xorRk1[g * 6 + 4];
            int b6 = xorRk1[g * 6 + 5];

            int row = (b1 << 1) | b6;
            int col = (b2 << 3) | (b3 << 2) | (b4 << 1) | b5;
            int val = HbeaTables.S_BOXES[g][row][col];

            sOutput32[g * 4]     = (val >>> 3) & 1;
            sOutput32[g * 4 + 1] = (val >>> 2) & 1;
            sOutput32[g * 4 + 2] = (val >>> 1) & 1;
            sOutput32[g * 4 + 3] = val & 1;
        }
        System.out.println("S-box output:      " + BitUtils.toHex(sOutput32));

        int[] fOut = roundFunc.apply(R0, rk1);
        System.out.println("F(R0, RK1) after P:" + BitUtils.toHex(fOut));

        int[] R1 = BitUtils.xor(L0, fOut);
        int[] L1 = R0;
        System.out.println("After round 1:     L1 = " + BitUtils.toHex(L1) + "   R1 = " + BitUtils.toHex(R1));

        // Full Hbea Encryption Demo
        try {
            Cipher hbea = new HbeaCipher(email);
            String cipherHex = hbea.encrypt(message);
            String decrypted = hbea.decrypt(cipherHex);

            System.out.println("\n--- Full HBEA Cipher Output ---");
            System.out.println("Ciphertext:\n" + cipherHex);
            System.out.println("Decrypted text: " + decrypted);
            System.out.println("Round trip verified: " + hbea.verifyRoundTrip(message));

            // Task 6: Polymorphism Demo with SecureMessenger
            System.out.println("\n=================================================");
            System.out.println("           POLYMORPHISM DEMO (TASK 6)            ");
            System.out.println("=================================================");

            // Plugging in HBEA Cipher
            SecureMessenger messenger = new SecureMessenger(new HbeaCipher(email));
            System.out.println("Active Cipher: " + messenger.getCipherName());
            String encryptedMsg = messenger.send(message);
            System.out.println("Encrypted: " + encryptedMsg);
            System.out.println("Decrypted: " + messenger.receive(encryptedMsg));

            // Swapping to XorCipher with 1 line of code change
            messenger.setCipher(new XorCipher(email));
            System.out.println("\nSwapped Cipher: " + messenger.getCipherName());
            String encryptedXor = messenger.send(message);
            System.out.println("Encrypted: " + encryptedXor);
            System.out.println("Decrypted: " + messenger.receive(encryptedXor));

        } catch (InvalidMessageException e) {
            System.err.println("Message processing failed: " + e.getMessage());
        }
    }
}