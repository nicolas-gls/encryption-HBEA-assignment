package hbea;

public class HbeaSimpleTests {

    private static int totalTests = 0;
    private static int passedTests = 0;

    public static void main(String[] args) {
        System.out.println("=================================================");
        System.out.println("         RUNNING HBEA SIMPLE TEST SUITE          ");
        System.out.println("=================================================\n");

        // Task 1: Input Validation and Padding (TDD)
        testTask1_ValidationAndPadding();

        // Task 2: Key Generation (BDD)
        testTask2_KeyGeneration();

        // Task 3: XOR Operations & Exceptions (TDD)
        testTask3_XorOperations();

        // Task 4: Round Function Components & Section 7 Vectors (Unit Tests)
        testTask4_RoundFunctionAndVectors();

        // Task 5: Full Encryption, Decryption & Key Isolation (BDD)
        testTask5_FullEncryptionAndDecryption();

        // Task 6: Polymorphism with SecureMessenger
        testTask6_PolymorphismDemo();

        System.out.println("\n=================================================");
        System.out.println(String.format("TEST RESULTS: %d/%d PASSED", passedTests, totalTests));
        System.out.println("=================================================");
    }

    // --- Task 1 Tests ---
    private static void testTask1_ValidationAndPadding() {
        System.out.println("--- Task 1: Validation & Padding Tests ---");
        Cipher cipher = new HbeaCipher("test@student.ie.edu");

        // Null message
        assertThrows("Task 1: Null message throws InvalidMessageException", () -> cipher.encrypt(null));

        // Empty message
        assertThrows("Task 1: Empty message throws InvalidMessageException", () -> cipher.encrypt(""));

        // Message > 32 characters
        assertThrows("Task 1: >32 chars throws InvalidMessageException",
                () -> cipher.encrypt("This message is way too long to fit into 32 chars!!"));

        // Non-ASCII character
        assertThrows("Task 1: Non-ASCII char 'é' throws InvalidMessageException",
                () -> cipher.encrypt("Café"));

        // Valid short message (padding applied)
        assertTrue("Task 1: Short message encrypts to 64 hex digits", () -> {
            String hex = cipher.encrypt("Hello");
            return hex != null && hex.length() == 64;
        });

        // Exactly 32 characters (no padding needed)
        assertTrue("Task 1: Exactly 32 chars encrypts to 64 hex digits", () -> {
            String hex = cipher.encrypt("Meet me at the library at 5 PM!!");
            return hex != null && hex.length() == 64;
        });
    }

    // --- Task 2 Tests ---
    private static void testTask2_KeyGeneration() {
        System.out.println("\n--- Task 2: Key Generation (BDD) ---");
        KeyGenerator keyGen = new Sha256KeyGenerator();

        // Scenario: Given "student@student.ie.edu", When key generated, Then KS1 = 6C099BA0
        assertTrue("Task 2: BDD Scenario 1 - Correct KS1 generated for official email", () -> {
            int[][] ks = keyGen.generateKeySegments("student@student.ie.edu");
            return BitUtils.toHex(ks[0]).equals("6C099BA0");
        });

        // Scenario: Given " Student@Student.IE.edu " (spaces + caps), Then same KS1 produced
        assertTrue("Task 2: BDD Scenario 2 - Trimming & lowercase handling", () -> {
            int[][] ks1 = keyGen.generateKeySegments("student@student.ie.edu");
            int[][] ks2 = keyGen.generateKeySegments(" Student@Student.IE.edu ");
            return BitUtils.toHex(ks1[0]).equals(BitUtils.toHex(ks2[0]));
        });
    }

    // --- Task 3 Tests ---
    private static void testTask3_XorOperations() {
        System.out.println("\n--- Task 3: XOR (TDD + Exceptions) ---");

        // Known XOR result
        assertTrue("Task 3: BitUtils.xor with known values", () -> {
            int[] a = {1, 0, 1, 0};
            int[] b = {1, 1, 0, 0};
            int[] expected = {0, 1, 1, 0};
            int[] actual = BitUtils.xor(a, b);
            for (int i = 0; i < 4; i++) {
                if (actual[i] != expected[i]) return false;
            }
            return true;
        });

        // Mismatched lengths throw exception
        assertThrows("Task 3: Mismatched array lengths throw IllegalArgumentException", () -> {
            BitUtils.xor(new int[4], new int[6]);
        });

        // Null argument throws exception
        assertThrows("Task 3: Null input throws IllegalArgumentException", () -> {
            BitUtils.xor(null, new int[4]);
        });
    }

    // --- Task 4 Tests ---
    private static void testTask4_RoundFunctionAndVectors() {
        System.out.println("\n--- Task 4: Round Function & Section 7 Test Vectors ---");

        int[] ks1 = BitUtils.fromHex("6C099BA0");
        int[] rk1 = BitUtils.permute(ks1, HbeaTables.E);

        assertTrue("Task 4: RK1 = E(KS1) matches test vector (358053CF7D00)", () ->
                BitUtils.toHex(rk1).equals("358053CF7D00")
        );

        int[] r0 = BitUtils.fromHex("00FE2100");
        int[] eR0 = BitUtils.permute(r0, HbeaTables.E);
        assertTrue("Task 4: E(R0) matches test vector (0017FC102800)", () ->
                BitUtils.toHex(eR0).equals("0017FC102800")
        );

        int[] xorRk1 = BitUtils.xor(eR0, rk1);
        assertTrue("Task 4: E(R0) XOR RK1 matches test vector (3597AFDF5500)", () ->
                BitUtils.toHex(xorRk1).equals("3597AFDF5500")
        );

        DesRoundFunction roundFunc = new DesRoundFunction();
        int[] fOut = roundFunc.apply(r0, rk1);
        assertTrue("Task 4: F(R0, RK1) matches test vector (6B80A973)", () ->
                BitUtils.toHex(fOut).equals("6B80A973")
        );
    }

    // --- Task 5 Tests ---
    private static void testTask5_FullEncryptionAndDecryption() {
        System.out.println("\n--- Task 5: Full Encryption & Key Isolation (BDD) ---");
        String email = "student@student.ie.edu";
        String message = "Meet me at the library at 5 PM!!";
        String expectedCipherHex = "AB980FB8275358AE1D411D5FF38B89E5DCAD224E7282B8A8FF7A945EE97A5D40";

        assertTrue("Task 5: HBEA full ciphertext matches Section 7 test vector", () -> {
            Cipher cipher = new HbeaCipher(email);
            return cipher.encrypt(message).equals(expectedCipherHex);
        });

        assertTrue("Task 5: Given encrypted msg, When decrypted, Then original returned", () -> {
            Cipher cipher = new HbeaCipher(email);
            String cipherHex = cipher.encrypt(message);
            return cipher.decrypt(cipherHex).equals(message);
        });

        assertTrue("Task 5: Decrypting with wrong email fails to yield original message", () -> {
            Cipher correctCipher = new HbeaCipher(email);
            Cipher wrongCipher = new HbeaCipher("wrong.email@student.ie.edu");
            String cipherHex = correctCipher.encrypt(message);
            String decryptedWithWrongKey = wrongCipher.decrypt(cipherHex);
            return !decryptedWithWrongKey.equals(message);
        });
    }

    // --- Task 6 Tests ---
    private static void testTask6_PolymorphismDemo() {
        System.out.println("\n--- Task 6: Polymorphism Demo ---");
        String email = "student@student.ie.edu";
        String msg = "Test message for polymorphism!!";

        assertTrue("Task 6: SecureMessenger works interchangeably with Hbea and Xor Ciphers", () -> {
            Cipher hbea = new HbeaCipher(email);
            Cipher xor = new XorCipher(email);

            SecureMessenger messenger = new SecureMessenger(hbea);
            String hbeaEnc = messenger.send(msg);
            boolean hbeaOk = messenger.receive(hbeaEnc).equals(msg);

            messenger.setCipher(xor);
            String xorEnc = messenger.send(msg);
            boolean xorOk = messenger.receive(xorEnc).equals(msg);

            return hbeaOk && xorOk;
        });
    }

    // --- Test Helper Assertions ---
    private static void assertTrue(String testName, BooleanCondition condition) {
        totalTests++;
        try {
            if (condition.run()) {
                System.out.println("[PASS] " + testName);
                passedTests++;
            } else {
                System.err.println("[FAIL] " + testName);
            }
        } catch (Exception e) {
            System.err.println("[FAIL] " + testName + " (Unexpected Exception: " + e.getMessage() + ")");
        }
    }

    private static void assertThrows(String testName, Executable block) {
        totalTests++;
        try {
            block.run();
            System.err.println("[FAIL] " + testName + " (Expected exception was not thrown)");
        } catch (Exception e) {
            System.out.println("[PASS] " + testName);
            passedTests++;
        }
    }

    @FunctionalInterface
    interface BooleanCondition {
        boolean run() throws Exception;
    }

    @FunctionalInterface
    interface Executable {
        void run() throws Exception;
    }
}