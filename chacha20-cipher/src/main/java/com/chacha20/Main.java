package com.chacha20;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * Console-based demonstration and interactive testing tool for ChaCha20 Stream Cipher.
 * Designed for BCS703 Cryptography and Network Security Assignment.
 */
public class Main {

    private static final Scanner scanner = new Scanner(System.in);
    private static final SecureRandom secureRandom = new SecureRandom();

    public static void main(String[] args) {
        printBanner();

        boolean running = true;
        while (running) {
            printMenu();
            System.out.print("Select an option (1-5): ");
            String input = scanner.nextLine().trim();

            switch (input) {
                case "1":
                    handleEncryptOption();
                    break;
                case "2":
                    handleDecryptOption();
                    break;
                case "3":
                    runAllDemonstrationTests();
                    break;
                case "4":
                    runRfc8439TestVector();
                    break;
                case "5":
                    System.out.println("\nThank you for using ChaCha20 Stream Cipher Demo. Exiting...");
                    running = false;
                    break;
                default:
                    System.out.println("\n[!] Invalid selection. Please enter a number between 1 and 5.\n");
            }
        }
    }

    private static void printBanner() {
        System.out.println("===============================================================");
        System.out.println("          ChaCha20 Stream Cipher Implementation Demo          ");
        System.out.println("     BCS703: Cryptography and Network Security Assignment      ");
        System.out.println("             Standard: RFC 8439 (IETF ChaCha20)                ");
        System.out.println("===============================================================");
    }

    private static void printMenu() {
        System.out.println("\n--------------------------- MAIN MENU -------------------------");
        System.out.println("  1. Encrypt Text (with custom or random Key & Nonce)");
        System.out.println("  2. Decrypt Hex Ciphertext");
        System.out.println("  3. Run Built-in Test Cases Suite");
        System.out.println("  4. Run Official RFC 8439 Test Vector");
        System.out.println("  5. Exit");
        System.out.println("---------------------------------------------------------------");
    }

    private static void handleEncryptOption() {
        System.out.println("\n--- [1] ENCRYPT TEXT ---");

        System.out.print("Enter plaintext (or press ENTER for default demo message): ");
        String text = scanner.nextLine();
        if (text.isEmpty()) {
            text = "ChaCha20 is a high-speed, secure stream cipher specified in RFC 8439.";
            System.out.println("Using default plaintext: \"" + text + "\"");
        }

        System.out.print("Enter 256-bit Key in hex (64 hex chars, or press ENTER to generate random): ");
        String keyHex = scanner.nextLine().trim();
        byte[] key;
        if (keyHex.isEmpty()) {
            key = new byte[32];
            secureRandom.nextBytes(key);
            System.out.println("Generated Random Key: " + HexUtils.bytesToHex(key));
        } else {
            try {
                key = HexUtils.hexToBytes(keyHex);
                InputValidator.validateKey(key);
            } catch (Exception e) {
                System.out.println("[ERROR] " + e.getMessage());
                return;
            }
        }

        System.out.print("Enter 96-bit Nonce in hex (24 hex chars, or press ENTER to generate random): ");
        String nonceHex = scanner.nextLine().trim();
        byte[] nonce;
        if (nonceHex.isEmpty()) {
            nonce = new byte[12];
            secureRandom.nextBytes(nonce);
            System.out.println("Generated Random Nonce: " + HexUtils.bytesToHex(nonce));
        } else {
            try {
                nonce = HexUtils.hexToBytes(nonceHex);
                InputValidator.validateNonce(nonce);
            } catch (Exception e) {
                System.out.println("[ERROR] " + e.getMessage());
                return;
            }
        }

        System.out.print("Enter initial block counter (default = 1): ");
        String counterStr = scanner.nextLine().trim();
        int counter = 1;
        if (!counterStr.isEmpty()) {
            try {
                long c = Long.parseLong(counterStr);
                InputValidator.validateCounter(c);
                counter = (int) c;
            } catch (Exception e) {
                System.out.println("[ERROR] Invalid counter: " + e.getMessage());
                return;
            }
        }

        byte[] plaintextBytes = text.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = ChaCha20.encrypt(key, counter, nonce, plaintextBytes);
        byte[] decrypted = ChaCha20.decrypt(key, counter, nonce, ciphertext);
        String decryptedText = new String(decrypted, StandardCharsets.UTF_8);

        System.out.println("\n---------------------- ENCRYPTION RESULT ----------------------");
        System.out.println("Plaintext:          " + text);
        System.out.println("Plaintext Length:   " + plaintextBytes.length + " bytes (" + ((plaintextBytes.length + 63) / 64) + " ChaCha20 block(s))");
        System.out.println("Key (256-bit):      " + HexUtils.bytesToHex(key));
        System.out.println("Nonce (96-bit):     " + HexUtils.bytesToHex(nonce));
        System.out.println("Block Counter:      " + counter);
        System.out.println("Ciphertext (Hex):   " + HexUtils.bytesToHex(ciphertext));
        System.out.println("Decrypted Text:     " + decryptedText);
        System.out.println("Integrity Check:    " + (text.equals(decryptedText) ? "[PASS] Exact match verified!" : "[FAIL] Mismatch!"));
        System.out.println("---------------------------------------------------------------");
    }

    private static void handleDecryptOption() {
        System.out.println("\n--- [2] DECRYPT HEX CIPHERTEXT ---");

        System.out.print("Enter Ciphertext in hex: ");
        String cipherHex = scanner.nextLine().trim();
        byte[] ciphertext;
        try {
            ciphertext = HexUtils.hexToBytes(cipherHex);
            InputValidator.validateData(ciphertext);
        } catch (Exception e) {
            System.out.println("[ERROR] " + e.getMessage());
            return;
        }

        System.out.print("Enter 256-bit Key in hex (64 hex chars): ");
        String keyHex = scanner.nextLine().trim();
        byte[] key;
        try {
            key = HexUtils.hexToBytes(keyHex);
            InputValidator.validateKey(key);
        } catch (Exception e) {
            System.out.println("[ERROR] " + e.getMessage());
            return;
        }

        System.out.print("Enter 96-bit Nonce in hex (24 hex chars): ");
        String nonceHex = scanner.nextLine().trim();
        byte[] nonce;
        try {
            nonce = HexUtils.hexToBytes(nonceHex);
            InputValidator.validateNonce(nonce);
        } catch (Exception e) {
            System.out.println("[ERROR] " + e.getMessage());
            return;
        }

        System.out.print("Enter initial block counter (default = 1): ");
        String counterStr = scanner.nextLine().trim();
        int counter = 1;
        if (!counterStr.isEmpty()) {
            try {
                long c = Long.parseLong(counterStr);
                InputValidator.validateCounter(c);
                counter = (int) c;
            } catch (Exception e) {
                System.out.println("[ERROR] Invalid counter: " + e.getMessage());
                return;
            }
        }

        byte[] decrypted = ChaCha20.decrypt(key, counter, nonce, ciphertext);
        String decryptedText = new String(decrypted, StandardCharsets.UTF_8);

        System.out.println("\n---------------------- DECRYPTION RESULT ----------------------");
        System.out.println("Ciphertext (Hex):   " + HexUtils.bytesToHex(ciphertext));
        System.out.println("Key (Hex):          " + HexUtils.bytesToHex(key));
        System.out.println("Nonce (Hex):        " + HexUtils.bytesToHex(nonce));
        System.out.println("Counter:            " + counter);
        System.out.println("Decrypted (Hex):    " + HexUtils.bytesToHex(decrypted));
        System.out.println("Decrypted (UTF-8):  " + decryptedText);
        System.out.println("---------------------------------------------------------------");
    }

    public static void runRfc8439TestVector() {
        System.out.println("\n===============================================================");
        System.out.println("           RFC 8439 Section 2.4.2 Official Test Vector          ");
        System.out.println("===============================================================");

        // RFC 8439 Section 2.4.2 Test Vector parameters:
        // Key: 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f
        byte[] key = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };

        // Nonce: 00:00:00:00:00:00:00:4a:00:00:00:00 (12 bytes)
        byte[] nonce = new byte[]{
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x4a,
                0x00, 0x00, 0x00, 0x00
        };

        int initialCounter = 1;

        String plaintextStr = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        byte[] plaintextBytes = plaintextStr.getBytes(StandardCharsets.US_ASCII);

        String expectedCiphertextHex =
                "6e2e359a2568f98041ba0728dd0d6981" +
                "e97e7aec1d4360c20a27afccfd9fae0b" +
                "f91b65c5524733ab8f593dabcd62b357" +
                "1639d624e65152ab8f530c359f0861d8" +
                "07ca0dbf500d6a6156a38e088a22b65e" +
                "52bc514d16ccf806818ce91ab7793736" +
                "5af90bbf74a35be6b40b8eedf2785e42" +
                "874d";

        System.out.println("Key (256-bit):");
        System.out.println("  " + HexUtils.bytesToSpacedHex(key));
        System.out.println("Nonce (96-bit):");
        System.out.println("  " + HexUtils.bytesToSpacedHex(nonce));
        System.out.println("Initial Counter: " + initialCounter);
        System.out.println("Plaintext (" + plaintextBytes.length + " bytes):");
        System.out.println("  \"" + plaintextStr + "\"");

        // Execute encryption
        byte[] actualCiphertextBytes = ChaCha20.encrypt(key, initialCounter, nonce, plaintextBytes);
        String actualCiphertextHex = HexUtils.bytesToHex(actualCiphertextBytes);

        System.out.println("\nExpected Ciphertext Hex (RFC 8439 Section 2.4.2):");
        System.out.println("  " + expectedCiphertextHex);
        System.out.println("Actual Generated Ciphertext Hex:");
        System.out.println("  " + actualCiphertextHex);

        boolean match = expectedCiphertextHex.equalsIgnoreCase(actualCiphertextHex);
        System.out.println("\nVerification Result: " + (match ? "[PASS] MATCHES RFC 8439 EXACTLY!" : "[FAIL] DOES NOT MATCH!"));

        // Decryption test
        byte[] decryptedBytes = ChaCha20.decrypt(key, initialCounter, nonce, actualCiphertextBytes);
        String decryptedStr = new String(decryptedBytes, StandardCharsets.US_ASCII);
        System.out.println("Decrypted Plaintext:");
        System.out.println("  \"" + decryptedStr + "\"");
        System.out.println("Decryption Correctness: " + (plaintextStr.equals(decryptedStr) ? "[PASS] Decryption verified!" : "[FAIL] Mismatch!"));
        System.out.println("===============================================================");
    }

    public static void runAllDemonstrationTests() {
        System.out.println("\n===============================================================");
        System.out.println("                  ChaCha20 Test Suite Execution                ");
        System.out.println("===============================================================");

        int passed = 0;
        int total = 10;

        // Test 1: Basic Encryption/Decryption
        try {
            byte[] key = HexUtils.hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            byte[] nonce = HexUtils.hexToBytes("000000000000004a00000000");
            byte[] msg = "Network Security Assignment".getBytes(StandardCharsets.UTF_8);
            byte[] ct = ChaCha20.encrypt(key, 1, nonce, msg);
            byte[] pt = ChaCha20.decrypt(key, 1, nonce, ct);
            if (java.util.Arrays.equals(msg, pt)) {
                System.out.println("[PASS] TEST 1: Basic Encryption / Decryption");
                passed++;
            } else {
                System.out.println("[FAIL] TEST 1: Basic Encryption / Decryption");
            }
        } catch (Exception e) {
            System.out.println("[FAIL] TEST 1: " + e.getMessage());
        }

        // Test 2: Short Plaintext ("Hello")
        try {
            byte[] key = HexUtils.hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            byte[] nonce = HexUtils.hexToBytes("000000000000004a00000000");
            byte[] msg = "Hello".getBytes(StandardCharsets.UTF_8);
            byte[] ct = ChaCha20.encrypt(key, 1, nonce, msg);
            byte[] pt = ChaCha20.decrypt(key, 1, nonce, ct);
            if (java.util.Arrays.equals(msg, pt) && ct.length == 5) {
                System.out.println("[PASS] TEST 2: Short Plaintext (\"Hello\")");
                passed++;
            } else {
                System.out.println("[FAIL] TEST 2: Short Plaintext");
            }
        } catch (Exception e) {
            System.out.println("[FAIL] TEST 2: " + e.getMessage());
        }

        // Test 3: Empty Plaintext
        try {
            byte[] key = HexUtils.hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            byte[] nonce = HexUtils.hexToBytes("000000000000004a00000000");
            byte[] msg = new byte[0];
            byte[] ct = ChaCha20.encrypt(key, 1, nonce, msg);
            byte[] pt = ChaCha20.decrypt(key, 1, nonce, ct);
            if (ct.length == 0 && pt.length == 0) {
                System.out.println("[PASS] TEST 3: Empty Plaintext (0-length byte array)");
                passed++;
            } else {
                System.out.println("[FAIL] TEST 3: Empty Plaintext");
            }
        } catch (Exception e) {
            System.out.println("[FAIL] TEST 3: " + e.getMessage());
        }

        // Test 4: Multi-block Long Plaintext (> 64 bytes)
        try {
            byte[] key = HexUtils.hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            byte[] nonce = HexUtils.hexToBytes("000000000000004a00000000");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 10; i++) {
                sb.append("This is block number ").append(i).append(" of multi-block ChaCha20 test. ");
            }
            byte[] msg = sb.toString().getBytes(StandardCharsets.UTF_8);
            byte[] ct = ChaCha20.encrypt(key, 1, nonce, msg);
            byte[] pt = ChaCha20.decrypt(key, 1, nonce, ct);
            if (msg.length > 64 && java.util.Arrays.equals(msg, pt)) {
                System.out.println("[PASS] TEST 4: Multi-block Long Plaintext (" + msg.length + " bytes across multiple 64-byte blocks)");
                passed++;
            } else {
                System.out.println("[FAIL] TEST 4: Multi-block Long Plaintext");
            }
        } catch (Exception e) {
            System.out.println("[FAIL] TEST 4: " + e.getMessage());
        }

        // Test 5: Different Keys Produce Different Ciphertext
        try {
            byte[] key1 = HexUtils.hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            byte[] key2 = HexUtils.hexToBytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            byte[] nonce = HexUtils.hexToBytes("000000000000004a00000000");
            byte[] msg = "Cryptographic Security".getBytes(StandardCharsets.UTF_8);
            byte[] ct1 = ChaCha20.encrypt(key1, 1, nonce, msg);
            byte[] ct2 = ChaCha20.encrypt(key2, 1, nonce, msg);
            if (!java.util.Arrays.equals(ct1, ct2)) {
                System.out.println("[PASS] TEST 5: Different Keys -> Different Ciphertext");
                passed++;
            } else {
                System.out.println("[FAIL] TEST 5: Different Keys");
            }
        } catch (Exception e) {
            System.out.println("[FAIL] TEST 5: " + e.getMessage());
        }

        // Test 6: Determinism (Same parameters produce identical ciphertext)
        try {
            byte[] key = HexUtils.hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            byte[] nonce = HexUtils.hexToBytes("000000000000004a00000000");
            byte[] msg = "Deterministic stream cipher output".getBytes(StandardCharsets.UTF_8);
            byte[] ct1 = ChaCha20.encrypt(key, 1, nonce, msg);
            byte[] ct2 = ChaCha20.encrypt(key, 1, nonce, msg);
            if (java.util.Arrays.equals(ct1, ct2)) {
                System.out.println("[PASS] TEST 6: Same Parameters -> Identical Ciphertext (Deterministic)");
                passed++;
            } else {
                System.out.println("[FAIL] TEST 6: Determinism");
            }
        } catch (Exception e) {
            System.out.println("[FAIL] TEST 6: Determinism");
        }

        // Test 7: Different Nonce Produces Different Ciphertext
        try {
            byte[] key = HexUtils.hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            byte[] nonce1 = HexUtils.hexToBytes("000000000000004a00000000");
            byte[] nonce2 = HexUtils.hexToBytes("000000000000004a00000001");
            byte[] msg = "Sensitive payload data".getBytes(StandardCharsets.UTF_8);
            byte[] ct1 = ChaCha20.encrypt(key, 1, nonce1, msg);
            byte[] ct2 = ChaCha20.encrypt(key, 1, nonce2, msg);
            if (!java.util.Arrays.equals(ct1, ct2)) {
                System.out.println("[PASS] TEST 7: Different Nonce -> Different Ciphertext");
                passed++;
            } else {
                System.out.println("[FAIL] TEST 7: Different Nonce");
            }
        } catch (Exception e) {
            System.out.println("[FAIL] TEST 7: " + e.getMessage());
        }

        // Test 8: Different Counter Produces Different Keystream / Ciphertext
        try {
            byte[] key = HexUtils.hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            byte[] nonce = HexUtils.hexToBytes("000000000000004a00000000");
            byte[] msg = "Counter value variation test".getBytes(StandardCharsets.UTF_8);
            byte[] ct1 = ChaCha20.encrypt(key, 1, nonce, msg);
            byte[] ct2 = ChaCha20.encrypt(key, 2, nonce, msg);
            if (!java.util.Arrays.equals(ct1, ct2)) {
                System.out.println("[PASS] TEST 8: Different Counter -> Different Ciphertext");
                passed++;
            } else {
                System.out.println("[FAIL] TEST 8: Different Counter");
            }
        } catch (Exception e) {
            System.out.println("[FAIL] TEST 8: " + e.getMessage());
        }

        // Test 9: RFC 8439 Official Test Vector
        try {
            byte[] key = new byte[]{
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
            };
            byte[] nonce = new byte[]{
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x4a,
                    0x00, 0x00, 0x00, 0x00
            };
            int counter = 1;
            String pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
            String expectedHex =
                    "6e2e359a2568f98041ba0728dd0d6981" +
                    "e97e7aec1d4360c20a27afccfd9fae0b" +
                    "f91b65c5524733ab8f593dabcd62b357" +
                    "1639d624e65152ab8f530c359f0861d8" +
                    "07ca0dbf500d6a6156a38e088a22b65e" +
                    "52bc514d16ccf806818ce91ab7793736" +
                    "5af90bbf74a35be6b40b8eedf2785e42" +
                    "874d";

            byte[] ct = ChaCha20.encrypt(key, counter, nonce, pt.getBytes(StandardCharsets.US_ASCII));
            String actualHex = HexUtils.bytesToHex(ct);
            if (expectedHex.equalsIgnoreCase(actualHex)) {
                System.out.println("[PASS] TEST 9: RFC 8439 Official Test Vector (Exact Match)");
                passed++;
            } else {
                System.out.println("[FAIL] TEST 9: RFC 8439 Official Test Vector");
            }
        } catch (Exception e) {
            System.out.println("[FAIL] TEST 9: " + e.getMessage());
        }

        // Test 10: Full Round-Trip Decrypt(Encrypt(M)) == M
        try {
            byte[] key = new byte[32];
            byte[] nonce = new byte[12];
            for (int i = 0; i < 32; i++) key[i] = (byte) (i * 7);
            for (int i = 0; i < 12; i++) nonce[i] = (byte) (i * 13);
            byte[] msg = "Testing arbitrary round-trip encryption/decryption with varied keys and nonces.".getBytes(StandardCharsets.UTF_8);
            byte[] ct = ChaCha20.encrypt(key, 42, nonce, msg);
            byte[] pt = ChaCha20.decrypt(key, 42, nonce, ct);
            if (java.util.Arrays.equals(msg, pt)) {
                System.out.println("[PASS] TEST 10: Round-Trip Integrity Decrypt(Encrypt(P)) == P");
                passed++;
            } else {
                System.out.println("[FAIL] TEST 10: Round-Trip Integrity");
            }
        } catch (Exception e) {
            System.out.println("[FAIL] TEST 10: " + e.getMessage());
        }

        System.out.println("---------------------------------------------------------------");
        System.out.println("Summary: " + passed + "/" + total + " tests passed.");
        if (passed == total) {
            System.out.println("Result: [SUCCESS] All built-in demonstration tests passed successfully!");
        } else {
            System.out.println("Result: [FAILURE] Some tests failed!");
        }
        System.out.println("===============================================================");
    }
}
