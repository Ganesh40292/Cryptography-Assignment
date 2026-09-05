package com.chacha20;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;
import java.util.Scanner;

/**
 * Interactive Console CLI and Demonstration Studio for ChaCha20, Round Variants,
 * ChaCha20-Poly1305 AEAD, File Encryption, Avalanche Analysis, and Benchmarking.
 *
 * <p>Course: BCS703 — Cryptography and Network Security
 * <p>Standards: RFC 8439 (IETF ChaCha20 and Poly1305 AEAD)
 */
public class Main {

    private static final Scanner scanner = new Scanner(System.in);
    private static final SecureRandom secureRandom = new SecureRandom();

    public static void main(String[] args) {
        printBanner();

        boolean running = true;
        while (running) {
            printMenu();
            System.out.print("Select an option (1-10): ");
            String input = scanner.nextLine().trim();

            switch (input) {
                case "1":
                    handleEncryptOption();
                    break;
                case "2":
                    handleDecryptOption();
                    break;
                case "3":
                    handleAeadEncryptOption();
                    break;
                case "4":
                    handleAeadDecryptOption();
                    break;
                case "5":
                    handleFileCipherOption();
                    break;
                case "6":
                    handleAvalancheOption();
                    break;
                case "7":
                    handleBenchmarkOption();
                    break;
                case "8":
                    handleTraceOption();
                    break;
                case "9":
                    runAllDemonstrationTests();
                    break;
                case "10":
                    System.out.println("\nThank you for using ChaCha20 Stream Cipher Studio. Exiting...");
                    running = false;
                    break;
                default:
                    System.out.println("\n[!] Invalid selection. Please enter a number between 1 and 10.\n");
            }
        }
    }

    private static void printBanner() {
        System.out.println("===============================================================");
        System.out.println("         ChaCha20 CipherForge · Cryptographic Engine           ");
        System.out.println("     BCS703: Cryptography and Network Security Assignment      ");
        System.out.println("       Pure Java Implementation · Zero Crypto Dependencies     ");
        System.out.println("===============================================================");
    }

    private static void printMenu() {
        System.out.println("\n--------------------------- MAIN MENU -------------------------");
        System.out.println("  1.  Encrypt Text (ChaCha20 / ChaCha8 / ChaCha12)");
        System.out.println("  2.  Decrypt Hex Ciphertext");
        System.out.println("  3.  AEAD Encrypt & Tag (ChaCha20-Poly1305 with AAD)");
        System.out.println("  4.  AEAD Decrypt & Verify Tag (ChaCha20-Poly1305)");
        System.out.println("  5.  File Encryption & Decryption (Buffered Stream I/O)");
        System.out.println("  6.  Avalanche Effect & Bit-Diffusion Analysis");
        System.out.println("  7.  Performance & Throughput Benchmarking Suite");
        System.out.println("  8.  Step-by-Step State Matrix Execution Trace");
        System.out.println("  9.  Built-in RFC 8439 Verification Demonstration");
        System.out.println("  10. Exit");
        System.out.println("---------------------------------------------------------------");
    }

    private static byte[] promptKey() {
        System.out.print("Enter 256-bit Key in hex (64 hex chars, or press ENTER for random): ");
        String keyHex = scanner.nextLine().trim();
        if (keyHex.isEmpty()) {
            byte[] key = new byte[32];
            secureRandom.nextBytes(key);
            System.out.println("Generated Random Key: " + HexUtils.bytesToHex(key));
            return key;
        }
        try {
            byte[] key = HexUtils.hexToBytes(keyHex);
            InputValidator.validateKey(key);
            return key;
        } catch (Exception e) {
            System.out.println("[ERROR] " + e.getMessage());
            return null;
        }
    }

    private static byte[] promptNonce() {
        System.out.print("Enter 96-bit Nonce in hex (24 hex chars, or press ENTER for random): ");
        String nonceHex = scanner.nextLine().trim();
        if (nonceHex.isEmpty()) {
            byte[] nonce = new byte[12];
            secureRandom.nextBytes(nonce);
            System.out.println("Generated Random Nonce: " + HexUtils.bytesToHex(nonce));
            return nonce;
        }
        try {
            byte[] nonce = HexUtils.hexToBytes(nonceHex);
            InputValidator.validateNonce(nonce);
            return nonce;
        } catch (Exception e) {
            System.out.println("[ERROR] " + e.getMessage());
            return null;
        }
    }

    private static int promptRounds() {
        System.out.print("Select Rounds [8 (ChaCha8), 12 (ChaCha12), 20 (Standard ChaCha20)] (ENTER for 20): ");
        String rStr = scanner.nextLine().trim();
        if (rStr.isEmpty()) return 20;
        try {
            int r = Integer.parseInt(rStr);
            if (r == 8 || r == 12 || r == 20) return r;
            System.out.println("[!] Unsupported round count. Defaulting to 20 rounds.");
            return 20;
        } catch (Exception e) {
            return 20;
        }
    }

    private static void handleEncryptOption() {
        System.out.println("\n--- [1] ENCRYPT TEXT ---");
        System.out.print("Enter plaintext (or press ENTER for demo message): ");
        String text = scanner.nextLine();
        if (text.isEmpty()) {
            text = "ChaCha20 is a high-speed, secure stream cipher specified in RFC 8439.";
            System.out.println("Using default plaintext: \"" + text + "\"");
        }

        byte[] key = promptKey();
        if (key == null) return;
        byte[] nonce = promptNonce();
        if (nonce == null) return;
        int rounds = promptRounds();

        byte[] plaintextBytes = text.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = ChaCha20.encrypt(key, 1, nonce, plaintextBytes, rounds);

        System.out.println("\n====================== ENCRYPTION RESULT ======================");
        System.out.println("Algorithm       : ChaCha" + rounds);
        System.out.println("Plaintext Length: " + plaintextBytes.length + " bytes");
        System.out.println("Ciphertext Hex  : " + HexUtils.bytesToHex(ciphertext));
        System.out.println("Ciphertext Dump :");
        System.out.print(HexUtils.formatHexDump(ciphertext));
        System.out.println("===============================================================");
    }

    private static void handleDecryptOption() {
        System.out.println("\n--- [2] DECRYPT HEX CIPHERTEXT ---");
        System.out.print("Enter ciphertext in hex: ");
        String cipherHex = scanner.nextLine().trim();
        byte[] ciphertext;
        try {
            ciphertext = HexUtils.hexToBytes(cipherHex);
        } catch (Exception e) {
            System.out.println("[ERROR] " + e.getMessage());
            return;
        }

        byte[] key = promptKey();
        if (key == null) return;
        byte[] nonce = promptNonce();
        if (nonce == null) return;
        int rounds = promptRounds();

        byte[] decryptedBytes = ChaCha20.decrypt(key, 1, nonce, ciphertext, rounds);
        String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);

        System.out.println("\n====================== DECRYPTION RESULT ======================");
        System.out.println("Algorithm       : ChaCha" + rounds);
        System.out.println("Decrypted Bytes : " + decryptedBytes.length + " bytes");
        System.out.println("Decrypted Text  : \"" + decryptedText + "\"");
        System.out.println("Decrypted Hex   : " + HexUtils.bytesToHex(decryptedBytes));
        System.out.println("===============================================================");
    }

    private static void handleAeadEncryptOption() {
        System.out.println("\n--- [3] AEAD ENCRYPT & TAG (ChaCha20-Poly1305) ---");
        System.out.print("Enter plaintext (ENTER for demo text): ");
        String text = scanner.nextLine();
        if (text.isEmpty()) {
            text = "Authenticated encryption guarantees both confidentiality and data integrity.";
            System.out.println("Using default plaintext: \"" + text + "\"");
        }

        System.out.print("Enter Additional Authenticated Data (AAD) [optional, press ENTER to skip]: ");
        String aadStr = scanner.nextLine();
        byte[] aad = aadStr.isEmpty() ? new byte[0] : aadStr.getBytes(StandardCharsets.UTF_8);

        byte[] key = promptKey();
        if (key == null) return;
        byte[] nonce = promptNonce();
        if (nonce == null) return;

        ChaCha20Poly1305.AeadResult result = ChaCha20Poly1305.encrypt(key, nonce, aad, text.getBytes(StandardCharsets.UTF_8));

        System.out.println("\n==================== AEAD ENCRYPTION RESULT ====================");
        System.out.println("Ciphertext Hex: " + HexUtils.bytesToHex(result.ciphertext()));
        System.out.println("Auth Tag Hex  : " + HexUtils.bytesToHex(result.tag()) + " (128-bit Poly1305)");
        System.out.println("Combined Hex  : " + HexUtils.bytesToHex(result.toCombinedByteArray()));
        System.out.println("===============================================================");
    }

    private static void handleAeadDecryptOption() {
        System.out.println("\n--- [4] AEAD DECRYPT & VERIFY TAG (ChaCha20-Poly1305) ---");
        System.out.print("Enter ciphertext in hex: ");
        String cipherHex = scanner.nextLine().trim();
        byte[] ciphertext;
        try {
            ciphertext = HexUtils.hexToBytes(cipherHex);
        } catch (Exception e) {
            System.out.println("[ERROR] " + e.getMessage());
            return;
        }

        System.out.print("Enter 16-byte Poly1305 Auth Tag in hex (32 hex chars): ");
        String tagHex = scanner.nextLine().trim();
        byte[] tag;
        try {
            tag = HexUtils.hexToBytes(tagHex);
            InputValidator.validateTag(tag);
        } catch (Exception e) {
            System.out.println("[ERROR] " + e.getMessage());
            return;
        }

        System.out.print("Enter Additional Authenticated Data (AAD) [press ENTER if none]: ");
        String aadStr = scanner.nextLine();
        byte[] aad = aadStr.isEmpty() ? new byte[0] : aadStr.getBytes(StandardCharsets.UTF_8);

        byte[] key = promptKey();
        if (key == null) return;
        byte[] nonce = promptNonce();
        if (nonce == null) return;

        try {
            byte[] decrypted = ChaCha20Poly1305.decrypt(key, nonce, aad, ciphertext, tag);
            System.out.println("\n==================== AEAD VERIFICATION SUCCESS ====================");
            System.out.println("[✓] Poly1305 MAC Tag VERIFIED successfully (Data is authentic)");
            System.out.println("Decrypted Text: \"" + new String(decrypted, StandardCharsets.UTF_8) + "\"");
            System.out.println("===================================================================");
        } catch (SecurityException se) {
            System.out.println("\n[✗] AUTHENTICATION FAILED: " + se.getMessage());
        } catch (Exception e) {
            System.out.println("[ERROR] " + e.getMessage());
        }
    }

    private static void handleFileCipherOption() {
        System.out.println("\n--- [5] FILE ENCRYPTION & DECRYPTION (BUFFERED STREAMING) ---");
        System.out.print("Enter path to source file: ");
        String inputPath = scanner.nextLine().trim();
        File inputFile = new File(inputPath);
        if (!inputFile.exists() || !inputFile.isFile()) {
            System.out.println("[ERROR] File does not exist or is not a valid file: " + inputPath);
            return;
        }

        System.out.print("Enter path for output file: ");
        String outputPath = scanner.nextLine().trim();
        if (outputPath.isEmpty()) {
            outputPath = inputPath.endsWith(".enc") ? inputPath.replace(".enc", ".dec") : inputPath + ".enc";
            System.out.println("Using default output path: " + outputPath);
        }
        File outputFile = new File(outputPath);

        byte[] key = promptKey();
        if (key == null) return;
        byte[] nonce = promptNonce();
        if (nonce == null) return;
        int rounds = promptRounds();

        System.out.println("\nProcessing file (" + (inputFile.length() / 1024.0) + " KB)...");
        try {
            FileCipher.FileResult res = FileCipher.processFile(inputFile, outputFile, key, 1, nonce, rounds);
            System.out.println("\n======================= FILE RESULT =======================");
            System.out.println("Source File    : " + res.inputFile().getAbsolutePath());
            System.out.println("Output File    : " + res.outputFile().getAbsolutePath());
            System.out.println("Bytes Processed: " + res.bytesProcessed() + " bytes");
            System.out.println(String.format("Elapsed Time   : %.2f ms", res.getElapsedMillis()));
            System.out.println(String.format("Throughput     : %.2f MB/s", res.getThroughputMBps()));
            System.out.println("===========================================================");
        } catch (Exception e) {
            System.out.println("[ERROR] File processing failed: " + e.getMessage());
        }
    }

    private static void handleAvalancheOption() {
        System.out.println("\n--- [6] AVALANCHE EFFECT & BIT-DIFFUSION ANALYSIS ---");
        System.out.println("Measuring diffusion when flipping 1 single bit in the 256-bit Key across 20 rounds...\n");

        AvalancheAnalyzer.AvalancheReport report = AvalancheAnalyzer.runDefaultAnalysis();

        System.out.println("+-------+-------------------+--------------------+");
        System.out.println("| Round | Differing Bits/512| Percentage Flipped |");
        System.out.println("+-------+-------------------+--------------------+");
        for (AvalancheAnalyzer.RoundMetric rm : report.roundMetrics()) {
            System.out.println(String.format("|  %2d   |     %3d / 512     |       %6.2f %%     |",
                    rm.round(), rm.flippedBits(), rm.percentageFlipped()));
        }
        System.out.println("+-------+-------------------+--------------------+");
        System.out.println(String.format("Final Diffusion: %d / 512 bits (%.2f %%)", report.finalFlippedBits(), report.finalPercentage()));
        System.out.println("Scientific Analysis: Observed bit diffusion rapidly approaches the expected ~50% state-bit");
        System.out.println("change behavior across repeated permutation rounds, demonstrating strong avalanche diffusion.");

        System.out.println("\nRunning multi-trial statistical analysis (32 single-bit perturbation trials)...");
        AvalancheAnalyzer.MultiTrialReport multi = AvalancheAnalyzer.runMultiTrialAnalysis(32);
        System.out.println(String.format("Multi-Trial Statistics: Mean = %.1f/512 (%.2f%%) | Min = %d | Max = %d | StdDev = %.2f bits\n",
                multi.meanFlippedBits(), multi.meanPercentage(), multi.minFlippedBits(), multi.maxFlippedBits(), multi.stdDevBits()));
    }

    private static void handleBenchmarkOption() {
        System.out.println("\n--- [7] PERFORMANCE & THROUGHPUT BENCHMARKING SUITE ---");
        System.out.println("Academic Performance Comparison (JVM warm-up followed by multi-payload throughput measurement)...\n");

        List<BenchmarkRunner.BenchmarkResult> results = BenchmarkRunner.runComprehensiveSuite();

        System.out.println("+-------------------+--------------+--------------+------------------+");
        System.out.println("| Algorithm         | Payload Size |  Throughput  | Latency / Block  |");
        System.out.println("+-------------------+--------------+--------------+------------------+");
        for (BenchmarkRunner.BenchmarkResult br : results) {
            String sizeStr = (br.payloadSizeBytes() >= 1024 * 1024) ? (br.payloadSizeBytes() / (1024 * 1024) + " MB")
                    : (br.payloadSizeBytes() >= 1024 ? (br.payloadSizeBytes() / 1024 + " KB") : (br.payloadSizeBytes() + " B"));
            System.out.println(String.format("| %-17s | %-12s | %8.2f MB/s | %8.2f ns/blk |",
                    br.algorithm(), sizeStr, br.throughputMBps(), br.nanosPerBlock()));
        }
        System.out.println("+-------------------+--------------+--------------+------------------+\n");
    }

    private static void handleTraceOption() {
        System.out.println("\n--- [8] STEP-BY-STEP STATE MATRIX EXECUTION TRACE ---");
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) key[i] = (byte) i;
        byte[] nonce = new byte[]{0,0,0,0, 0,0,0,0x4a, 0,0,0,0};

        System.out.println(StateTracer.traceBlock(key, 1, nonce, 20));
    }

    private static void runAllDemonstrationTests() {
        System.out.println("\n===============================================================");
        System.out.println("        BUILT-IN RFC 8439 VERIFICATION DEMONSTRATION           ");
        System.out.println("===============================================================");
        System.out.println("Executing live verification of authoritative RFC 8439 test vectors:\n");

        // 1. Quarter Round RFC 8439 Section 2.1.1
        int[] qrState = new int[]{0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567};
        ChaCha20.quarterRound(qrState, 0, 1, 2, 3);
        boolean qrPass = (qrState[0] == 0xea2a92f4 && qrState[1] == (int)0xcb1cf8ceL &&
                          qrState[2] == 0x4581472e && qrState[3] == 0x5881c4bb);
        System.out.println("  [1] Quarter Round (§2.1.1)                     : " + (qrPass ? "PASS" : "FAIL"));

        // 2. Block Function RFC 8439 Section 2.3.2 (Complete 64-byte keystream comparison)
        byte[] bKey = HexUtils.hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] bNonce = HexUtils.hexToBytes("000000090000004a00000000");
        byte[] blockOut = ChaCha20.chachaBlock(bKey, 1, bNonce);
        String blockHex = HexUtils.bytesToHex(blockOut);
        String expectedBlockHex =
                "10f1e7e4d13b5915500fdd1fa32071c4" +
                "c7d1f4c733c068030422aa9ac3d46c4e" +
                "d2826446079faa0914c2d705d98b02a2" +
                "b5129cd1de164eb9cbd083e8a2503c4e";
        boolean blockPass = blockHex.equalsIgnoreCase(expectedBlockHex);
        System.out.println("  [2] Block Function (§2.3.2)                    : " + (blockPass ? "PASS" : "FAIL"));

        // 3. ChaCha20 Encryption RFC 8439 Section 2.4.2 (Complete 114-byte ciphertext comparison)
        byte[] encKey = HexUtils.hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] encNonce = HexUtils.hexToBytes("000000000000004a00000000");
        String plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        byte[] ciphertext = ChaCha20.encrypt(encKey, 1, encNonce, plaintext.getBytes(StandardCharsets.US_ASCII));
        String expectedCipherHex =
                "6e2e359a2568f98041ba0728dd0d6981" +
                "e97e7aec1d4360c20a27afccfd9fae0b" +
                "f91b65c5524733ab8f593dabcd62b357" +
                "1639d624e65152ab8f530c359f0861d8" +
                "07ca0dbf500d6a6156a38e088a22b65e" +
                "52bc514d16ccf806818ce91ab7793736" +
                "5af90bbf74a35be6b40b8eedf2785e42" +
                "874d";
        boolean encPass = HexUtils.bytesToHex(ciphertext).equalsIgnoreCase(expectedCipherHex);
        System.out.println("  [3] ChaCha20 Encrypt (§2.4.2)                  : " + (encPass ? "PASS" : "FAIL"));

        // 4. Poly1305 MAC RFC 8439 Section 2.5.2 (Complete 16-byte tag comparison)
        byte[] polyKey = HexUtils.hexToBytes("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        byte[] polyMsg = "Cryptographic Forum Research Group".getBytes(StandardCharsets.US_ASCII);
        byte[] tag = Poly1305.computeMac(polyKey, polyMsg);
        boolean polyPass = HexUtils.bytesToHex(tag).equalsIgnoreCase("a8061dc1305136c6c22b8baf0c0127a9");
        System.out.println("  [4] Poly1305 Authenticator (§2.5.2)            : " + (polyPass ? "PASS" : "FAIL"));

        // 5. AEAD Construction RFC 8439 Section 2.8.2 (Complete ciphertext AND tag comparisons)
        byte[] aeadKey = HexUtils.hexToBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] aeadNonce = HexUtils.hexToBytes("070000004041424344454647");
        byte[] aeadAad = HexUtils.hexToBytes("50515253c0c1c2c3c4c5c6c7");
        byte[] aeadPt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".getBytes(StandardCharsets.US_ASCII);
        ChaCha20Poly1305.AeadResult aeadRes = ChaCha20Poly1305.encrypt(aeadKey, aeadNonce, aeadAad, aeadPt);

        String expectedAeadCipherHex =
                "d31a8d34648e60db7b86afbc53ef7ec2" +
                "a4aded51296e08fea9e2b5a736ee62d6" +
                "3dbea45e8ca9671282fafb69da92728b" +
                "1a71de0a9e060b2905d6a5b67ecd3b36" +
                "92ddbd7f2d778b8c9803aee328091b58" +
                "fab324e4fad675945585808b4831d7bc" +
                "3ff4def08e4b7a9de576d26586cec64b" +
                "6116";
        String expectedAeadTagHex = "1ae10b594f09e26a7e902ecbd0600691";

        boolean aeadCipherPass = HexUtils.bytesToHex(aeadRes.ciphertext()).equalsIgnoreCase(expectedAeadCipherHex);
        boolean aeadTagPass = HexUtils.bytesToHex(aeadRes.tag()).equalsIgnoreCase(expectedAeadTagHex);
        System.out.println("  [5] AEAD Ciphertext (§2.8.2)                   : " + (aeadCipherPass ? "PASS" : "FAIL"));
        System.out.println("  [6] AEAD Authentication Tag (§2.8.2)           : " + (aeadTagPass ? "PASS" : "FAIL"));

        boolean allPass = qrPass && blockPass && encPass && polyPass && aeadCipherPass && aeadTagPass;
        System.out.println("---------------------------------------------------------------");
        if (allPass) {
            System.out.println("Overall RFC 8439 Verification Result: ALL 6 CHECKS PASSED [100% COMPLETE MATCH]");
        } else {
            System.out.println("Overall RFC 8439 Verification Result: ONE OR MORE CHECKS FAILED");
        }
        System.out.println("Note: For full automated regression testing, run: mvn test");
    }
}
