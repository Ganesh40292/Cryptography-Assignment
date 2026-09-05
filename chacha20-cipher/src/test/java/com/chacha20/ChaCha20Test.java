package com.chacha20;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive JUnit 5 Test Suite for ChaCha20 Stream Cipher implementation.
 * Verifies algorithmic correctness against RFC 8439 specifications and edge cases.
 */
public class ChaCha20Test {

    private static final byte[] TEST_KEY_1 = HexUtils.hexToBytes(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static final byte[] TEST_NONCE_1 = HexUtils.hexToBytes(
            "000000000000004a00000000");

    @BeforeAll
    static void init() {
        System.out.println("===============================================================");
        System.out.println("                Running ChaCha20 Test Suite                    ");
        System.out.println("===============================================================");
    }

    @Test
    @DisplayName("TEST 1: Basic Encryption/Decryption Round-Trip")
    void testBasicEncryptionDecryption() {
        String originalMessage = "Cryptography and Network Security: ChaCha20 Stream Cipher";
        byte[] plaintext = originalMessage.getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = ChaCha20.encrypt(TEST_KEY_1, 1, TEST_NONCE_1, plaintext);
        assertNotNull(ciphertext);
        assertEquals(plaintext.length, ciphertext.length);
        assertFalse(Arrays.equals(plaintext, ciphertext), "Ciphertext must not be identical to plaintext");

        byte[] decrypted = ChaCha20.decrypt(TEST_KEY_1, 1, TEST_NONCE_1, ciphertext);
        assertArrayEquals(plaintext, decrypted, "Decrypted text must match original plaintext");
        assertEquals(originalMessage, new String(decrypted, StandardCharsets.UTF_8));
        System.out.println("[PASS] TEST 1: Basic Encryption/Decryption");
    }

    @Test
    @DisplayName("TEST 2: Short Plaintext (\"Hello\")")
    void testShortPlaintext() {
        byte[] plaintext = "Hello".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = ChaCha20.encrypt(TEST_KEY_1, 1, TEST_NONCE_1, plaintext);
        assertEquals(5, ciphertext.length, "Ciphertext length must exactly equal plaintext length (5 bytes)");

        byte[] decrypted = ChaCha20.decrypt(TEST_KEY_1, 1, TEST_NONCE_1, ciphertext);
        assertArrayEquals(plaintext, decrypted);
        assertEquals("Hello", new String(decrypted, StandardCharsets.UTF_8));
        System.out.println("[PASS] TEST 2: Short Plaintext");
    }

    @Test
    @DisplayName("TEST 3: Empty Plaintext (0-length array)")
    void testEmptyPlaintext() {
        byte[] plaintext = new byte[0];

        byte[] ciphertext = ChaCha20.encrypt(TEST_KEY_1, 1, TEST_NONCE_1, plaintext);
        assertNotNull(ciphertext);
        assertEquals(0, ciphertext.length, "Ciphertext of empty input must be empty");

        byte[] decrypted = ChaCha20.decrypt(TEST_KEY_1, 1, TEST_NONCE_1, ciphertext);
        assertNotNull(decrypted);
        assertEquals(0, decrypted.length);
        System.out.println("[PASS] TEST 3: Empty Plaintext");
    }

    @Test
    @DisplayName("TEST 4: Long Plaintext spanning Multiple 64-byte Blocks")
    void testLongPlaintext() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 20; i++) {
            sb.append("BlockSegment #").append(i).append(": ChaCha20 generates 64-byte keystreams per block. ");
        }
        byte[] plaintext = sb.toString().getBytes(StandardCharsets.UTF_8);
        assertTrue(plaintext.length > 256, "Plaintext should span at least 4 ChaCha20 blocks");

        byte[] ciphertext = ChaCha20.encrypt(TEST_KEY_1, 1, TEST_NONCE_1, plaintext);
        assertEquals(plaintext.length, ciphertext.length);

        byte[] decrypted = ChaCha20.decrypt(TEST_KEY_1, 1, TEST_NONCE_1, ciphertext);
        assertArrayEquals(plaintext, decrypted, "Decrypted multi-block plaintext must match original");
        System.out.println("[PASS] TEST 4: Long Plaintext (" + plaintext.length + " bytes across multiple blocks)");
    }

    @Test
    @DisplayName("TEST 5: Different Keys Produce Different Ciphertexts")
    void testDifferentKeysProduceDifferentCiphertext() {
        byte[] keyA = TEST_KEY_1;
        byte[] keyB = HexUtils.hexToBytes("1111111111111111111111111111111111111111111111111111111111111111");
        byte[] plaintext = "Confidential Data Payload".getBytes(StandardCharsets.UTF_8);

        byte[] cipherA = ChaCha20.encrypt(keyA, 1, TEST_NONCE_1, plaintext);
        byte[] cipherB = ChaCha20.encrypt(keyB, 1, TEST_NONCE_1, plaintext);

        assertFalse(Arrays.equals(cipherA, cipherB), "Different keys must produce different ciphertexts");
        System.out.println("[PASS] TEST 5: Different Keys -> Different Ciphertexts");
    }

    @Test
    @DisplayName("TEST 6: Determinism - Same Parameters Produce Identical Ciphertext")
    void testSameParametersProduceSameCiphertext() {
        byte[] plaintext = "Deterministic Cipher Output Verification".getBytes(StandardCharsets.UTF_8);

        byte[] cipher1 = ChaCha20.encrypt(TEST_KEY_1, 1, TEST_NONCE_1, plaintext);
        byte[] cipher2 = ChaCha20.encrypt(TEST_KEY_1, 1, TEST_NONCE_1, plaintext);

        assertArrayEquals(cipher1, cipher2, "Same inputs must always produce identical ciphertext");
        System.out.println("[PASS] TEST 6: Same Parameters -> Same Ciphertext");
    }

    @Test
    @DisplayName("TEST 7: Changing Nonce Produces Different Ciphertext")
    void testDifferentNonceProducesDifferentCiphertext() {
        byte[] nonceA = TEST_NONCE_1;
        byte[] nonceB = HexUtils.hexToBytes("000000000000004a00000001");
        byte[] plaintext = "Nonce Uniqueness is Critical for Security".getBytes(StandardCharsets.UTF_8);

        byte[] cipherA = ChaCha20.encrypt(TEST_KEY_1, 1, nonceA, plaintext);
        byte[] cipherB = ChaCha20.encrypt(TEST_KEY_1, 1, nonceB, plaintext);

        assertFalse(Arrays.equals(cipherA, cipherB), "Different nonces must produce different ciphertexts");
        System.out.println("[PASS] TEST 7: Different Nonce -> Different Ciphertext");
    }

    @Test
    @DisplayName("TEST 8: Changing Counter Produces Different Keystream / Ciphertext")
    void testDifferentCounterProducesDifferentCiphertext() {
        byte[] plaintext = "Block Counter Increment Test".getBytes(StandardCharsets.UTF_8);

        byte[] cipher1 = ChaCha20.encrypt(TEST_KEY_1, 1, TEST_NONCE_1, plaintext);
        byte[] cipher2 = ChaCha20.encrypt(TEST_KEY_1, 2, TEST_NONCE_1, plaintext);

        assertFalse(Arrays.equals(cipher1, cipher2), "Different initial counters must produce different ciphertexts");
        System.out.println("[PASS] TEST 8: Different Counter -> Different Ciphertext");
    }

    @Test
    @DisplayName("TEST 9: Official RFC 8439 Section 2.4.2 Test Vector")
    void testRfc8439OfficialTestVector() {
        // RFC 8439 Section 2.4.2
        byte[] key = HexUtils.hexToBytes(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] nonce = HexUtils.hexToBytes(
                "000000000000004a00000000");
        int counter = 1;

        String plaintextStr = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        byte[] plaintext = plaintextStr.getBytes(StandardCharsets.US_ASCII);

        String expectedCiphertextHex =
                "6e2e359a2568f98041ba0728dd0d6981" +
                "e97e7aec1d4360c20a27afccfd9fae0b" +
                "f91b65c5524733ab8f593dabcd62b357" +
                "1639d624e65152ab8f530c359f0861d8" +
                "07ca0dbf500d6a6156a38e088a22b65e" +
                "52bc514d16ccf806818ce91ab7793736" +
                "5af90bbf74a35be6b40b8eedf2785e42" +
                "874d";

        byte[] actualCiphertext = ChaCha20.encrypt(key, counter, nonce, plaintext);
        String actualCiphertextHex = HexUtils.bytesToHex(actualCiphertext);

        assertEquals(expectedCiphertextHex.toLowerCase(), actualCiphertextHex.toLowerCase(),
                "Generated ciphertext must exactly match RFC 8439 Section 2.4.2 test vector");

        byte[] decrypted = ChaCha20.decrypt(key, counter, nonce, actualCiphertext);
        assertEquals(plaintextStr, new String(decrypted, StandardCharsets.US_ASCII));
        System.out.println("[PASS] TEST 9: RFC 8439 Official Test Vector (Section 2.4.2)");
    }

    @Test
    @DisplayName("TEST 10: Arbitrary Round-Trip Decrypt(Encrypt(M)) == M")
    void testArbitraryRoundTrip() {
        byte[] key = HexUtils.hexToBytes("fedcba98765432100123456789abcdef0123456789abcdeffedcba9876543210");
        byte[] nonce = HexUtils.hexToBytes("1234567890abcdef12345678");
        byte[] plaintext = "The quick brown fox jumps over the lazy dog 1234567890 !@#$%^&*()".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = ChaCha20.encrypt(key, 99, nonce, plaintext);
        byte[] decrypted = ChaCha20.decrypt(key, 99, nonce, ciphertext);

        assertArrayEquals(plaintext, decrypted);
        System.out.println("[PASS] TEST 10: Arbitrary Round-Trip Integrity");
    }

    @Test
    @DisplayName("TEST 11: RFC 8439 Section 2.1.1 Quarter Round Test Vector")
    void testRfc8439QuarterRoundTestVector() {
        // RFC 8439 Section 2.1.1 Test Vector
        int a = 0x11111111;
        int b = 0x01020304;
        int c = 0x9b8d6f43;
        int d = 0x01234567;

        int[] result = ChaCha20.quarterRound(a, b, c, d);

        assertEquals(0xea2a92f4, result[0], "Word a mismatch");
        assertEquals(0xcb1cf8ce, result[1], "Word b mismatch");
        assertEquals(0x4581472e, result[2], "Word c mismatch");
        assertEquals(0x5881c4bb, result[3], "Word d mismatch");
        System.out.println("[PASS] TEST 11: RFC 8439 Quarter Round Test Vector (Section 2.1.1)");
    }

    @Test
    @DisplayName("TEST 12: RFC 8439 Section 2.3.2 ChaCha20 Block Function Test Vector")
    void testRfc8439BlockFunctionTestVector() {
        // RFC 8439 Section 2.3.2
        byte[] key = HexUtils.hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] nonce = HexUtils.hexToBytes("000000090000004a00000000");
        int counter = 1;

        byte[] expectedBlock = HexUtils.hexToBytes(
                "10f1e7e4d13b5915500fdd1fa32071c4" +
                "c7d1f4c733c068030422aa9ac3d46c4e" +
                "d2826446079faa0914c2d705d98b02a2" +
                "b5129cd1de164eb9cbd083e8a2503c4e");

        byte[] actualBlock = ChaCha20.chachaBlock(key, counter, nonce);
        assertArrayEquals(expectedBlock, actualBlock, "ChaCha20 block function must match RFC 8439 Section 2.3.2 keystream");
        System.out.println("[PASS] TEST 12: RFC 8439 Block Function Test Vector (Section 2.3.2)");
    }

    @Test
    @DisplayName("TEST 13: Input Validation - Invalid Key Lengths Rejection")
    void testInvalidKeyRejection() {
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateKey(null), "Null key rejected");
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateKey(new byte[0]), "0-byte key rejected");
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateKey(new byte[1]), "1-byte key rejected");
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateKey(new byte[16]), "16-byte key rejected");
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateKey(new byte[31]), "31-byte key rejected");
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateKey(new byte[33]), "33-byte key rejected");
        assertDoesNotThrow(() -> InputValidator.validateKey(new byte[32]), "32-byte key must be accepted");
        System.out.println("[PASS] TEST 13: Invalid Key Length Rejection");
    }

    @Test
    @DisplayName("TEST 14: Input Validation - Invalid Nonce Lengths Rejection")
    void testInvalidNonceRejection() {
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateNonce(null), "Null nonce rejected");
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateNonce(new byte[0]), "0-byte nonce rejected");
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateNonce(new byte[8]), "8-byte nonce rejected");
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateNonce(new byte[11]), "11-byte nonce rejected");
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateNonce(new byte[13]), "13-byte nonce rejected");
        assertDoesNotThrow(() -> InputValidator.validateNonce(new byte[12]), "12-byte nonce must be accepted");
        System.out.println("[PASS] TEST 14: Invalid Nonce Length Rejection");
    }

    @Test
    @DisplayName("TEST 15: HexUtils Utility Functions and Edge Cases")
    void testHexUtils() {
        // Empty string
        byte[] empty = HexUtils.hexToBytes("");
        assertEquals(0, empty.length);
        assertEquals("", HexUtils.bytesToHex(new byte[0]));

        // Uppercase, lowercase, mixed case
        byte[] raw = new byte[]{0x00, (byte) 0xff, 0x12, 0x34, (byte) 0xab};
        assertArrayEquals(raw, HexUtils.hexToBytes("00ff1234ab"));
        assertArrayEquals(raw, HexUtils.hexToBytes("00FF1234AB"));
        assertArrayEquals(raw, HexUtils.hexToBytes("00Ff1234aB"));

        // Delimiters / spaces
        assertArrayEquals(raw, HexUtils.hexToBytes("00 ff 12 34 ab"));
        assertArrayEquals(raw, HexUtils.hexToBytes("00:ff:12:34:ab"));

        // Odd length rejection
        assertThrows(IllegalArgumentException.class, () -> HexUtils.hexToBytes("123"));
        assertThrows(IllegalArgumentException.class, () -> HexUtils.hexToBytes("a"));

        // Invalid characters rejection
        assertThrows(IllegalArgumentException.class, () -> HexUtils.hexToBytes("12zz"));
        assertThrows(IllegalArgumentException.class, () -> HexUtils.hexToBytes("00gg"));
        assertThrows(IllegalArgumentException.class, () -> HexUtils.hexToBytes(null));

        System.out.println("[PASS] TEST 15: HexUtils Utility Functions and Edge Cases");
    }

    @Test
    @DisplayName("TEST 16: Configurable Rounds (ChaCha8 & ChaCha12 Round-Trip)")
    void testConfigurableRounds() {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = "Testing reduced round variants: ChaCha8 & ChaCha12".getBytes(StandardCharsets.UTF_8);

        // ChaCha8
        byte[] cipher8 = ChaCha20.encrypt(key, 1, nonce, plaintext, 8);
        byte[] dec8 = ChaCha20.decrypt(key, 1, nonce, cipher8, 8);
        assertArrayEquals(plaintext, dec8, "ChaCha8 must decrypt back to original plaintext.");

        // ChaCha12
        byte[] cipher12 = ChaCha20.encrypt(key, 1, nonce, plaintext, 12);
        byte[] dec12 = ChaCha20.decrypt(key, 1, nonce, cipher12, 12);
        assertArrayEquals(plaintext, dec12, "ChaCha12 must decrypt back to original plaintext.");

        // ChaCha8, ChaCha12, and ChaCha20 produce distinct ciphertexts
        byte[] cipher20 = ChaCha20.encrypt(key, 1, nonce, plaintext, 20);
        assertFalse(java.util.Arrays.equals(cipher8, cipher12));
        assertFalse(java.util.Arrays.equals(cipher12, cipher20));
        System.out.println("[PASS] TEST 16: Configurable Rounds (ChaCha8 & ChaCha12)");
    }

    @Test
    @DisplayName("TEST 17: Unicode, Multilingual UTF-8, Indian Script & Emoji Round-Trip")
    void testUnicodeAndMultilingualPayloads() {
        String complexText = "Hello नमस्ते 🔐! Cryptography Assignment 1: ChaCha20 বাংলা தமிழ் 🚀 $#@% 1234567890";
        byte[] plaintext = complexText.getBytes(StandardCharsets.UTF_8);

        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        for (int i = 0; i < 32; i++) key[i] = (byte) (i + 5);
        for (int i = 0; i < 12; i++) nonce[i] = (byte) (i + 1);

        byte[] ciphertext = ChaCha20.encrypt(key, 1, nonce, plaintext);
        assertFalse(Arrays.equals(plaintext, ciphertext));

        byte[] decrypted = ChaCha20.decrypt(key, 1, nonce, ciphertext);
        assertArrayEquals(plaintext, decrypted);
        assertEquals(complexText, new String(decrypted, StandardCharsets.UTF_8),
                "Decrypted UTF-8 multilingual text must match original exactly.");
        System.out.println("[PASS] TEST 17: Unicode, Multilingual UTF-8 & Emoji Round-Trip");
    }

    @Test
    @DisplayName("TEST 18: Educational Demonstration - Raw ChaCha20 Tampering Lack of Authentication")
    void testRawChaCha20TamperingDemonstration() {
        // Educational test verifying that raw ChaCha20 stream cipher does NOT authenticate data.
        // A single-bit alteration in the ciphertext propagates directly into the decrypted plaintext
        // without raising an error. This demonstrates the necessity of ChaCha20-Poly1305 AEAD.
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        String original = "Transfer $1000 to Alice";
        byte[] plaintext = original.getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = ChaCha20.encrypt(key, 1, nonce, plaintext);

        // Tamper with ciphertext by flipping 1 bit
        byte[] tamperedCiphertext = ciphertext.clone();
        tamperedCiphertext[10] ^= 0x01;

        // Raw ChaCha20 decrypts without error, yielding altered plaintext
        byte[] decrypted = ChaCha20.decrypt(key, 1, nonce, tamperedCiphertext);
        assertFalse(Arrays.equals(plaintext, decrypted), "Decrypted plaintext is altered");
        assertNotEquals(original, new String(decrypted, StandardCharsets.UTF_8));
        System.out.println("[PASS] TEST 18: Educational Demo - Raw ChaCha20 Tampering");
    }

    @Test
    @DisplayName("TEST 19: Counter Validation and Boundary Checks")
    void testCounterValidation() {
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateCounter(-1),
                "Negative counter must be rejected");
        assertThrows(IllegalArgumentException.class, () -> InputValidator.validateCounter(0x100000000L),
                "Counter exceeding 32-bit unsigned range must be rejected");

        assertDoesNotThrow(() -> InputValidator.validateCounter(0), "Counter 0 is valid");
        assertDoesNotThrow(() -> InputValidator.validateCounter(1), "Counter 1 is valid");
        assertDoesNotThrow(() -> InputValidator.validateCounter(0xFFFFFFFFL), "Counter 0xFFFFFFFF is valid");
        System.out.println("[PASS] TEST 19: Counter Validation");
    }

    @Test
    @DisplayName("TEST 20: AvalancheAnalyzer Parameter Index Validation & Bounds Checking")
    void testAvalancheAnalyzerParameterValidation() {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];

        // Valid execution
        assertDoesNotThrow(() -> AvalancheAnalyzer.analyze(key, 1, nonce, AvalancheAnalyzer.PerturbationTarget.KEY, 0, 0));
        assertDoesNotThrow(() -> AvalancheAnalyzer.analyze(key, 1, nonce, AvalancheAnalyzer.PerturbationTarget.KEY, 31, 7));
        assertDoesNotThrow(() -> AvalancheAnalyzer.analyze(key, 1, nonce, AvalancheAnalyzer.PerturbationTarget.NONCE, 11, 7));
        assertDoesNotThrow(() -> AvalancheAnalyzer.analyze(key, 1, nonce, AvalancheAnalyzer.PerturbationTarget.COUNTER, 0, 31));

        // Invalid Key byte index (< 0 or > 31)
        assertThrows(IllegalArgumentException.class, () ->
                AvalancheAnalyzer.analyze(key, 1, nonce, AvalancheAnalyzer.PerturbationTarget.KEY, -1, 0));
        assertThrows(IllegalArgumentException.class, () ->
                AvalancheAnalyzer.analyze(key, 1, nonce, AvalancheAnalyzer.PerturbationTarget.KEY, 32, 0));

        // Invalid Nonce byte index (< 0 or > 11)
        assertThrows(IllegalArgumentException.class, () ->
                AvalancheAnalyzer.analyze(key, 1, nonce, AvalancheAnalyzer.PerturbationTarget.NONCE, -1, 0));
        assertThrows(IllegalArgumentException.class, () ->
                AvalancheAnalyzer.analyze(key, 1, nonce, AvalancheAnalyzer.PerturbationTarget.NONCE, 12, 0));

        // Invalid bit index for Key / Nonce (< 0 or > 7)
        assertThrows(IllegalArgumentException.class, () ->
                AvalancheAnalyzer.analyze(key, 1, nonce, AvalancheAnalyzer.PerturbationTarget.KEY, 0, -1));
        assertThrows(IllegalArgumentException.class, () ->
                AvalancheAnalyzer.analyze(key, 1, nonce, AvalancheAnalyzer.PerturbationTarget.KEY, 0, 8));

        // Invalid bit index for Counter (< 0 or > 31)
        assertThrows(IllegalArgumentException.class, () ->
                AvalancheAnalyzer.analyze(key, 1, nonce, AvalancheAnalyzer.PerturbationTarget.COUNTER, 0, -1));
        assertThrows(IllegalArgumentException.class, () ->
                AvalancheAnalyzer.analyze(key, 1, nonce, AvalancheAnalyzer.PerturbationTarget.COUNTER, 0, 32));

        // Null target
        assertThrows(IllegalArgumentException.class, () ->
                AvalancheAnalyzer.analyze(key, 1, nonce, null, 0, 0));

        System.out.println("[PASS] TEST 20: AvalancheAnalyzer Parameter Index Validation");
    }
}
