package com.chacha20;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit 5 Unit Tests for ChaCha20-Poly1305 AEAD Construction (RFC 8439 Section 2.8).
 */
public class ChaCha20Poly1305Test {

    @Test
    @DisplayName("TC-AEAD01: Official RFC 8439 Section 2.8.2 AEAD Test Vector")
    void testRfc8439Section282Vector() {
        // 256-bit Key
        byte[] key = HexUtils.hexToBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        // 96-bit Nonce
        byte[] nonce = HexUtils.hexToBytes("070000004041424344454647");
        // AAD (12 bytes)
        byte[] aad = HexUtils.hexToBytes("50515253c0c1c2c3c4c5c6c7");

        // Plaintext: Sunscreen quote (114 bytes)
        String plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.US_ASCII);

        // Expected Ciphertext & Tag from RFC 8439 Section 2.8.2
        String expectedCipherHex = "d31a8d34648e60db7b86afbc53ef7ec2"
                + "a4aded51296e08fea9e2b5a736ee62d6"
                + "3dbea45e8ca9671282fafb69da92728b"
                + "1a71de0a9e060b2905d6a5b67ecd3b36"
                + "92ddbd7f2d778b8c9803aee328091b58"
                + "fab324e4fad675945585808b4831d7bc"
                + "3ff4def08e4b7a9de576d26586cec64b"
                + "6116";
        String expectedTagHex = "1ae10b594f09e26a7e902ecbd0600691";

        // Execute AEAD encryption
        ChaCha20Poly1305.AeadResult result = ChaCha20Poly1305.encrypt(key, nonce, aad, plaintextBytes);

        assertEquals(expectedCipherHex, HexUtils.bytesToHex(result.ciphertext()),
                "Ciphertext must match RFC 8439 Section 2.8.2 verbatim.");
        assertEquals(expectedTagHex, HexUtils.bytesToHex(result.tag()),
                "Poly1305 Authentication Tag must match RFC 8439 Section 2.8.2 verbatim.");

        // Execute AEAD decryption and authentication
        byte[] decrypted = ChaCha20Poly1305.decrypt(key, nonce, aad, result.ciphertext(), result.tag());
        assertArrayEquals(plaintextBytes, decrypted, "Decrypted text must match original plaintext.");
    }

    @Test
    @DisplayName("TC-AEAD02: Tampering in Ciphertext Triggers SecurityException")
    void testTamperedCiphertextRejection() {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = "Sensitive Financial Transaction Payload".getBytes(StandardCharsets.UTF_8);

        ChaCha20Poly1305.AeadResult result = ChaCha20Poly1305.encrypt(key, nonce, plaintext);

        // Tamper with 1 byte of ciphertext
        byte[] tamperedCipher = result.ciphertext().clone();
        tamperedCipher[0] ^= 0x01;

        assertThrows(SecurityException.class, () -> {
            ChaCha20Poly1305.decrypt(key, nonce, tamperedCipher, result.tag());
        }, "Tampered ciphertext must be rejected by MAC tag verification.");
    }

    @Test
    @DisplayName("TC-AEAD03: Tampering in AAD Triggers SecurityException")
    void testTamperedAadRejection() {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] aad = "Header: Packet-ID-12345".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "Secret Message".getBytes(StandardCharsets.UTF_8);

        ChaCha20Poly1305.AeadResult result = ChaCha20Poly1305.encrypt(key, nonce, aad, plaintext);

        byte[] tamperedAad = "Header: Packet-ID-99999".getBytes(StandardCharsets.UTF_8);

        assertThrows(SecurityException.class, () -> {
            ChaCha20Poly1305.decrypt(key, nonce, tamperedAad, result.ciphertext(), result.tag());
        }, "Tampered AAD must be rejected by MAC tag verification.");
    }

    @Test
    @DisplayName("TC-AEAD04: AEAD Decryption with Wrong Key Rejection")
    void testAeadWrongKeyRejection() {
        byte[] keyA = new byte[32];
        byte[] keyB = new byte[32];
        keyA[0] = 0x01;
        keyB[0] = 0x02;

        byte[] nonce = new byte[12];
        byte[] aad = "Associated Data".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "Confidential Payload".getBytes(StandardCharsets.UTF_8);

        ChaCha20Poly1305.AeadResult result = ChaCha20Poly1305.encrypt(keyA, nonce, aad, plaintext);

        assertThrows(SecurityException.class, () -> {
            ChaCha20Poly1305.decrypt(keyB, nonce, aad, result.ciphertext(), result.tag());
        }, "Decrypting with the wrong key must trigger an AEAD authentication failure.");
    }

    @Test
    @DisplayName("TC-AEAD05: AEAD Decryption with Wrong Nonce Rejection")
    void testAeadWrongNonceRejection() {
        byte[] key = new byte[32];
        byte[] nonceA = new byte[12];
        byte[] nonceB = new byte[12];
        nonceA[0] = 0x11;
        nonceB[0] = 0x22;

        byte[] aad = "Associated Data".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "Confidential Payload".getBytes(StandardCharsets.UTF_8);

        ChaCha20Poly1305.AeadResult result = ChaCha20Poly1305.encrypt(key, nonceA, aad, plaintext);

        assertThrows(SecurityException.class, () -> {
            ChaCha20Poly1305.decrypt(key, nonceB, aad, result.ciphertext(), result.tag());
        }, "Decrypting with the wrong nonce must trigger an AEAD authentication failure.");
    }

    @Test
    @DisplayName("TC-AEAD06: Tampered Authentication Tag Rejection")
    void testTamperedTagRejection() {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] plaintext = "Integrity Protected Message".getBytes(StandardCharsets.UTF_8);

        ChaCha20Poly1305.AeadResult result = ChaCha20Poly1305.encrypt(key, nonce, plaintext);

        byte[] tamperedTag = result.tag().clone();
        tamperedTag[15] ^= 0x01; // flip 1 bit in tag

        assertThrows(SecurityException.class, () -> {
            ChaCha20Poly1305.decrypt(key, nonce, result.ciphertext(), tamperedTag);
        }, "Tampered MAC tag must be rejected immediately before plaintext release.");
    }

    @Test
    @DisplayName("TC-AEAD07: Empty Plaintext with and without AAD Round-Trip")
    void testEmptyPlaintextAead() {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] emptyPt = new byte[0];
        byte[] aad = "Authenticated Header Only".getBytes(StandardCharsets.UTF_8);

        // With AAD
        ChaCha20Poly1305.AeadResult resWithAad = ChaCha20Poly1305.encrypt(key, nonce, aad, emptyPt);
        assertEquals(0, resWithAad.ciphertext().length, "Ciphertext for empty plaintext must be 0 bytes.");
        assertEquals(16, resWithAad.tag().length, "Tag must still be 16 bytes.");
        byte[] decryptedWithAad = ChaCha20Poly1305.decrypt(key, nonce, aad, resWithAad.ciphertext(), resWithAad.tag());
        assertArrayEquals(emptyPt, decryptedWithAad, "Decrypted empty plaintext must match original.");

        // Without AAD (null AAD)
        ChaCha20Poly1305.AeadResult resNoAad = ChaCha20Poly1305.encrypt(key, nonce, null, emptyPt);
        assertEquals(0, resNoAad.ciphertext().length);
        byte[] decryptedNoAad = ChaCha20Poly1305.decrypt(key, nonce, null, resNoAad.ciphertext(), resNoAad.tag());
        assertArrayEquals(emptyPt, decryptedNoAad);
    }

    @Test
    @DisplayName("TC-AEAD08: Empty AAD with Normal Plaintext Round-Trip")
    void testEmptyAadAead() {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] pt = "Payload without any associated data".getBytes(StandardCharsets.UTF_8);

        ChaCha20Poly1305.AeadResult res = ChaCha20Poly1305.encrypt(key, nonce, new byte[0], pt);
        byte[] dec = ChaCha20Poly1305.decrypt(key, nonce, new byte[0], res.ciphertext(), res.tag());
        assertArrayEquals(pt, dec, "AEAD with empty byte array AAD must encrypt and decrypt perfectly.");
    }

    @Test
    @DisplayName("TC-AEAD09: Invalid Tag Validations")
    void testInvalidTagValidation() {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] cipher = new byte[16];

        // Null tag
        assertThrows(IllegalArgumentException.class, () -> {
            ChaCha20Poly1305.decrypt(key, nonce, cipher, null);
        });

        // 0-byte tag
        assertThrows(IllegalArgumentException.class, () -> {
            ChaCha20Poly1305.decrypt(key, nonce, cipher, new byte[0]);
        });

        // 15-byte tag (short)
        assertThrows(IllegalArgumentException.class, () -> {
            ChaCha20Poly1305.decrypt(key, nonce, cipher, new byte[15]);
        });

        // 17-byte tag (long)
        assertThrows(IllegalArgumentException.class, () -> {
            ChaCha20Poly1305.decrypt(key, nonce, cipher, new byte[17]);
        });
    }
}
