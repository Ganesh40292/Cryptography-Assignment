package com.chacha20;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit 5 Unit Tests for Poly1305 One-Time Authenticator (RFC 8439 Section 2.5).
 */
public class Poly1305Test {

    @Test
    @DisplayName("TC-P01: Official RFC 8439 Section 2.5.2 Poly1305 Test Vector")
    void testRfc8439Section252Vector() {
        // 32-byte one-time key
        String keyHex = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b";
        byte[] key = HexUtils.hexToBytes(keyHex);

        // Message: "Cryptographic Forum Research Group"
        String msg = "Cryptographic Forum Research Group";
        byte[] msgBytes = msg.getBytes(StandardCharsets.US_ASCII);

        // Expected Tag from RFC 8439 Section 2.5.2
        String expectedTagHex = "a8061dc1305136c6c22b8baf0c0127a9";

        byte[] tag = Poly1305.computeMac(key, msgBytes);
        String actualTagHex = HexUtils.bytesToHex(tag);

        assertEquals(expectedTagHex, actualTagHex, "Poly1305 tag must match RFC 8439 Section 2.5.2 exactly.");
    }

    @Test
    @DisplayName("TC-P02: Empty Message MAC computation")
    void testEmptyMessageMac() {
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) key[i] = (byte) (i + 1);

        byte[] tag = Poly1305.computeMac(key, new byte[0]);
        assertNotNull(tag);
        assertEquals(16, tag.length);
    }

    @Test
    @DisplayName("TC-P03: Constant-Time Tag Verification")
    void testTagVerification() {
        byte[] key = new byte[32];
        key[0] = 0x42;
        byte[] msg = "Secure Authentication Test".getBytes(StandardCharsets.UTF_8);

        byte[] tag = Poly1305.computeMac(key, msg);
        assertTrue(Poly1305.verify(tag, tag), "Identical tags must verify as true.");

        byte[] corruptedTag = tag.clone();
        corruptedTag[0] ^= 0x01;
        assertFalse(Poly1305.verify(tag, corruptedTag), "Corrupted tag must fail verification.");
    }
}
