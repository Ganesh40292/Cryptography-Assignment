package com.chacha20;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Pure Java implementation of the Poly1305 One-Time Authenticator (RFC 8439 Section 2.5).
 *
 * <p>Poly1305 takes a 32-byte one-time key and a message of arbitrary length,
 * and produces a 16-byte (128-bit) authentication tag.
 *
 * <p>Formulas (modulo 2^130 - 5):
 * <ul>
 *   <li>Key is split into (r, s): r = key[0..15] (clamped), s = key[16..31]</li>
 *   <li>Accumulator a = 0</li>
 *   <li>For each block: a = ((a + block + 2^(8*len)) * r) mod (2^130 - 5)</li>
 *   <li>Tag = (a + s) mod 2^128</li>
 * </ul>
 *
 * <p><b>Side-Channel Notice:</b> This educational implementation relies on {@link java.math.BigInteger}
 * for modular arithmetic modulo 2^130 - 5. Java's BigInteger does not provide constant-time execution
 * guarantees. While the {@link #verify(byte[], byte[])} method performs a constant-time comparison
 * to eliminate timing leakage during authentication tag checks, the mathematical operations are not
 * formally constant-time.
 */
public final class Poly1305 {

    public static final int KEY_SIZE_BYTES = 32;
    public static final int BLOCK_SIZE_BYTES = 16;
    public static final int TAG_SIZE_BYTES = 16;

    // Prime modulus p = 2^130 - 5
    private static final BigInteger P = BigInteger.valueOf(2).pow(130).subtract(BigInteger.valueOf(5));
    // 2^128 for final tag addition modulo 2^128
    private static final BigInteger TWO_POW_128 = BigInteger.valueOf(2).pow(128);

    private Poly1305() {
        // Utility class
    }

    /**
     * Clamps the 16-byte r portion of the Poly1305 key according to RFC 8439 Section 2.5.
     *
     * @param rRaw 16-byte raw r key
     * @return 16-byte clamped r array
     */
    public static byte[] clamp(byte[] rRaw) {
        if (rRaw == null || rRaw.length != 16) {
            throw new IllegalArgumentException("r component must be exactly 16 bytes.");
        }
        byte[] r = Arrays.copyOf(rRaw, 16);
        r[3] &= 15;
        r[7] &= 15;
        r[11] &= 15;
        r[15] &= 15;
        r[4] &= (byte) 252;
        r[8] &= (byte) 252;
        r[12] &= (byte) 252;
        return r;
    }

    /**
     * Converts a little-endian byte array to an unsigned BigInteger.
     */
    private static BigInteger leBytesToBigInteger(byte[] bytes, int offset, int length) {
        byte[] beBytes = new byte[length + 1]; // +1 for positive sign
        for (int i = 0; i < length; i++) {
            beBytes[length - i] = bytes[offset + i];
        }
        return new BigInteger(beBytes);
    }

    /**
     * Serializes a BigInteger to a 16-byte array in little-endian format.
     */
    private static byte[] bigIntegerToLeBytes16(BigInteger value) {
        byte[] out = new byte[TAG_SIZE_BYTES];
        byte[] be = value.toByteArray();
        int beLen = be.length;
        for (int i = 0; i < TAG_SIZE_BYTES; i++) {
            int srcIdx = beLen - 1 - i;
            out[i] = (srcIdx >= 0) ? be[srcIdx] : 0;
        }
        return out;
    }

    /**
     * Computes the 16-byte Poly1305 MAC tag for the given message using the 32-byte one-time key.
     *
     * @param key 32-byte one-time key (first 16 bytes for r, second 16 bytes for s)
     * @param message arbitrary-length message to authenticate
     * @return 16-byte authentication tag
     */
    public static byte[] computeMac(byte[] key, byte[] message) {
        if (key == null || key.length != KEY_SIZE_BYTES) {
            throw new IllegalArgumentException("Poly1305 key must be exactly 32 bytes.");
        }
        if (message == null) {
            throw new IllegalArgumentException("Message cannot be null.");
        }

        // 1. Extract and clamp r
        byte[] rClamped = clamp(Arrays.copyOfRange(key, 0, 16));
        BigInteger r = leBytesToBigInteger(rClamped, 0, 16);

        // 2. Extract s
        BigInteger s = leBytesToBigInteger(key, 16, 16);

        // 3. Initialize accumulator a = 0
        BigInteger a = BigInteger.ZERO;

        int numBlocks = (message.length + BLOCK_SIZE_BYTES - 1) / BLOCK_SIZE_BYTES;
        if (message.length == 0) {
            numBlocks = 0;
        }

        for (int i = 0; i < numBlocks; i++) {
            int offset = i * BLOCK_SIZE_BYTES;
            int blockSize = Math.min(BLOCK_SIZE_BYTES, message.length - offset);

            // Construct block with appended 0x01 byte: block || 0x01
            byte[] blockWithOne = new byte[blockSize + 1];
            System.arraycopy(message, offset, blockWithOne, 0, blockSize);
            blockWithOne[blockSize] = 0x01;

            BigInteger n = leBytesToBigInteger(blockWithOne, 0, blockWithOne.length);

            // a = ((a + n) * r) % P
            a = a.add(n).multiply(r).mod(P);
        }

        // 4. Final tag calculation: (a + s) % 2^128
        BigInteger tagInt = a.add(s).mod(TWO_POW_128);

        return bigIntegerToLeBytes16(tagInt);
    }

    /**
     * Constant-time comparison of two MAC tags to prevent timing side-channel attacks.
     *
     * @param tag1 first 16-byte tag
     * @param tag2 second 16-byte tag
     * @return true if tags are identical, false otherwise
     */
    public static boolean verify(byte[] tag1, byte[] tag2) {
        if (tag1 == null || tag2 == null || tag1.length != TAG_SIZE_BYTES || tag2.length != TAG_SIZE_BYTES) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < TAG_SIZE_BYTES; i++) {
            diff |= (tag1[i] ^ tag2[i]);
        }
        return diff == 0;
    }
}
