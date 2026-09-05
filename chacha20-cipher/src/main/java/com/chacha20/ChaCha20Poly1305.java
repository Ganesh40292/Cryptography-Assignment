package com.chacha20;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) as defined in RFC 8439 Section 2.8.
 *
 * <p>Provides simultaneous confidentiality, integrity, and authenticity for data payloads.
 *
 * <p>Pipeline:
 * <ol>
 *   <li>Generate 32-byte Poly1305 key using ChaCha20 block function with counter = 0</li>
 *   <li>Encrypt plaintext using ChaCha20 with initial counter = 1</li>
 *   <li>Construct mac data: AAD || pad16(AAD) || Ciphertext || pad16(Ciphertext) || len(AAD) [8 bytes LE] || len(Ciphertext) [8 bytes LE]</li>
 *   <li>Compute 16-byte Poly1305 tag over the constructed mac data</li>
 * </ol>
 */
public final class ChaCha20Poly1305 {

    public static final int TAG_LENGTH_BYTES = 16;
    public static final int KEY_LENGTH_BYTES = 32;
    public static final int NONCE_LENGTH_BYTES = 12;

    private ChaCha20Poly1305() {
        // Utility class
    }

    /**
     * Represents the combined output of an AEAD encryption: Ciphertext + Authentication Tag.
     */
    public static record AeadResult(byte[] ciphertext, byte[] tag) {
        /**
         * Returns the concatenated ciphertext and 16-byte authentication tag.
         */
        public byte[] toCombinedByteArray() {
            byte[] combined = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
            System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);
            return combined;
        }
    }

    /**
     * Derives the 32-byte one-time Poly1305 subkey using ChaCha20 block function at counter 0.
     *
     * @param key 256-bit key (32 bytes)
     * @param nonce 96-bit nonce (12 bytes)
     * @return 32-byte Poly1305 key
     */
    public static byte[] derivePoly1305Key(byte[] key, byte[] nonce) {
        InputValidator.validateKey(key);
        InputValidator.validateNonce(nonce);
        byte[] block0 = ChaCha20.chachaBlock(key, 0, nonce);
        return Arrays.copyOfRange(block0, 0, 32);
    }

    /**
     * Constructs the message buffer for Poly1305 authentication (RFC 8439 Section 2.8).
     */
    public static byte[] constructMacData(byte[] aad, byte[] ciphertext) {
        byte[] safeAad = (aad != null) ? aad : new byte[0];
        byte[] safeCiphertext = (ciphertext != null) ? ciphertext : new byte[0];

        int aadPaddingLen = (16 - (safeAad.length % 16)) % 16;
        int cipherPaddingLen = (16 - (safeCiphertext.length % 16)) % 16;

        int totalLen = safeAad.length + aadPaddingLen + safeCiphertext.length + cipherPaddingLen + 16;
        ByteBuffer buffer = ByteBuffer.allocate(totalLen).order(ByteOrder.LITTLE_ENDIAN);

        // 1. AAD + padding
        buffer.put(safeAad);
        if (aadPaddingLen > 0) {
            buffer.put(new byte[aadPaddingLen]);
        }

        // 2. Ciphertext + padding
        buffer.put(safeCiphertext);
        if (cipherPaddingLen > 0) {
            buffer.put(new byte[cipherPaddingLen]);
        }

        // 3. Lengths as 64-bit unsigned integers in little-endian order
        buffer.putLong(safeAad.length);
        buffer.putLong(safeCiphertext.length);

        return buffer.array();
    }

    /**
     * Encrypts plaintext and generates a 16-byte Poly1305 authentication tag with Associated Data (AAD).
     *
     * @param key 256-bit encryption key (32 bytes)
     * @param nonce 96-bit nonce (12 bytes)
     * @param aad optional Additional Authenticated Data (can be null or empty)
     * @param plaintext plaintext payload
     * @return AeadResult containing ciphertext and authentication tag
     */
    public static AeadResult encrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) {
        InputValidator.validateKey(key);
        InputValidator.validateNonce(nonce);
        InputValidator.validateData(plaintext);

        // 1. Generate one-time Poly1305 subkey from block 0
        byte[] poly1305Key = derivePoly1305Key(key, nonce);

        // 2. Encrypt plaintext starting from counter = 1
        byte[] ciphertext = ChaCha20.encrypt(key, 1, nonce, plaintext);

        // 3. Construct the authenticated message payload
        byte[] macData = constructMacData(aad, ciphertext);

        // 4. Compute Poly1305 MAC tag
        byte[] tag = Poly1305.computeMac(poly1305Key, macData);

        return new AeadResult(ciphertext, tag);
    }

    /**
     * Overloaded AEAD encryption without Associated Data (AAD).
     */
    public static AeadResult encrypt(byte[] key, byte[] nonce, byte[] plaintext) {
        return encrypt(key, nonce, null, plaintext);
    }

    /**
     * Decrypts ciphertext and verifies the 16-byte Poly1305 authentication tag.
     *
     * @param key 256-bit encryption key (32 bytes)
     * @param nonce 96-bit nonce (12 bytes)
     * @param aad optional Additional Authenticated Data (must match encryption AAD)
     * @param ciphertext ciphertext payload
     * @param tag 16-byte Poly1305 authentication tag
     * @return decrypted plaintext byte array
     * @throws SecurityException if authentication tag verification fails (tampering detected)
     */
    public static byte[] decrypt(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext, byte[] tag) {
        InputValidator.validateKey(key);
        InputValidator.validateNonce(nonce);
        InputValidator.validateData(ciphertext);

        InputValidator.validateTag(tag);

        // 1. Generate one-time Poly1305 subkey from block 0
        byte[] poly1305Key = derivePoly1305Key(key, nonce);

        // 2. Construct authenticated message payload
        byte[] macData = constructMacData(aad, ciphertext);

        // 3. Compute expected MAC tag
        byte[] expectedTag = Poly1305.computeMac(poly1305Key, macData);

        // 4. Verify tag in constant time
        if (!Poly1305.verify(expectedTag, tag)) {
            throw new SecurityException("AEAD Authentication failed: MAC tag mismatch (data has been tampered with or corrupted).");
        }

        // 5. Decrypt ciphertext starting from counter = 1
        return ChaCha20.decrypt(key, 1, nonce, ciphertext);
    }

    /**
     * Overloaded AEAD decryption without Associated Data (AAD).
     */
    public static byte[] decrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag) {
        return decrypt(key, nonce, null, ciphertext, tag);
    }
}
