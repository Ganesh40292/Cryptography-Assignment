package com.chacha20;

/**
 * Validator class for ChaCha20 cipher parameters according to RFC 8439.
 * Ensures keys, nonces, counters, and data buffers satisfy algorithmic requirements.
 */
public final class InputValidator {

    public static final int KEY_LENGTH_BYTES = 32;       // 256 bits
    public static final int NONCE_LENGTH_BYTES = 12;     // 96 bits (IETF ChaCha20 / RFC 8439)
    public static final int BLOCK_SIZE_BYTES = 64;       // 512 bits state / block

    private InputValidator() {
        // Prevent instantiation
    }

    /**
     * Validates the 256-bit encryption key.
     *
     * @param key the key byte array
     * @throws IllegalArgumentException if the key is null or not exactly 32 bytes (256 bits)
     */
    public static void validateKey(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null.");
        }
        if (key.length != KEY_LENGTH_BYTES) {
            throw new IllegalArgumentException(String.format(
                    "Invalid key length: %d bytes (%d bits). ChaCha20 requires exactly %d bytes (256 bits).",
                    key.length, key.length * 8, KEY_LENGTH_BYTES));
        }
    }

    /**
     * Validates the 96-bit nonce.
     *
     * @param nonce the nonce byte array
     * @throws IllegalArgumentException if the nonce is null or not exactly 12 bytes (96 bits)
     */
    public static void validateNonce(byte[] nonce) {
        if (nonce == null) {
            throw new IllegalArgumentException("Nonce cannot be null.");
        }
        if (nonce.length != NONCE_LENGTH_BYTES) {
            throw new IllegalArgumentException(String.format(
                    "Invalid nonce length: %d bytes (%d bits). RFC 8439 ChaCha20 requires exactly %d bytes (96 bits).",
                    nonce.length, nonce.length * 8, NONCE_LENGTH_BYTES));
        }
    }

    /**
     * Validates the 32-bit block counter.
     *
     * @param counter the counter value as a long to check unsigned 32-bit range
     * @throws IllegalArgumentException if the counter is outside [0, 2^32 - 1]
     */
    public static void validateCounter(long counter) {
        if (counter < 0 || counter > 0xFFFFFFFFL) {
            throw new IllegalArgumentException(String.format(
                    "Counter value %d is out of valid 32-bit unsigned range [0, 4294967295 (0xFFFFFFFF)].",
                    counter));
        }
    }

    /**
     * Validates input data buffer (plaintext or ciphertext).
     *
     * @param data the byte array to validate
     * @throws IllegalArgumentException if data is null
     */
    public static void validateData(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Input data buffer cannot be null.");
        }
    }

    /**
     * Validates that a string is a valid hexadecimal representation.
     *
     * @param hex the string to validate
     * @return true if valid hex string
     */
    public static boolean isValidHex(String hex) {
        if (hex == null) {
            return false;
        }
        String cleaned = hex.replaceAll("[\\s:\\-]", "");
        if (cleaned.isEmpty()) {
            return true;
        }
        if (cleaned.length() % 2 != 0) {
            return false;
        }
        for (int i = 0; i < cleaned.length(); i++) {
            char c = cleaned.charAt(i);
            if (Character.digit(c, 16) == -1) {
                return false;
            }
        }
        return true;
    }

    /**
     * Validates the 128-bit (16-byte) Poly1305 authentication tag.
     *
     * @param tag the tag byte array
     * @throws IllegalArgumentException if tag is null or not exactly 16 bytes
     */
    public static void validateTag(byte[] tag) {
        if (tag == null) {
            throw new IllegalArgumentException("Authentication tag cannot be null.");
        }
        if (tag.length != 16) {
            throw new IllegalArgumentException(String.format(
                    "Invalid tag length: %d bytes. Poly1305 requires exactly 16 bytes (128 bits).", tag.length));
        }
    }
}
