package com.chacha20;

/**
 * Utility class for converting between byte arrays, 32-bit integer words,
 * and hexadecimal string representations.
 */
public final class HexUtils {

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    private HexUtils() {
        // Prevent instantiation of utility class
    }

    /**
     * Converts a byte array to a continuous lowercase hexadecimal string.
     *
     * @param bytes the byte array to convert
     * @return lowercase hexadecimal string representation, or empty string if input is null/empty
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Converts a byte array to a formatted hexadecimal string separated by spaces.
     *
     * @param bytes the byte array to convert
     * @return spaced hexadecimal string
     */
    public static String bytesToSpacedHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            sb.append(HEX_ARRAY[v >>> 4]);
            sb.append(HEX_ARRAY[v & 0x0F]);
            if (i < bytes.length - 1) {
                sb.append(' ');
            }
        }
        return sb.toString();
    }

    /**
     * Converts a hexadecimal string to a byte array.
     * Ignores spaces, colons, and hyphens if present.
     *
     * @param hex the hexadecimal string to convert
     * @return parsed byte array
     * @throws IllegalArgumentException if the hex string contains invalid characters or has odd length
     */
    public static byte[] hexToBytes(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("Hex string cannot be null.");
        }
        // Remove common delimiters like spaces, colons, hyphens
        String cleaned = hex.replaceAll("[\\s:\\-]", "");
        if (cleaned.isEmpty()) {
            return new byte[0];
        }
        if (cleaned.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even number of hex digits (length = " + cleaned.length() + ").");
        }

        int len = cleaned.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int high = Character.digit(cleaned.charAt(i), 16);
            int low = Character.digit(cleaned.charAt(i + 1), 16);
            if (high == -1 || low == -1) {
                throw new IllegalArgumentException("Invalid hexadecimal character at position " + (high == -1 ? i : i + 1) + ": '" + cleaned.charAt(high == -1 ? i : i + 1) + "'");
            }
            data[i / 2] = (byte) ((high << 4) | low);
        }
        return data;
    }

    /**
     * Formats a 16-word ChaCha20 state as a 4x4 matrix in hexadecimal format.
     *
     * @param state the 16-word ChaCha20 state
     * @return multi-line string representing the 4x4 state matrix
     */
    public static String formatStateMatrix(int[] state) {
        if (state == null || state.length != 16) {
            throw new IllegalArgumentException("State must contain exactly 16 words.");
        }
        StringBuilder sb = new StringBuilder();
        for (int row = 0; row < 4; row++) {
            sb.append(String.format("  [%08x  %08x  %08x  %08x]%n",
                    state[row * 4],
                    state[row * 4 + 1],
                    state[row * 4 + 2],
                    state[row * 4 + 3]));
        }
        return sb.toString();
    }

    /**
     * Formats a byte array as a 16-bytes-per-line hexadecimal dump with ASCII preview.
     *
     * @param bytes source bytes
     * @return formatted hex dump string
     */
    public static String formatHexDump(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i += 16) {
            sb.append(String.format("  %04x: ", i));
            int lineLen = Math.min(16, bytes.length - i);
            for (int j = 0; j < 16; j++) {
                if (j < lineLen) {
                    sb.append(String.format("%02x ", bytes[i + j]));
                } else {
                    sb.append("   ");
                }
                if (j == 7) sb.append(" ");
            }
            sb.append(" |");
            for (int j = 0; j < lineLen; j++) {
                byte b = bytes[i + j];
                char c = (b >= 32 && b <= 126) ? (char) b : '.';
                sb.append(c);
            }
            sb.append("|\n");
        }
        return sb.toString();
    }

    /**
     * Securely clears sensitive cryptographic material from memory.
     *
     * @param bytes byte array to wipe
     */
    public static void zeroize(byte[] bytes) {
        if (bytes != null) {
            java.util.Arrays.fill(bytes, (byte) 0);
        }
    }
}
