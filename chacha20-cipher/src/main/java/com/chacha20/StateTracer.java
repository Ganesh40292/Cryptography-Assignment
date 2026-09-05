package com.chacha20;

import java.util.Arrays;

/**
 * Step-by-Step State Matrix Visualizer & Trace Logger for ChaCha20.
 *
 * <p>Generates detailed ASCII-formatted representations of the 4x4 32-bit state matrix
 * at initial setup, after each individual round (1..20), feed-forward addition,
 * and final keystream byte serialization.
 */
public final class StateTracer {

    private StateTracer() {
        // Utility class
    }

    /**
     * Formats a 16-word state array into a clean 4x4 ASCII table.
     *
     * @param state 16-word state array
     * @return formatted ASCII string
     */
    public static String formatStateMatrix(int[] state) {
        if (state == null || state.length != 16) {
            return "[Invalid State: expected 16 words]";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("+--------------+--------------+--------------+--------------+\n");
        for (int row = 0; row < 4; row++) {
            sb.append("|");
            for (int col = 0; col < 4; col++) {
                int word = state[row * 4 + col];
                sb.append(String.format("  0x%08x  |", word));
            }
            sb.append("\n");
        }
        sb.append("+--------------+--------------+--------------+--------------+");
        return sb.toString();
    }

    /**
     * Generates a complete step-by-step trace of a 64-byte ChaCha20 block generation.
     *
     * @param key 256-bit key (32 bytes)
     * @param counter 32-bit block counter
     * @param nonce 96-bit nonce (12 bytes)
     * @param rounds number of rounds (e.g. 8, 12, 20)
     * @return multi-line formatted trace log
     */
    public static String traceBlock(byte[] key, int counter, byte[] nonce, int rounds) {
        StringBuilder sb = new StringBuilder();
        sb.append("=======================================================================\n");
        sb.append("                 CHACHA").append(rounds).append(" STEP-BY-STEP EXECUTION TRACE\n");
        sb.append("=======================================================================\n\n");

        sb.append("[1] INPUT PARAMETERS:\n");
        sb.append("  Key (256-bit)   : ").append(HexUtils.bytesToHex(key)).append("\n");
        sb.append("  Counter (32-bit): ").append(counter).append(" (0x").append(String.format("%08x", counter)).append(")\n");
        sb.append("  Nonce (96-bit)  : ").append(HexUtils.bytesToHex(nonce)).append("\n");
        sb.append("  Total Rounds    : ").append(rounds).append(" (").append(rounds / 2).append(" double rounds)\n\n");

        // Initial State
        int[] initialState = ChaCha20.createInitialState(key, counter, nonce);
        sb.append("[2] INITIAL 4x4 STATE MATRIX (512 bits):\n");
        sb.append("  Row 0 (Words 0..3)  : Constants (\"expand 32-byte k\")\n");
        sb.append("  Row 1 (Words 4..7)  : Key Words k0..k3\n");
        sb.append("  Row 2 (Words 8..11) : Key Words k4..k7\n");
        sb.append("  Row 3 (Words 12..15): Counter (Word 12) & Nonce n0..n2 (Words 13..15)\n");
        sb.append(formatStateMatrix(initialState)).append("\n\n");

        int[] workingState = Arrays.copyOf(initialState, 16);

        sb.append("[3] ROUND-BY-ROUND TRANSFORMATION:\n");
        for (int r = 1; r <= rounds; r++) {
            boolean isColumnRound = (r % 2 == 1);
            sb.append(String.format("--- Round %2d (%s Round) ---\n", r, isColumnRound ? "Column  " : "Diagonal"));
            if (isColumnRound) {
                sb.append("    QuarterRounds: QR(0,4,8,12)  QR(1,5,9,13)  QR(2,6,10,14)  QR(3,7,11,15)\n");
            } else {
                sb.append("    QuarterRounds: QR(0,5,10,15) QR(1,6,11,12) QR(2,7,8,13)  QR(3,4,9,14)\n");
            }

            ChaCha20.applySingleRound(workingState, r);
            sb.append(formatStateMatrix(workingState)).append("\n\n");
        }

        // Feed forward
        sb.append("[4] FEED-FORWARD ADDITION (Working State + Initial State mod 2^32):\n");
        int[] outputState = new int[16];
        for (int i = 0; i < 16; i++) {
            outputState[i] = workingState[i] + initialState[i];
        }
        sb.append(formatStateMatrix(outputState)).append("\n\n");

        // Keystream
        byte[] keystream = new byte[64];
        for (int i = 0; i < 16; i++) {
            ChaCha20.wordToBytesLittleEndian(outputState[i], keystream, i * 4);
        }

        sb.append("[5] FINAL SERIALIZED 64-BYTE KEYSTREAM BLOCK (Little-Endian Hex):\n");
        sb.append(HexUtils.formatHexDump(keystream)).append("\n");

        return sb.toString();
    }
}
