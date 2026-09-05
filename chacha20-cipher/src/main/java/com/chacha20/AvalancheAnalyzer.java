package com.chacha20;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Cryptographic Avalanche Effect & Bit-Diffusion Analyzer for ChaCha20.
 *
 * <p>Measures how a single bit flip in the input (Key, Nonce, or Block Counter)
 * diffuses across the 512-bit internal state across each of the 20 permutation rounds.
 *
 * <p>The Strict Avalanche Criterion (SAC) is a statistical property requiring that whenever
 * a single input bit is complemented, each output bit changes with a probability of 0.5.
 * A single bit-flip experiment demonstrates observed bit diffusion towards this expected ~50%
 * behavior, while multi-trial experiments aggregate diffusion statistics across multiple bit positions.
 */
public final class AvalancheAnalyzer {

    public static final int TOTAL_STATE_BITS = 512;

    public enum PerturbationTarget {
        KEY,
        NONCE,
        COUNTER
    }

    public static record RoundMetric(int round, int flippedBits, double percentageFlipped) {}

    public static record AvalancheReport(
            PerturbationTarget target,
            int bitPosition,
            List<RoundMetric> roundMetrics,
            int finalFlippedBits,
            double finalPercentage
    ) {}

    public static record MultiTrialReport(
            int totalTrials,
            int minFlippedBits,
            int maxFlippedBits,
            double meanFlippedBits,
            double meanPercentage,
            double stdDevBits
    ) {}

    private AvalancheAnalyzer() {
        // Utility class
    }

    /**
     * Calculates the Hamming distance (total number of differing bits) between two 16-word states.
     *
     * @param stateA first 16-word state
     * @param stateB second 16-word state
     * @return count of differing bits (0..512)
     */
    public static int computeHammingDistance(int[] stateA, int[] stateB) {
        int distance = 0;
        for (int i = 0; i < 16; i++) {
            distance += Integer.bitCount(stateA[i] ^ stateB[i]);
        }
        return distance;
    }

    /**
     * Executes the Avalanche Effect analysis across all 20 rounds.
     *
     * @param baseKey 32-byte baseline key
     * @param baseCounter baseline counter (e.g. 1)
     * @param baseNonce 12-byte baseline nonce
     * @param target which parameter to flip (KEY, NONCE, COUNTER)
     * @param byteIndex index of the byte to flip a bit in
     * @param bitIndex bit index within that byte (0..7)
     * @return AvalancheReport containing progression across rounds 1..20
     */
    public static AvalancheReport analyze(byte[] baseKey, int baseCounter, byte[] baseNonce,
                                          PerturbationTarget target, int byteIndex, int bitIndex) {
        if (target == null) {
            throw new IllegalArgumentException("Perturbation target cannot be null.");
        }

        // Explicit parameter index validation to prevent silent modulo wrapping
        switch (target) {
            case KEY:
                if (byteIndex < 0 || byteIndex > 31) {
                    throw new IllegalArgumentException(String.format(
                            "Key byte index must be between 0 and 31 (received: %d).", byteIndex));
                }
                if (bitIndex < 0 || bitIndex > 7) {
                    throw new IllegalArgumentException(String.format(
                            "Bit index must be between 0 and 7 (received: %d).", bitIndex));
                }
                break;
            case NONCE:
                if (byteIndex < 0 || byteIndex > 11) {
                    throw new IllegalArgumentException(String.format(
                            "Nonce byte index must be between 0 and 11 (received: %d).", byteIndex));
                }
                if (bitIndex < 0 || bitIndex > 7) {
                    throw new IllegalArgumentException(String.format(
                            "Bit index must be between 0 and 7 (received: %d).", bitIndex));
                }
                break;
            case COUNTER:
                if (bitIndex < 0 || bitIndex > 31) {
                    throw new IllegalArgumentException(String.format(
                            "Counter bit index must be between 0 and 31 (received: %d).", bitIndex));
                }
                break;
        }

        byte[] key1 = Arrays.copyOf(baseKey, 32);
        byte[] key2 = Arrays.copyOf(baseKey, 32);
        int counter1 = baseCounter;
        int counter2 = baseCounter;
        byte[] nonce1 = Arrays.copyOf(baseNonce, 12);
        byte[] nonce2 = Arrays.copyOf(baseNonce, 12);

        byte mask = (byte) (1 << bitIndex);

        switch (target) {
            case KEY:
                key2[byteIndex] ^= mask;
                break;
            case NONCE:
                nonce2[byteIndex] ^= mask;
                break;
            case COUNTER:
                counter2 ^= (1 << bitIndex);
                break;
        }

        int[] stateA = ChaCha20.createInitialState(key1, counter1, nonce1);
        int[] stateB = ChaCha20.createInitialState(key2, counter2, nonce2);

        List<RoundMetric> metrics = new ArrayList<>();

        for (int r = 1; r <= 20; r++) {
            ChaCha20.applySingleRound(stateA, r);
            ChaCha20.applySingleRound(stateB, r);

            int dist = computeHammingDistance(stateA, stateB);
            double pct = (dist * 100.0) / TOTAL_STATE_BITS;
            metrics.add(new RoundMetric(r, dist, pct));
        }

        RoundMetric finalMetric = metrics.get(metrics.size() - 1);
        int bitPos = (target == PerturbationTarget.COUNTER) ? bitIndex : (byteIndex * 8) + bitIndex;
        return new AvalancheReport(target, bitPos, metrics,
                finalMetric.flippedBits(), finalMetric.percentageFlipped());
    }

    /**
     * Executes a multi-trial avalanche experiment flipping bits across different positions
     * to statistically assess diffusion consistency across the 512-bit state.
     *
     * @param trials number of distinct bit perturbation trials (e.g. 32, 64)
     * @return MultiTrialReport with min, max, mean, and standard deviation
     */
    public static MultiTrialReport runMultiTrialAnalysis(int trials) {
        if (trials <= 0) {
            throw new IllegalArgumentException("Number of trials must be positive.");
        }
        byte[] defaultKey = new byte[32];
        for (int i = 0; i < 32; i++) defaultKey[i] = (byte) (i * 7 + 13);
        byte[] defaultNonce = new byte[]{0,0,0,0, 0,0,0,0x4a, 0,0,0,0};

        int minBits = Integer.MAX_VALUE;
        int maxBits = Integer.MIN_VALUE;
        long sumBits = 0;
        int[] results = new int[trials];

        for (int t = 0; t < trials; t++) {
            int byteIdx = (t / 8) % 32;
            int bitIdx = t % 8;
            AvalancheReport report = analyze(defaultKey, 1, defaultNonce, PerturbationTarget.KEY, byteIdx, bitIdx);
            int flipped = report.finalFlippedBits();
            results[t] = flipped;
            sumBits += flipped;
            if (flipped < minBits) minBits = flipped;
            if (flipped > maxBits) maxBits = flipped;
        }

        double meanBits = (double) sumBits / trials;
        double varianceSum = 0;
        for (int r : results) {
            varianceSum += Math.pow(r - meanBits, 2);
        }
        double stdDev = Math.sqrt(varianceSum / trials);
        double meanPct = (meanBits * 100.0) / TOTAL_STATE_BITS;

        return new MultiTrialReport(trials, minBits, maxBits, meanBits, meanPct, stdDev);
    }

    /**
     * Helper to run a standard baseline avalanche analysis flipping bit 0 of the key.
     */
    public static AvalancheReport runDefaultAnalysis() {
        byte[] defaultKey = new byte[32];
        for (int i = 0; i < 32; i++) defaultKey[i] = (byte) i;
        byte[] defaultNonce = new byte[]{0,0,0,0, 0,0,0,0x4a, 0,0,0,0};
        return analyze(defaultKey, 1, defaultNonce, PerturbationTarget.KEY, 0, 0);
    }
}
