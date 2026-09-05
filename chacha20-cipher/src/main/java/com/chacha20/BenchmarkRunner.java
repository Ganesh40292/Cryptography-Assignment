package com.chacha20;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Performance & Throughput Benchmarking Suite for ChaCha20, Round Variants, and AEAD.
 *
 * <p>Measures:
 * <ul>
 *   <li>Encryption Throughput in Megabytes per second (MB/s)</li>
 *   <li>Block Latency in nanoseconds per 64-byte block</li>
 *   <li>Comparative analysis between ChaCha8, ChaCha12, ChaCha20, and ChaCha20-Poly1305</li>
 * </ul>
 */
public final class BenchmarkRunner {

    private static final SecureRandom RANDOM = new SecureRandom();

    public static record BenchmarkResult(
            String algorithm,
            int payloadSizeBytes,
            long totalBytesProcessed,
            long totalElapsedNanos,
            int iterations,
            double throughputMBps,
            double nanosPerBlock
    ) {}

    private BenchmarkRunner() {
        // Utility class
    }

    /**
     * Executes a benchmark for a specific payload size and algorithm.
     *
     * @param algorithm name ("ChaCha8", "ChaCha12", "ChaCha20", "ChaCha20-Poly1305")
     * @param payloadSize size in bytes
     * @param iterations number of timed runs
     * @return BenchmarkResult with metrics
     */
    public static BenchmarkResult benchmark(String algorithm, int payloadSize, int iterations) {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] data = new byte[payloadSize];
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(nonce);
        RANDOM.nextBytes(data);

        // Warmup JVM JIT compiler
        for (int i = 0; i < 500; i++) {
            runAlgorithm(algorithm, key, nonce, data);
        }

        // Timed measurement run
        long startNanos = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            runAlgorithm(algorithm, key, nonce, data);
        }
        long elapsedNanos = System.nanoTime() - startNanos;

        long totalBytes = (long) payloadSize * iterations;
        double seconds = elapsedNanos / 1_000_000_000.0;
        double throughputMBps = (totalBytes / (1024.0 * 1024.0)) / seconds;

        long totalBlocks = (totalBytes + 63) / 64;
        double nanosPerBlock = (double) elapsedNanos / totalBlocks;

        return new BenchmarkResult(algorithm, payloadSize, totalBytes, elapsedNanos, iterations, throughputMBps, nanosPerBlock);
    }

    private static void runAlgorithm(String algorithm, byte[] key, byte[] nonce, byte[] data) {
        switch (algorithm) {
            case "ChaCha8":
                ChaCha20.encrypt(key, 1, nonce, data, 8);
                break;
            case "ChaCha12":
                ChaCha20.encrypt(key, 1, nonce, data, 12);
                break;
            case "ChaCha20":
                ChaCha20.encrypt(key, 1, nonce, data, 20);
                break;
            case "ChaCha20-Poly1305":
                ChaCha20Poly1305.encrypt(key, nonce, data);
                break;
            default:
                ChaCha20.encrypt(key, 1, nonce, data);
        }
    }

    /**
     * Runs a standard benchmark suite comparing ChaCha8, ChaCha12, ChaCha20, and ChaCha20-Poly1305
     * across 64B, 1KB, 64KB, and 1MB payloads.
     */
    public static List<BenchmarkResult> runComprehensiveSuite() {
        int[] sizes = new int[]{64, 1024, 64 * 1024, 1024 * 1024};
        String[] algorithms = new String[]{"ChaCha8", "ChaCha12", "ChaCha20", "ChaCha20-Poly1305"};

        List<BenchmarkResult> results = new ArrayList<>();

        for (int size : sizes) {
            int iters = (size >= 1024 * 1024) ? 50 : (size >= 64 * 1024 ? 500 : 5000);
            for (String algo : algorithms) {
                results.add(benchmark(algo, size, iters));
            }
        }

        return results;
    }
}
