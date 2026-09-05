package com.chacha20;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;

/**
 * High-performance buffered stream cipher for encrypting and decrypting files
 * (PDFs, images, videos, ZIPs, text documents) using ChaCha20.
 *
 * <p>Uses a 64 KB memory buffer with precise 64-byte block counter tracking to handle
 * large binary files within the available ChaCha20 32-bit block-counter space
 * with constant, minimal memory overhead.
 *
 * <p><b>Security and Operational Notes:</b>
 * <ul>
 *   <li><b>Confidentiality Only:</b> This file cipher applies raw ChaCha20 stream encryption.
 *       It provides confidentiality but does <i>not</i> provide message authentication or integrity verification.
 *       Tampering or bit-flipping on ciphertext files cannot be automatically detected by raw ChaCha20 alone.</li>
 *   <li><b>Key/Nonce/Counter Management:</b> The generated ciphertext file contains only the raw ciphertext payload;
 *       it does not store header metadata. Decryption requires the caller to provide the exact same key, nonce,
 *       and initial counter value.</li>
 * </ul>
 */
public final class FileCipher {

    public static final int BUFFER_SIZE_BYTES = 64 * 1024; // 64 KB chunk buffer
    public static final int BLOCK_SIZE_BYTES = ChaCha20.BLOCK_SIZE_BYTES; // 64 bytes

    private FileCipher() {
        // Utility class
    }

    /**
     * Statistics result returned after completing a file encryption or decryption operation.
     */
    public static record FileResult(File inputFile, File outputFile, long bytesProcessed, long elapsedNanos) {
        public double getThroughputMBps() {
            if (elapsedNanos <= 0) return 0.0;
            double seconds = elapsedNanos / 1_000_000_000.0;
            double megabytes = bytesProcessed / (1024.0 * 1024.0);
            return megabytes / seconds;
        }

        public double getElapsedMillis() {
            return elapsedNanos / 1_000_000.0;
        }
    }

    /**
     * Encrypts or decrypts a file using ChaCha20 stream cipher with specified key, counter, and nonce.
     * Since ChaCha20 uses symmetric XOR stream encryption, this single method performs both operations.
     *
     * @param inputFile source file to read
     * @param outputFile destination file to write (must be different from inputFile)
     * @param key 256-bit key (32 bytes)
     * @param initialCounter 32-bit initial block counter
     * @param nonce 96-bit nonce (12 bytes)
     * @param rounds number of rounds (e.g. 8, 12, 20)
     * @return FileResult containing processed size and execution time
     * @throws IOException on file I/O errors
     * @throws IllegalArgumentException if inputFile or outputFile are invalid, or if both refer to the same file
     */
    public static FileResult processFile(File inputFile, File outputFile, byte[] key, int initialCounter, byte[] nonce, int rounds) throws IOException {
        InputValidator.validateKey(key);
        InputValidator.validateNonce(nonce);

        if (inputFile == null || !inputFile.exists() || !inputFile.isFile()) {
            throw new IllegalArgumentException("Input file must exist and be a valid file.");
        }
        if (outputFile == null) {
            throw new IllegalArgumentException("Output file cannot be null.");
        }

        // Prevent file truncation bug when input and output point to the same file
        if (inputFile.getCanonicalFile().equals(outputFile.getCanonicalFile())) {
            throw new IllegalArgumentException("Input and output files must be different.");
        }

        // Check if both paths refer to the same filesystem object when output already exists
        if (outputFile.exists()) {
            try {
                if (Files.isSameFile(inputFile.toPath(), outputFile.toPath())) {
                    throw new IllegalArgumentException("Input and output files must be different.");
                }
            } catch (IOException ignored) {
                // If isSameFile fails due to provider-specific reasons, canonical check already protects above
            }
        }

        long startTime = System.nanoTime();
        long totalBytesProcessed = 0;
        long totalBlocksProcessed = 0;

        byte[] buffer = new byte[BUFFER_SIZE_BYTES];

        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(inputFile));
             BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(outputFile))) {

            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                // Number of 64-byte blocks in this chunk
                int numBlocksInChunk = (bytesRead + BLOCK_SIZE_BYTES - 1) / BLOCK_SIZE_BYTES;

                for (int b = 0; b < numBlocksInChunk; b++) {
                    int currentCounter = initialCounter + (int) totalBlocksProcessed;
                    byte[] keystreamBlock = ChaCha20.chachaBlock(key, currentCounter, nonce, rounds);

                    int offset = b * BLOCK_SIZE_BYTES;
                    int bytesInBlock = Math.min(BLOCK_SIZE_BYTES, bytesRead - offset);

                    for (int i = 0; i < bytesInBlock; i++) {
                        buffer[offset + i] ^= keystreamBlock[i];
                    }
                    totalBlocksProcessed++;
                }

                out.write(buffer, 0, bytesRead);
                totalBytesProcessed += bytesRead;
            }
            out.flush();
        }

        long elapsedNanos = System.nanoTime() - startTime;
        return new FileResult(inputFile, outputFile, totalBytesProcessed, elapsedNanos);
    }

    /**
     * Overloaded method with default 20 rounds and initial counter = 1.
     */
    public static FileResult processFile(File inputFile, File outputFile, byte[] key, byte[] nonce) throws IOException {
        return processFile(inputFile, outputFile, key, 1, nonce, ChaCha20.NUM_ROUNDS);
    }
}
