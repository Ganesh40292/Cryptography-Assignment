package com.chacha20;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit 5 Unit Tests for FileCipher buffered stream processing.
 */
public class FileCipherTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    @DisplayName("TC-F01: Large File Streaming Round-Trip Verification")
    void testFileEncryptionRoundTrip(@TempDir Path tempDir) throws IOException {
        // Create a 250 KB random binary test file (crosses multiple 64 KB buffers)
        byte[] originalContent = new byte[250 * 1024];
        RANDOM.nextBytes(originalContent);

        File plainFile = tempDir.resolve("sample.dat").toFile();
        File encFile = tempDir.resolve("sample.dat.enc").toFile();
        File decFile = tempDir.resolve("sample.dat.dec").toFile();

        try (FileOutputStream fos = new FileOutputStream(plainFile)) {
            fos.write(originalContent);
        }

        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(nonce);

        // Encrypt file
        FileCipher.FileResult encRes = FileCipher.processFile(plainFile, encFile, key, nonce);
        assertEquals(originalContent.length, encRes.bytesProcessed());
        assertTrue(encFile.exists());
        assertEquals(plainFile.length(), encFile.length());

        // Decrypt file
        FileCipher.FileResult decRes = FileCipher.processFile(encFile, decFile, key, nonce);
        assertEquals(originalContent.length, decRes.bytesProcessed());
        assertTrue(decFile.exists());

        // Verify byte-for-byte identity
        byte[] decryptedContent = Files.readAllBytes(decFile.toPath());
        assertArrayEquals(originalContent, decryptedContent, "Decrypted file content must match original binary exactly.");
    }

    @Test
    @DisplayName("TC-F02: Same Input and Output File Path Rejection")
    void testSameInputOutputFileRejection(@TempDir Path tempDir) throws IOException {
        File plainFile = tempDir.resolve("collision.txt").toFile();
        Files.writeString(plainFile.toPath(), "Critical payload data to prevent truncation");

        byte[] key = new byte[32];
        byte[] nonce = new byte[12];

        // Same file object
        IllegalArgumentException ex1 = assertThrows(IllegalArgumentException.class, () -> {
            FileCipher.processFile(plainFile, plainFile, key, nonce);
        }, "Specifying the exact same file as input and output must be rejected.");
        assertTrue(ex1.getMessage().contains("must be different"));

        // Equivalent path file object
        File sameFileOtherInstance = new File(plainFile.getAbsolutePath());
        IllegalArgumentException ex2 = assertThrows(IllegalArgumentException.class, () -> {
            FileCipher.processFile(plainFile, sameFileOtherInstance, key, nonce);
        });
        assertTrue(ex2.getMessage().contains("must be different"));

        // When output file already exists and refers to the same file
        File existingTarget = tempDir.resolve("existing_collision.txt").toFile();
        Files.writeString(existingTarget.toPath(), "Target content");
        File sameTargetSecondHandle = new File(existingTarget.getCanonicalPath());
        IllegalArgumentException ex3 = assertThrows(IllegalArgumentException.class, () -> {
            FileCipher.processFile(existingTarget, sameTargetSecondHandle, key, nonce);
        });
        assertTrue(ex3.getMessage().contains("must be different"));
    }

    @Test
    @DisplayName("TC-F03: File Size Edge Cases (0, 1, 2, 63, 64, 65, 127, 128, 129, 65535, 65536, 65537 bytes)")
    void testFileSizeEdgeCases(@TempDir Path tempDir) throws IOException {
        int[] edgeSizes = {
                0,        // Empty file
                1,        // Single byte
                2,        // Two bytes
                63,       // 1 byte below ChaCha20 block boundary
                64,       // Exact single ChaCha20 block
                65,       // 1 byte above ChaCha20 block boundary
                127,      // 1 byte below 2 ChaCha20 blocks
                128,      // Exactly 2 ChaCha20 blocks
                129,      // 1 byte above 2 ChaCha20 blocks
                65535,    // 1 byte below FileCipher buffer boundary (64 KB - 1)
                65536,    // Exactly 1 FileCipher buffer boundary (64 KB)
                65537     // 1 byte above FileCipher buffer boundary (64 KB + 1)
        };

        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(nonce);

        for (int size : edgeSizes) {
            byte[] content = new byte[size];
            RANDOM.nextBytes(content);

            File src = tempDir.resolve("edge_" + size + ".bin").toFile();
            File enc = tempDir.resolve("edge_" + size + ".bin.enc").toFile();
            File dec = tempDir.resolve("edge_" + size + ".bin.dec").toFile();

            Files.write(src.toPath(), content);

            // Encrypt
            FileCipher.FileResult encRes = FileCipher.processFile(src, enc, key, nonce);
            assertEquals(size, encRes.bytesProcessed());
            assertEquals(size, enc.length());

            // Decrypt
            FileCipher.FileResult decRes = FileCipher.processFile(enc, dec, key, nonce);
            assertEquals(size, decRes.bytesProcessed());

            // Compare
            byte[] roundTrip = Files.readAllBytes(dec.toPath());
            assertArrayEquals(content, roundTrip, "File size " + size + " bytes failed round-trip decryption.");
        }
    }

    @Test
    @DisplayName("TC-F04: Large 1MB Random Binary File Streaming Round-Trip")
    void testLargeOneMegabyteFile(@TempDir Path tempDir) throws IOException {
        int size = 1024 * 1024; // 1 MB
        byte[] largeContent = new byte[size];
        RANDOM.nextBytes(largeContent);

        File src = tempDir.resolve("large_1mb.bin").toFile();
        File enc = tempDir.resolve("large_1mb.bin.enc").toFile();
        File dec = tempDir.resolve("large_1mb.bin.dec").toFile();

        Files.write(src.toPath(), largeContent);

        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(key);
        RANDOM.nextBytes(nonce);

        FileCipher.processFile(src, enc, key, nonce);
        FileCipher.processFile(enc, dec, key, nonce);

        byte[] roundTrip = Files.readAllBytes(dec.toPath());
        assertArrayEquals(largeContent, roundTrip, "1 MB random binary file must round-trip with zero bit corruptions.");
    }
}
