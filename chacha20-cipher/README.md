# Implementation and Testing of ChaCha20 Stream Cipher

## 1. Assignment Context
* **Course:** BCS703 — Cryptography and Network Security
* **Semester:** 7th Semester B.Tech / B.E. Computer Science & Engineering
* **Assignment Task:** Q1 — Implementation and Testing of ChaCha20 Stream Cipher
* **Standard Specification:** RFC 8439 (IETF ChaCha20 and Poly1305 for IETF Protocols)
* **Programming Language:** Java 17+ (Java SE / Standard JDK, Zero Third-Party Crypto Libraries)
* **Target IDE:** NetBeans / IntelliJ IDEA / Eclipse / Command Line (Maven)

---

## 2. Project Objective
The primary objective of this project is to analyze, implement, and verify the **IETF ChaCha20 stream cipher** from scratch directly from the RFC 8439 mathematical specification. The implementation avoids high-level abstractions or third-party cryptographic libraries (such as BouncyCastle or `javax.crypto.Cipher`), explicitly detailing:
1. 32-bit unsigned word arithmetic using Java primitives
2. ChaCha20 Quarter Round ARX (Add-Rotate-Xor) operations
3. 512-bit state matrix construction (constants, key, block counter, nonce)
4. 20 rounds (10 double rounds alternating between column and diagonal rounds)
5. Little-endian serialization and block keystream generation
6. Multi-block plaintext encryption and decryption
7. Automated verification against official RFC 8439 normative test vectors and edge cases

---

## 3. What is ChaCha20?
**ChaCha20** is a modern symmetric stream cipher designed by Daniel J. Bernstein in 2008 as an evolution of Salsa20. It was standardized by the Internet Engineering Task Force (IETF) in **RFC 7539** and updated in **RFC 8439**.

ChaCha20 generates a pseudo-random keystream by processing a 512-bit internal state through 20 rounds of quarter-round transformations. The resulting keystream is XORed with plaintext bytes to produce ciphertext.

---

## 4. Why ChaCha20 is Used
1. **Software Performance:** Unlike AES, which requires hardware instructions (AES-NI) for high-speed execution, ChaCha20 is exceptionally fast in pure software on mobile devices, embedded systems, and CPUs without cryptographic accelerators.
2. **Timing Attack Immunity:** ChaCha20 uses only constant-time operations: addition modulo $2^{32}$, bitwise XOR, and fixed-distance bit rotations (ARX design). It uses no lookup tables (S-boxes), making it inherently immune to cache-timing side-channel attacks that affect table-based AES implementations.
3. **High Security Margin:** ChaCha20 uses 20 rounds. The best known cryptanalytic attacks can only break up to 7 rounds, leaving a massive 13-round security margin.
4. **Standardization & Industry Adoption:** ChaCha20 is widely deployed in TLS 1.3, OpenSSH, WireGuard VPN, Android OS encryption, and Apple iOS.

---

## 5. Important Cipher Parameters

| Parameter | Size (Bits) | Size (Bytes) | Description |
|---|---|---|---|
| **Key** | 256 bits | 32 bytes | Master secret key shared between sender and recipient |
| **Nonce (IV)** | 96 bits | 12 bytes | Number used once per key to ensure keystream uniqueness |
| **Block Counter** | 32 bits | 4 bytes | Incremented for each 64-byte block (allows up to 256 GB stream) |
| **Internal State** | 512 bits | 64 bytes | Organized as a $4 \times 4$ matrix of 16 unsigned 32-bit words |
| **Constants** | 128 bits | 16 bytes | ASCII `"expand 32-byte k"` in 4 little-endian words |
| **Rounds** | 20 rounds | — | 10 double rounds (10 column rounds + 10 diagonal rounds) |
| **Block Size** | 512 bits | 64 bytes | Keystream block size per state permutation |

---

## 6. High-Level Algorithm Flow

```
+-------------------------------------------------------------------------+
|                              ChaCha20 State                             |
|                                                                         |
|   [ c0 = 0x61707865 ]  [ c1 = 0x3320646e ]  [ c2 = 0x79622d32 ]  [ c3 = 0x6b206574 ]  |  Constants ("expand 32-byte k")
|   [ k0 (key 0..3)   ]  [ k1 (key 4..7)   ]  [ k2 (key 8..11)  ]  [ k3 (key 12..15) ]  |  256-bit Key
|   [ k4 (key 16..19) ]  [ k5 (key 20..23) ]  [ k6 (key 24..27) ]  [ k7 (key 28..31) ]  |  (8 words)
|   [ Block Counter   ]  [ Nonce 0 (0..3)  ]  [ Nonce 1 (4..7)  ]  [ Nonce 2 (8..11) ]  |  Counter + 96-bit Nonce
+-------------------------------------------------------------------------+
                                    |
                                    v
               +-----------------------------------------+
               |  Perform 10 Double Rounds (20 Rounds):  |
               |   - 4 Column Quarter-Rounds             |
               |   - 4 Diagonal Quarter-Rounds           |
               +-----------------------------------------+
                                    |
                                    v
               +-----------------------------------------+
               |  Add Original State (Modulo 2^32)       |
               |  to Permuted Working State              |
               +-----------------------------------------+
                                    |
                                    v
               +-----------------------------------------+
               |  Serialize 16 Words -> 64-Byte          |
               |  Little-Endian Keystream Block          |
               +-----------------------------------------+
                                    |
                                    v
               +-----------------------------------------+
               |  XOR Keystream Block with Input Block   |
               |  (Plaintext / Ciphertext)               |
               +-----------------------------------------+
```

---

## 7. Quarter Round Operation
The core primitive of ChaCha20 is the **Quarter Round (QR)** operating on 4 words $(a, b, c, d)$:

$$\begin{aligned}
a &= a + b \pmod{2^{32}}; & d &= (d \oplus a) \lll 16; \\
c &= c + d \pmod{2^{32}}; & b &= (b \oplus c) \lll 12; \\
a &= a + b \pmod{2^{32}}; & d &= (d \oplus a) \lll 8; \\
c &= c + d \pmod{2^{32}}; & b &= (b \oplus c) \lll 7;
\end{aligned}$$

### Round Structure:
1. **Column Round (Rounds 1, 3, 5, ..., 19):**
   * $\text{QR}(0, 4, 8, 12)$
   * $\text{QR}(1, 5, 9, 13)$
   * $\text{QR}(2, 6, 10, 14)$
   * $\text{QR}(3, 7, 11, 15)$
2. **Diagonal Round (Rounds 2, 4, 6, ..., 20):**
   * $\text{QR}(0, 5, 10, 15)$
   * $\text{QR}(1, 6, 11, 12)$
   * $\text{QR}(2, 7, 8, 13)$
   * $\text{QR}(3, 4, 9, 14)$

---

## 8. Encryption & Decryption Process
Stream ciphers encrypt by computing bitwise XOR between keystream and plaintext:

$$C_i = P_i \oplus K_i$$

Because XOR is self-inverting ($(A \oplus B) \oplus B = A$), decryption uses the exact same keystream:

$$P_i = C_i \oplus K_i$$

For messages longer than 64 bytes, the block counter is incremented for each subsequent 64-byte block ($1, 2, 3, \dots$). If the final block has fewer than 64 bytes, only the required prefix of the keystream is XORed.

---

## 9. Project Structure

```
chacha20-cipher/
├── pom.xml                                   <- Maven project build configuration
├── README.md                                 <- Comprehensive documentation
├── .gitignore                                <- Git ignore rules
│
├── src/
│   ├── main/
│   │   └── java/
│   │       └── com/
│   │           └── chacha20/
│   │               ├── ChaCha20.java         <- Core cryptographic implementation
│   │               ├── HexUtils.java         <- Hexadecimal & formatting utilities
│   │               ├── InputValidator.java   <- Parameter bounds and length validation
│   │               └── Main.java             <- Interactive CLI demonstration & runner
│   │
│   └── test/
│       └── java/
│           └── com/
│               └── chacha20/
│                   └── ChaCha20Test.java     <- JUnit 5 automated test suite
│
└── test-results/
    └── TEST-RESULTS.md                       <- Detailed test log and RFC verification
```

---

## 10. How to Build and Run

### Prerequisites
* JDK 17 or higher (tested on OpenJDK 17 and Oracle JDK 21)
* Apache Maven 3.8+ (or NetBeans IDE bundled Maven)

### Building the Project
From the `chacha20-cipher` directory:
```bash
mvn clean compile
```

### Running Automated Unit Tests
```bash
mvn test
```

### Packaging into Executable JAR
```bash
mvn package
```

### Running the Interactive Console Program
Using Maven:
```bash
mvn exec:java
```
Or running the packaged JAR directly:
```bash
java -jar target/chacha20-cipher-1.0.0.jar
```

### Running in Apache NetBeans IDE
1. Open NetBeans.
2. Select **File -> Open Project...**
3. Navigate to and select the `chacha20-cipher` folder (NetBeans detects it automatically via `pom.xml`).
4. Right-click the project -> **Clean and Build**.
5. Right-click the project -> **Run** (executes `com.chacha20.Main`).
6. Right-click `ChaCha20Test.java` -> **Test File** (`Ctrl+F6`) to run JUnit tests.

### Running the Interactive Web Frontend Studio
A modern interactive web visualizer with real-time 512-bit state matrix inspection, 20-round animation stepper, and RFC 8439 test vector testing is included in [`web/`](web/):
* Simply open [`web/index.html`](web/index.html) in any modern web browser (Chrome, Firefox, Edge, Safari).
* Or serve locally via python: `python -m http.server 8000 -d web` and visit `http://localhost:8000`.

---

## 11. Test Cases & Correctness Verification

The test suite in [`ChaCha20Test.java`](src/test/java/com/chacha20/ChaCha20Test.java) verifies 15 distinct properties:

1. **TEST 1 — Basic Round-Trip:** Verifies standard encryption and decryption recovery.
2. **TEST 2 — Short Plaintext:** Verifies encryption of short string `"Hello"` (5 bytes).
3. **TEST 3 — Empty Plaintext:** Verifies safe handling of 0-length byte array without crashing.
4. **TEST 4 — Multi-Block Plaintext:** Verifies 1330-byte message spanning across 21 ChaCha blocks with counter incrementation.
5. **TEST 5 — Key Sensitivity:** Confirms that distinct keys yield distinct ciphertexts.
6. **TEST 6 — Determinism:** Confirms identical inputs yield identical ciphertext.
7. **TEST 7 — Nonce Sensitivity:** Confirms different nonces produce distinct keystreams.
8. **TEST 8 — Counter Sensitivity:** Confirms counter change shifts keystream.
9. **TEST 9 — RFC 8439 Section 2.4.2 Test Vector:** Verifies 114-byte Sunscreen test vector ciphertext against RFC 8439 normative reference.
10. **TEST 10 — Arbitrary Round-Trip Integrity:** Round-trip test with complex ASCII characters.
11. **TEST 11 — RFC 8439 Section 2.1.1 Test Vector:** Validates 4-word Quarter Round ARX transformation.
12. **TEST 12 — RFC 8439 Section 2.3.2 Test Vector:** Validates 64-byte block function keystream generation.
13. **TEST 13 — Key Length Validation:** Asserts rejection of non-32-byte keys.
14. **TEST 14 — Nonce Length Validation:** Asserts rejection of non-12-byte nonces.
15. **TEST 15 — Hex Utilities:** Verifies hex encoder/decoder and error detection.

---

## 12. Security Considerations
1. **Never Reuse a Nonce with the Same Key:**  
   If the same $(Key, Nonce)$ pair is reused for two different messages $P_1$ and $P_2$:
   $$C_1 \oplus C_2 = (P_1 \oplus K) \oplus (P_2 \oplus K) = P_1 \oplus P_2$$
   An attacker can eliminate the key entirely and compute the XOR sum of plaintexts (Two-Time Pad attack), allowing recovery of original plaintexts via frequency analysis.
2. **Confidentiality vs Authenticity:**  
   ChaCha20 alone provides **confidentiality**, not integrity or authentication. An active adversary can modify ciphertext bits ($C'_i = C_i \oplus \Delta$), resulting in predictable modifications to the decrypted plaintext ($P'_i = P_i \oplus \Delta$) without detection (malleability).
3. **Authenticated Encryption (AEAD):**  
   In production environments, ChaCha20 must be paired with an authentication mechanism, specifically **ChaCha20-Poly1305 AEAD** (RFC 8439 Section 2.8), which computes a 128-bit Poly1305 MAC tag over the ciphertext and associated data.

---

## 13. Conclusion
The implementation strictly adheres to **RFC 8439**, correctly handling 32-bit unsigned arithmetic in Java, little-endian state mapping, the ARX quarter-round permutation, and keystream XOR operations. All automated tests and RFC 8439 test vectors pass with 100% fidelity.

---

## 14. References
* **RFC 8439:** *ChaCha20 and Poly1305 for IETF Protocols* (Y. Nir, A. Langley, June 2018). [https://www.rfc-editor.org/rfc/rfc8439](https://www.rfc-editor.org/rfc/rfc8439)
* **Daniel J. Bernstein:** *ChaCha, a variant of Salsa20* (2008). [https://cr.yp.to/chacha.html](https://cr.yp.to/chacha.html)
