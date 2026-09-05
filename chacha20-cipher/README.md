# ChaCha20 CipherForge — Interactive ARX Cryptographic Engine & AEAD Studio

An academic, zero-dependency pure Java 17+ implementation and interactive educational visualizer for the **IETF ChaCha20 Stream Cipher**, **Poly1305 One-Time Authenticator**, and **ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD)** adhering to **RFC 8439**.

---

## 1. Project Title
**ChaCha20 CipherForge: Cryptographic Engine, Streaming File Cipher & Web Studio**  
*Course:* BCS703 — Cryptography and Network Security (Assignment 1)  
*Standard:* IETF RFC 8439 (Supercedes RFC 7539)

---

## 2. Project Objective
The primary objective of this project is to implement, test, analyze, and visually demonstrate the **ChaCha20 stream cipher** directly from its mathematical foundation in RFC 8439 without utilizing third-party cryptographic libraries (such as Bouncy Castle, Google Tink, or `javax.crypto.Cipher`).

Specific goals achieved:
1. Pure Java algorithmic realization of 32-bit unsigned ARX (Add-Rotate-Xor) operations.
2. 512-bit state matrix management and little-endian word serialization.
3. Configurable permutation rounds (ChaCha8, ChaCha12, and canonical ChaCha20).
4. Pure Java implementation of the RFC 8439 §2.5 Poly1305 128-bit MAC authenticator.
5. Construction of RFC 8439 §2.8 Authenticated Encryption with Associated Data (AEAD).
6. Constant-memory 64 KB chunked file encryption/decryption streaming engine.
7. Multi-trial empirical avalanche effect and bit-diffusion analysis.
8. Academic benchmarking suite measuring throughput and per-block latency.
9. Interactive web-based virtual laboratory for step-by-step 4x4 matrix visualization.
10. Automated verification using JUnit 5 against all authoritative RFC 8439 test vectors.

---

## 3. Features
* **Zero Cryptographic Dependencies:** Uses standard Java SE primitive operations, bit shifts, and standard JDK classes.
* **RFC 8439 Conformance:** Fully verified against RFC 8439 §2.1.1 (Quarter Round), §2.3.2 (Block Function), §2.4.2 (ChaCha20 Encryption with Sunscreen reference plaintext), §2.5.2 (Poly1305), and §2.8.2 (AEAD).
* **Configurable Round Permutations:** Supports 8, 12, and 20 rounds.
* **AEAD Authenticated Encryption:** Encrypts data while computing a 16-byte Poly1305 MAC tag over optional Additional Authenticated Data (AAD) and ciphertext. Rejects tampering before plaintext release.
* **Streaming File Cipher:** Processes large binary files within the available ChaCha20 32-bit block-counter space (PDF, images, binaries) in 64 KB buffers with constant memory consumption and built-in protection against same-path and same-file truncation.
* **Avalanche & Diffusion Analyzer:** Measures single-bit input perturbations diffusing across all 20 rounds, featuring multi-trial statistical reporting (mean, min, max, std-dev).
* **Academic Benchmark Suite:** Includes JVM JIT warmup, multi-payload measurements (64 B to 1 MB), and round-variant throughput comparisons.
* **ASCII State Tracer:** Generates printable step-by-step 4x4 matrix execution traces.
* **Interactive Web Studio:** Client-side web visualizer featuring 20-round animation stepper, live ARX formula displays, and instant RFC verification checks.

---

## 4. Architecture
The codebase is structured into cohesive components within `com.chacha20`:

```
+-------------------------------------------------------------------------+
|                               Main CLI                                  |
|   Interactive 10-Option Menu, Demonstration Runner, Benchmark Driver    |
+--------------------+---------------------+--------------------+---------+
                     |                     |                    |
                     v                     v                    v
          +--------------------+ +--------------------+ +---------------+
          | ChaCha20Poly1305   | |    FileCipher      | | Avalanche &   |
          | AEAD Engine §2.8   | | 64 KB Stream I/O   | | Benchmarking  |
          +---------+----------+ +---------+----------+ +---------------+
                    |                      |
         +----------+----------+           |
         |                     |           |
         v                     v           v
+------------------+ +--------------------------------------------------+
|     Poly1305     | |                      ChaCha20                    |
| Authenticator    | | 512-bit State, ARX Quarter Round, Block Function |
+------------------+ +--------------------------------------------------+
         |                                 |
         +----------------+----------------+
                          |
                          v
         +---------------------------------+
         |   InputValidator & HexUtils     |
         +---------------------------------+
```

---

## 5. ChaCha20 Explanation
ChaCha20 is a stream cipher designed by Daniel J. Bernstein. It generates a pseudo-random keystream by permuting an internal 512-bit (64-byte) state organized as a $4 \times 4$ matrix of 16 unsigned 32-bit words:

```
[ Constant 0 ] [ Constant 1 ] [ Constant 2 ] [ Constant 3 ]  (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
[   Key 0    ] [   Key 1    ] [   Key 2    ] [   Key 3    ]  (256-bit Key, words 0..3)
[   Key 4    ] [   Key 5    ] [   Key 6    ] [   Key 7    ]  (256-bit Key, words 4..7)
[   Counter  ] [  Nonce 0   ] [  Nonce 1   ] [  Nonce 2   ]  (32-bit Counter + 96-bit Nonce)
```

### Quarter Round (ARX):
The core permutation primitive operates on four words $(a, b, c, d)$ using Addition modulo $2^{32}$, Rotation, and XOR:
$$\begin{aligned}
a &= a + b \pmod{2^{32}}; & d &= (d \oplus a) \lll 16; \\
c &= c + d \pmod{2^{32}}; & b &= (b \oplus c) \lll 12; \\
a &= a + b \pmod{2^{32}}; & d &= (d \oplus a) \lll 8; \\
c &= c + d \pmod{2^{32}}; & b &= (b \oplus c) \lll 7;
\end{aligned}$$

### Double Rounds:
Ten double rounds (20 rounds total) alternate between:
1. **Column Rounds (Odd):** $\text{QR}(0,4,8,12)$, $\text{QR}(1,5,9,13)$, $\text{QR}(2,6,10,14)$, $\text{QR}(3,7,11,15)$
2. **Diagonal Rounds (Even):** $\text{QR}(0,5,10,15)$, $\text{QR}(1,6,11,12)$, $\text{QR}(2,7,8,13)$, $\text{QR}(3,4,9,14)$

After round 20, the working state is added word-by-word to the initial state (feed-forward addition modulo $2^{32}$) and serialized in little-endian byte order. The 64-byte keystream is then XORed with input bytes.

---

## 6. Poly1305 Explanation
Poly1305 (RFC 8439 §2.5) is a high-speed, one-time authenticator. It takes a 32-byte one-time key and an arbitrary-length message to generate a 16-byte (128-bit) tag:
1. Key is split into $(r, s)$: $r = \text{key}[0..15]$ (clamped to prevent small subgroup attacks), $s = \text{key}[16..31]$.
2. The message is divided into 16-byte blocks, each appended with an implicit $0\text{x}01$ byte.
3. Accumulator $a$ is initialized to 0 and updated for each block:
   $$a = ((a + \text{block}) \times r) \pmod{2^{130} - 5}$$
4. Final tag calculation:
   $$\text{Tag} = (a + s) \pmod{2^{128}}$$

---

## 7. AEAD Explanation
ChaCha20-Poly1305 AEAD (RFC 8439 §2.8) binds confidentiality and authenticity into a single cryptographic construction:
1. **Subkey Derivation:** ChaCha20 block function is evaluated at counter 0 with the master key and nonce. The first 32 bytes of the resulting keystream become the one-time Poly1305 key.
2. **Payload Encryption:** Plaintext is encrypted with ChaCha20 starting at counter 1.
3. **MAC Data Construction:**
   $$\text{MAC Data} = \text{AAD} \mathbin{\Vert} \text{pad}_{16}(\text{AAD}) \mathbin{\Vert} \text{Ciphertext} \mathbin{\Vert} \text{pad}_{16}(\text{Ciphertext}) \mathbin{\Vert} \text{len}(\text{AAD})_{64\text{ LE}} \mathbin{\Vert} \text{len}(\text{Ciphertext})_{64\text{ LE}}$$
4. **Tag Verification:** During decryption, the MAC tag is computed over the received ciphertext and AAD. Decryption is performed and plaintext released **only after** constant-time tag verification succeeds. Any bit modification in ciphertext or AAD raises a `SecurityException`.

---

## 8. File Encryption Explanation
The `FileCipher` class provides high-throughput streaming encryption and decryption for files within the available ChaCha20 block-counter space:
* **Constant Memory Footprint:** Reads and writes using a 64 KB buffer, enabling files larger than available RAM to be processed seamlessly.
* **Block Counter Synchronization:** Accurately increments the ChaCha20 counter across 64-byte block boundaries within each 64 KB buffer chunk.
* **Collision Protection:** Validates canonical paths and filesystem identity (`Files.isSameFile`) before processing. Attempting to specify the same file as both input and output throws `IllegalArgumentException("Input and output files must be different.")`, preventing destructive file truncation.
* **Confidentiality vs Integrity:** Encrypts using raw ChaCha20. Users must note that raw ciphertext files do not contain authentication tags or headers; callers must preserve the key, nonce, and counter for decryption.

---

## 9. Avalanche Analysis Explanation
The `AvalancheAnalyzer` class empirically tests diffusion by flipping a single bit in the 512-bit input (Key, Nonce, or Counter) and tracking the Hamming distance across rounds 1 to 20:
* **Scientific Clarification:** A single experiment does not mathematically "prove" the Strict Avalanche Criterion (SAC), as SAC is a statistical property requiring that every output bit changes with a probability of $0.5$ across all input perturbations.
* **Diffusion Progression:** Single-trial analysis demonstrates that observed bit diffusion rapidly approaches the expected ~50% state-bit change behavior after repeated rounds.
* **Multi-Trial Evaluation:** The `runMultiTrialAnalysis(trials)` method aggregates 32 independent bit-flip trials across different positions, reporting mean Hamming distance, min, max, and standard deviation (observed mean: $\approx 255.6 / 512$ bits, or $49.91\%$, $\sigma \approx 11.5$ bits).

---

## 10. Benchmark Explanation
The `BenchmarkRunner` provides an academic performance comparison across algorithms, payload sizes, and round counts:
* Precedes measurements with a JIT compiler warm-up phase (1,000 iterations).
* Measures throughput in MB/s and per-block latency in nanoseconds across payloads from 64 bytes to 1 megabyte.
* Evaluates performance tradeoffs between ChaCha8, ChaCha12, and ChaCha20.
* Note: This benchmark serves educational and comparative analysis purposes within standard JVM execution and is not intended as an industry-standard JMH microbenchmark.

---

## 11. State Visualizer Explanation
* **Java Console StateTracer:** Provides an ASCII matrix dump of the 512-bit state at Initialization, Round 1 (Column), Round 2 (Diagonal), Round 20, and Final Keystream.
* **Interactive Web Studio (`web/`):** A client-side virtual laboratory implemented in HTML5, Vanilla CSS, and JavaScript. Features interactive 4x4 matrix heatmaps, animated ARX quarter-round steppers, payload encryption, and automated browser-side RFC 8439 vector verification.

---

## 12. Project Structure

```
chacha20-cipher/
├── pom.xml                                   # Maven configuration (Java 17+, JUnit 5)
├── README.md                                 # Complete technical documentation
├── .gitignore                                # Excludes target/, node_modules/, dist/, .vite/
├── src/
│   ├── main/java/com/chacha20/
│   │   ├── ChaCha20.java                     # RFC 8439 core cipher & round variants (8/12/20)
│   │   ├── Poly1305.java                     # RFC 8439 §2.5 Poly1305 128-bit MAC authenticator
│   │   ├── ChaCha20Poly1305.java             # RFC 8439 §2.8 AEAD authenticated encryption
│   │   ├── FileCipher.java                   # 64 KB buffered streaming file cipher & collision check
│   │   ├── AvalancheAnalyzer.java            # Bit-diffusion & multi-trial statistical analyzer
│   │   ├── BenchmarkRunner.java              # Academic throughput & latency benchmark suite
│   │   ├── StateTracer.java                  # ASCII 4x4 state matrix execution tracer
│   │   ├── HexUtils.java                     # Hex/byte conversion, delimiter sanitizing, wiping
│   │   ├── InputValidator.java               # Strict key, nonce, counter, tag validation
│   │   └── Main.java                         # Interactive 10-option CLI console menu
│   └── test/java/com/chacha20/
│       ├── ChaCha20Test.java                 # 20 tests (RFC vectors, Unicode, tampering demo, rounds, index checks)
│       ├── Poly1305Test.java                 # 3 tests (RFC §2.5.2 vector, empty msg, constant-time)
│       ├── ChaCha20Poly1305Test.java         # 9 tests (RFC §2.8.2 AEAD, tampering, wrong key/nonce/AAD)
│       └── FileCipherTest.java               # 4 tests (same-path rejection, 12 edge sizes, 1MB stream)
├── test-results/
│   └── TEST-RESULTS.md                       # Comprehensive 36-test verification report & Maven logs
└── web/
    ├── index.html                            # Interactive Web Studio UI & RFC verification badge
    ├── style.css                             # Glassmorphism dark aesthetic design system
    ├── chacha20.js                           # Client-side educational RFC 8439 ChaCha20 engine
    ├── app.js                                # Interactive visualizer logic & test metrics source
    └── package.json                          # Vite development server configuration
```

---

## 13. Requirements
* **Java Development Kit (JDK):** Version 17 or higher (tested on JDK 17 and JDK 21).
* **Build Tool:** Apache Maven 3.8+ (or IDE-bundled Maven in IntelliJ/NetBeans/Eclipse).
* **Web Visualizer (Optional):** Any modern browser (Chrome, Edge, Firefox, Safari); Node.js 18+ for `npm run dev`.

---

## 14. How to Compile
From the `chacha20-cipher` directory:
```bash
# Clean previous build artifacts and compile all production classes
mvn clean compile
```

---

## 15. How to Run

### Interactive Console CLI (Option Menu)
```bash
# Option A: Execute directly via Maven
mvn exec:java -Dexec.mainClass="com.chacha20.Main"

# Option B: Package and execute standalone JAR
mvn package
java -jar target/chacha20-cipher-1.0.0.jar
```

The CLI provides 10 interactive options:
1. Encrypt Text (ChaCha20, ChaCha8, ChaCha12)
2. Decrypt Hex Ciphertext
3. AEAD Encrypt & Tag (ChaCha20-Poly1305 with AAD)
4. AEAD Decrypt & Verify Tag (ChaCha20-Poly1305)
5. File Encryption & Decryption (Buffered Stream I/O)
6. Avalanche Effect & Bit-Diffusion Analysis
7. Performance & Throughput Benchmarking Suite
8. Step-by-Step State Matrix Execution Trace
9. Built-in RFC 8439 Verification Demonstration
10. Exit

---

## 16. How to Run Tests
Execute the complete JUnit 5 regression test suite:
```bash
mvn clean test
```

---

## 17. How to Run Web Visualizer & 3D ARX Studio

The web studio includes a client-side RFC 8439 engine, interactive 20-round 4×4 state matrix debugger, and a **Holographic 3D ARX Cryptographic Reactor Forge** (Three.js + GSAP):
* **Automatic 3D Intro**: Launches automatically on page load/refresh with counter-rotating ARX rings, 16-word orbital matrix convergence, and shockwave lattice flash.
* **Instant Bypass**: Hit `[ESC]` or click `ENTER FORGE [ESC]` for immediate skip into the application.
* **Lighthouse 13.4.1 Results**: 100/100 Accessibility, 100/100 Best Practices, 100/100 SEO, 3/3 Agentic Browsing, and vendor code-splitting optimization.

```bash
cd web

# Install dependencies (Three.js, GSAP, Vite)
npm install

# Run local development server
npm run dev

# Build production bundle with vendor chunking
npm run build

# Preview production build locally
npm run preview
```
Open **`http://localhost:5180`** in your browser. Alternatively, `index.html` can be loaded directly in any modern browser.

---

## 18. RFC Verification
The project verifies all normative test vectors published in **RFC 8439**:
1. **Quarter Round (§2.1.1):** Validates the 4-word ARX primitive on test vector `(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567)`.
2. **Block Function (§2.3.2):** Validates the complete 64-byte keystream generated from key `000102...1f`, counter `1`, and nonce `000000090000004a00000000`.
3. **ChaCha20 Encryption (§2.4.2):** Validates encryption of the complete 114-byte RFC Sunscreen quote matching ciphertext hex `6e2e359a...`.
4. **Poly1305 Authenticator (§2.5.2):** Validates complete 16-byte MAC tag `a8061dc1305136c6c22b8baf0c0127a9` for `"Cryptographic Forum Research Group"`.
5. **ChaCha20-Poly1305 AEAD (§2.8.2):** Validates complete authenticated ciphertext and 16-byte tag `1ae10b594f09e26a7e902ecbd0600691` with AAD `50515253c0c1c2c3c4c5c6c7`.

---

## 19. Security Considerations
* **Nonce Reuse Vulnerability:** ChaCha20 is a stream cipher. Never reuse a nonce with the same key. Keystream reuse allows trivial XOR subtraction of ciphertexts ($C_1 \oplus C_2 = P_1 \oplus P_2$), destroying confidentiality.
* **Unauthenticated Stream Cipher Warning:** Raw ChaCha20 provides confidentiality but **not** integrity or authentication. Bit flips in raw ciphertext propagate directly into decrypted plaintext without error (empirically demonstrated in `TC-18`).
* **Authenticated Encryption (AEAD):** For secure network communications or storage, always use `ChaCha20Poly1305`, which authenticates ciphertext and AAD before releasing decrypted data.
* **Side-Channel & BigInteger Disclosures:** While ChaCha20 uses ARX operations without secret-dependent lookup tables (mitigating cache-timing attacks), our educational Poly1305 implementation relies on `java.math.BigInteger` for modular arithmetic modulo $2^{130} - 5$. Java's BigInteger does not provide formal constant-time guarantees. Tag equality checking in `Poly1305.verify()` is implemented in constant time to eliminate early-abort timing leakage.
* **Academic Scope:** This codebase is developed for academic study and virtual laboratory demonstration. It is not hardened against fault injection, physical side channels, or kernel-level memory dumps.
* **Key Management:** Generation, storage, rotation, and zeroization of cryptographic keys outside of memory arrays are outside the scope of this implementation.

---

## 20. Known Limitations
1. **Raw File Format:** `FileCipher` produces raw ciphertext without embedded metadata headers. The caller must securely store and supply the corresponding key, nonce, and initial counter for decryption.
2. **Single-threaded Streaming:** File encryption uses synchronous buffered streaming on a single thread. While achieving high throughput in pure Java, it does not leverage multi-threaded block pipelining.
3. **Frontend / Java Separation:** The browser virtual laboratory uses a client-side JavaScript engine to enable offline animation and interactive exploration without a live Java server. Both engines are independently validated against identical RFC 8439 vectors.

---

## 21. Testing Summary
The automated test suite in `src/test/java/com/chacha20/` contains **36 tests** across 4 test classes:

* `ChaCha20Test`: 20 tests
* `ChaCha20Poly1305Test`: 9 tests
* `FileCipherTest`: 4 tests
* `Poly1305Test`: 3 tests

```text
======================================================
TOTAL TESTS: 36 | PASSED: 36 | FAILED: 0 | SKIPPED: 0
SUCCESS RATE: 100.0%
======================================================
```
All tests pass cleanly. Full logs and parameter breakdowns are documented in [`test-results/TEST-RESULTS.md`](test-results/TEST-RESULTS.md).
