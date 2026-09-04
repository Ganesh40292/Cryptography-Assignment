# Implementation and Testing of ChaCha20 Stream Cipher

A manual implementation and verification of the **IETF ChaCha20 Stream Cipher (RFC 8439)** developed in **Java 17+** with zero third-party cryptographic dependencies, accompanied by an interactive web visualizer.

**Course:** BCS703 — Cryptography and Network Security (7th Semester CSE)

---

## 🔗 Repository Details

* **GitHub Repository:** [https://github.com/Ganesh40292/Cryptography-Assignment.git](https://github.com/Ganesh40292/Cryptography-Assignment.git)
* **Default Branch:** `main`
* **Clone Command:**
  ```bash
  git clone https://github.com/Ganesh40292/Cryptography-Assignment.git
  cd Cryptography-Assignment/chacha20-cipher
  ```

---

## 📁 Project Structure

```
chacha20-cipher/
├── pom.xml                                   # Maven configuration (Java 17+, JUnit 5)
├── README.md                                 # Technical documentation
├── src/
│   ├── main/java/com/chacha20/
│   │   ├── ChaCha20.java                     # RFC 8439 core cipher implementation
│   │   ├── HexUtils.java                     # Hex/byte conversion utilities
│   │   ├── InputValidator.java               # Key, nonce, and parameter validation
│   │   └── Main.java                         # Interactive CLI console menu
│   └── test/java/com/chacha20/
│       └── ChaCha20Test.java                 # 15 JUnit 5 test cases & RFC test vectors
├── test-results/
│   └── TEST-RESULTS.md                       # Test results & verification table
└── web/
    ├── index.html                            # Interactive Web Studio UI
    ├── style.css                             # Glassmorphism dark styling
    ├── chacha20.js                           # JavaScript ChaCha20 engine
    └── app.js                                # UI logic & 20-round stepper
```

---

## 🚀 How to Run

### 1. Java Console Application & Tests (CLI / NetBeans)
Navigate to the `chacha20-cipher` folder:
```bash
cd chacha20-cipher

# Run JUnit 5 test suite (15/15 tests)
mvn clean test

# Run interactive CLI application
mvn exec:java

# Or build and run standalone JAR
mvn clean package
java -jar target/chacha20-cipher-1.0.0.jar
```

### 2. Interactive Web Studio
```bash
cd chacha20-cipher
npm install
npm run dev
```
Open **[http://localhost:5173](http://localhost:5173)** in your browser (or open `web/index.html` directly).

---

## 🧪 Verification & Test Results

| Test # | Description | Standard Reference | Result |
|---|---|---|:---:|
| TC-01 | Basic Encryption / Decryption | Round-Trip Integrity | **PASS** |
| TC-02 | Short Plaintext (`"Hello"`) | Buffer edge case | **PASS** |
| TC-03 | Empty Plaintext (`0-length`) | Zero-length handling | **PASS** |
| TC-04 | Multi-Block Stream (>64 bytes) | 1330 bytes across 21 blocks | **PASS** |
| TC-05 | Key Sensitivity | Differential keystream check | **PASS** |
| TC-06 | Deterministic Cipher Output | Identical parameter consistency | **PASS** |
| TC-07 | Nonce Sensitivity | Nonce variation check | **PASS** |
| TC-08 | Counter Increment | Multi-block keystream shift | **PASS** |
| **TC-09** | **Official RFC 8439 Ciphertext Vector** | **RFC 8439 Section 2.4.2** | **PASS** |
| TC-10 | Arbitrary Round-Trip Integrity | Complex ASCII / UTF-8 | **PASS** |
| **TC-11** | **Quarter Round ARX Test Vector** | **RFC 8439 Section 2.1.1** | **PASS** |
| **TC-12** | **ChaCha20 Block Function Vector** | **RFC 8439 Section 2.3.2** | **PASS** |
| TC-13 | Invalid Key Length Rejection | 32-byte strict check | **PASS** |
| TC-14 | Invalid Nonce Length Rejection | 12-byte strict check | **PASS** |
| TC-15 | Hex Conversion Utilities | Encoder/Decoder verification | **PASS** |

---

## 📜 Reference
* **RFC 8439:** *ChaCha20 and Poly1305 for IETF Protocols* (IRTF CFRG)
