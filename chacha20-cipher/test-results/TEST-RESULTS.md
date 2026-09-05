# Test Results: ChaCha20 Stream Cipher & AEAD Implementation

**Course:** BCS703 Cryptography and Network Security  
**Standard:** RFC 8439 (IETF ChaCha20 Stream Cipher & Poly1305 AEAD)  
**Execution Environment:** Java 17+ (JDK 21 / Maven 3.9 / JUnit 5)  
**Status:** **ALL TESTS PASSED (36 / 36 Passed - 100% Success Rate across 4 Test Suites)**

---

## 📊 Summary Table of Test Cases (36 Tests)

| Test # | Class / Suite | Category / Description | Input Parameters | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|:---:|
| **TC-01** | `ChaCha20Test` | Basic Encryption & Decryption Round-Trip | Key: `000102...1f`<br>Nonce: `000000000000004a00000000`<br>Counter: `1`<br>Plaintext: `"Cryptography and Network Security..."` | Decrypted plaintext matches original message exactly | Exact match verified (`msg == pt`) | **PASS** |
| **TC-02** | `ChaCha20Test` | Short Plaintext Encryption | Key: `000102...1f`<br>Nonce: `000000000000004a00000000`<br>Counter: `1`<br>Plaintext: `"Hello"` (5 bytes) | Ciphertext length == 5 bytes; Decrypted string == `"Hello"` | Length = 5; Decrypted text: `"Hello"` | **PASS** |
| **TC-03** | `ChaCha20Test` | Empty Plaintext Handling | Key: `000102...1f`<br>Nonce: `000000000000004a00000000`<br>Counter: `1`<br>Plaintext: `byte[0]` (0 bytes) | Ciphertext is empty byte array (`byte[0]`); no exceptions | Empty `byte[0]` returned; Decrypted is `byte[0]` | **PASS** |
| **TC-04** | `ChaCha20Test` | Multi-Block Plaintext (> 64 bytes) | Key: `000102...1f`<br>Nonce: `000000000000004a00000000`<br>Counter: `1`<br>Plaintext: 1330 bytes across 21 ChaCha20 64-byte blocks | Proper counter incrementing per block; complete plaintext recovery | Exact byte-for-byte equality across all 21 blocks | **PASS** |
| **TC-05** | `ChaCha20Test` | Key Sensitivity (Different Keys) | Key 1: `000102...1f`<br>Key 2: `111111...11`<br>Nonce: `000000000000004a00000000`<br>Plaintext: `"Confidential Data Payload"` | Ciphertext 1 $\neq$ Ciphertext 2 | `cipherA` $\neq$ `cipherB` (distinct keystreams) | **PASS** |
| **TC-06** | `ChaCha20Test` | Determinism Test | Key: `000102...1f`<br>Nonce: `000000000000004a00000000`<br>Counter: `1`<br>Plaintext: `"Deterministic Cipher Output Verification"` | Two identical runs produce byte-for-byte identical ciphertext | `cipher1.equals(cipher2)` | **PASS** |
| **TC-07** | `ChaCha20Test` | Nonce Sensitivity (Different Nonce) | Key: `000102...1f`<br>Nonce 1: `...4a00000000`<br>Nonce 2: `...4a00000001`<br>Plaintext: `"Nonce Uniqueness is Critical for Security"` | Ciphertext 1 $\neq$ Ciphertext 2 | `cipherA` $\neq$ `cipherB` | **PASS** |
| **TC-08** | `ChaCha20Test` | Counter Sensitivity (Different Counter) | Key: `000102...1f`<br>Nonce: `000000000000004a00000000`<br>Counter 1: `1`<br>Counter 2: `2`<br>Plaintext: `"Block Counter Increment Test"` | Ciphertext 1 $\neq$ Ciphertext 2 | `cipher1` $\neq$ `cipher2` | **PASS** |
| **TC-09** | `ChaCha20Test` | **Official RFC 8439 §2.4.2 Test Vector** | Key: `000102...1f`<br>Nonce: `000000000000004a00000000`<br>Counter: `1`<br>Plaintext: Sunscreen quote (114 bytes) | Matches RFC 8439 Section 2.4.2 ciphertext verbatim | Matches RFC 8439 Section 2.4.2 verbatim (114 bytes) | **PASS** |
| **TC-10** | `ChaCha20Test` | Arbitrary Round-Trip Integrity | Key: `fedcba98...`<br>Nonce: `123456...`<br>Counter: `99`<br>Plaintext: `"The quick brown fox jumps..."` | `decrypt(encrypt(P)) == P` | Original plaintext recovered intact | **PASS** |
| **TC-11** | `ChaCha20Test` | **Official RFC 8439 §2.1.1 Quarter Round Vector** | $a = \text{0x11111111}, b = \text{0x01020304}, c = \text{0x9b8d6f43}, d = \text{0x01234567}$ | $a = \text{0xea2a92f4}, b = \text{0xcb1cf8ce}, c = \text{0x4581472e}, d = \text{0x5881c4bb}$ | Matches RFC 8439 §2.1.1 output words exactly | **PASS** |
| **TC-12** | `ChaCha20Test` | **Official RFC 8439 §2.3.2 Block Function Vector** | Key: `000102...1f`<br>Nonce: `000000090000004a00000000`<br>Counter: `1` | 64-byte keystream matching RFC 8439 Section 2.3.2 | Exact 64-byte match | **PASS** |
| **TC-13** | `ChaCha20Test` | Input Validation: Invalid Key Lengths | Null, 0, 1, 16, 31, 33 bytes (valid: 32 bytes) | Throws `IllegalArgumentException` | All invalid lengths rejected | **PASS** |
| **TC-14** | `ChaCha20Test` | Input Validation: Invalid Nonce Lengths | Null, 0, 8, 11, 13 bytes (valid: 12 bytes) | Throws `IllegalArgumentException` | All invalid lengths rejected | **PASS** |
| **TC-15** | `ChaCha20Test` | HexUtils Utility & Edge Cases | Uppercase, lowercase, mixed-case, spaces, delimiters, odd length, invalid chars | Robust hex parsing, strict odd/invalid detection | All conversions and exceptions verified | **PASS** |
| **TC-16** | `ChaCha20Test` | Configurable Rounds (ChaCha8 & ChaCha12) | Plaintext: `"Testing reduced round variants..."` | Distinct ciphertexts per round; complete round-trip recovery | Verified round-trip for 8, 12, 20 rounds | **PASS** |
| **TC-17** | `ChaCha20Test` | Unicode, Multilingual UTF-8 & Emoji Round-Trip | `"Hello नमस्ते 🔐! Cryptography বাংলা தமிழ் 🚀"` | Decrypted plaintext equals original UTF-8 string | Exact string equality verified | **PASS** |
| **TC-18** | `ChaCha20Test` | Educational Demo: Raw ChaCha20 Tampering | 1 bit flipped in ciphertext | Plaintext modified without error (shows lack of MAC) | Bit alteration verified, documents need for AEAD | **PASS** |
| **TC-19** | `ChaCha20Test` | Counter Validation & Boundary Checks | -1, 0, 1, 0xFFFFFFFF, 0x100000000L | Rejects negative & out-of-range (> 32-bit unsigned) | Boundary conditions verified | **PASS** |
| **TC-20** | `ChaCha20Test` | AvalancheAnalyzer Parameter Index Validation | Invalid key/nonce byte index, invalid bit index, null target | Rejects out-of-bounds indices with explicit `IllegalArgumentException` | All bounds verified without silent wrapping | **PASS** |
| **TC-21** | `Poly1305Test` | **Official RFC 8439 §2.5.2 Poly1305 Test Vector** | Key: `85d6be78...`<br>Message: `"Cryptographic Forum Research Group"` | Tag: `a8061dc1305136c6c22b8baf0c0127a9` | Exact 16-byte MAC match | **PASS** |
| **TC-22** | `Poly1305Test` | Empty Message MAC | Key: 32 bytes, Message: 0 bytes | 16-byte valid tag computed | Verified | **PASS** |
| **TC-23** | `Poly1305Test` | Constant-Time Tag Verification & Tamper Detection | Modifying 1 bit of Tag | Expected tag matches; Corrupted tag rejected | Constant-time verify passes | **PASS** |
| **TC-24** | `ChaCha20Poly1305Test` | **Official RFC 8439 §2.8.2 AEAD Test Vector** | Key: `808182...9f`<br>Nonce: `070000004041424344454647`<br>AAD: `50515253c0c1c2c3c4c5c6c7`<br>Plaintext: Sunscreen quote (114 bytes) | Ciphertext: `d31a8d...6116`<br>Tag: `1ae10b594f09e26a7e902ecbd0600691` | Ciphertext and 16-byte MAC Tag match RFC 8439 §2.8.2 verbatim | **PASS** |
| **TC-25** | `ChaCha20Poly1305Test` | AEAD Tampered Ciphertext Rejection | Flip 1 bit in ciphertext | Throws `SecurityException` during authentication | `SecurityException` thrown and caught | **PASS** |
| **TC-26** | `ChaCha20Poly1305Test` | AEAD Tampered AAD Header Rejection | Alter Associated Data string | Throws `SecurityException` during authentication | `SecurityException` thrown and caught | **PASS** |
| **TC-27** | `ChaCha20Poly1305Test` | AEAD Decryption with Wrong Key Rejection | Encrypt with Key A, decrypt with Key B | Throws `SecurityException` during authentication | `SecurityException` thrown and caught | **PASS** |
| **TC-28** | `ChaCha20Poly1305Test` | AEAD Decryption with Wrong Nonce Rejection | Encrypt with Nonce A, decrypt with Nonce B | Throws `SecurityException` during authentication | `SecurityException` thrown and caught | **PASS** |
| **TC-29** | `ChaCha20Poly1305Test` | Tampered Authentication Tag Rejection | Flip 1 bit in 16-byte Poly1305 tag | Throws `SecurityException` before plaintext release | `SecurityException` thrown and caught | **PASS** |
| **TC-30** | `ChaCha20Poly1305Test` | Empty Plaintext with and without AAD | Empty plaintext payload (`byte[0]`) | 0-byte ciphertext, valid 16-byte tag, clean recovery | Verified with and without AAD | **PASS** |
| **TC-31** | `ChaCha20Poly1305Test` | Empty AAD with Normal Plaintext Round-Trip | `byte[0]` AAD with non-empty payload | Clean encryption and authentic recovery | Verified | **PASS** |
| **TC-32** | `ChaCha20Poly1305Test` | Invalid Tag Validations | Null, 0, 15, 17-byte tags | Throws `IllegalArgumentException` | All invalid lengths rejected | **PASS** |
| **TC-33** | `FileCipherTest` | Large Multi-Chunk Buffered File Round-Trip | 250 KB random binary data file across multiple 64 KB buffers | Output file matches input file byte-for-byte | Byte-for-byte binary equality verified | **PASS** |
| **TC-34** | `FileCipherTest` | Same Input and Output File Path Collision Rejection | Input path equals output path (`input == output`), canonical & `Files.isSameFile` | Throws `IllegalArgumentException("Input and output files must be different.")` | Truncation bug prevented; exception thrown | **PASS** |
| **TC-35** | `FileCipherTest` | File Size Edge Cases | 0, 1, 2, 63, 64, 65, 127, 128, 129, 65535, 65536, 65537 bytes | Byte-for-byte exact round-trip across all boundary sizes | All 12 boundary sizes passed | **PASS** |
| **TC-36** | `FileCipherTest` | Large 1MB Random Binary Streaming Round-Trip | 1 MB random binary file across sixteen 64 KB buffers | Output matches input byte-for-byte | 1 MB exact round-trip verified | **PASS** |

---

## 🧪 Detailed Test Logs (Maven Surefire Test Run)

```text
[INFO] -------------------------------------------------------
[INFO]  T E S T S
[INFO] -------------------------------------------------------
[INFO] Running com.chacha20.ChaCha20Poly1305Test
[INFO] Tests run: 9, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.083 s -- in com.chacha20.ChaCha20Poly1305Test
[INFO] Running com.chacha20.ChaCha20Test
===============================================================
                Running ChaCha20 Test Suite                    
===============================================================
[PASS] TEST 4: Long Plaintext (1330 bytes across multiple blocks)
[PASS] TEST 3: Empty Plaintext
[PASS] TEST 17: Unicode, Multilingual UTF-8 & Emoji Round-Trip
[PASS] TEST 20: AvalancheAnalyzer Parameter Index Validation
[PASS] TEST 12: RFC 8439 Block Function Test Vector (Section 2.3.2)
[PASS] TEST 6: Same Parameters -> Same Ciphertext
[PASS] TEST 11: RFC 8439 Quarter Round Test Vector (Section 2.1.1)
[PASS] TEST 10: Arbitrary Round-Trip Integrity
[PASS] TEST 9: RFC 8439 Official Test Vector (Section 2.4.2)
[PASS] TEST 15: HexUtils Utility Functions and Edge Cases
[PASS] TEST 14: Invalid Nonce Length Rejection
[PASS] TEST 18: Educational Demo - Raw ChaCha20 Tampering
[PASS] TEST 13: Invalid Key Length Rejection
[PASS] TEST 2: Short Plaintext
[PASS] TEST 16: Configurable Rounds (ChaCha8 & ChaCha12)
[PASS] TEST 1: Basic Encryption/Decryption
[PASS] TEST 5: Different Keys -> Different Ciphertexts
[PASS] TEST 8: Different Counter -> Different Ciphertext
[PASS] TEST 19: Counter Validation
[PASS] TEST 7: Different Nonce -> Different Ciphertext
[INFO] Tests run: 20, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.067 s -- in com.chacha20.ChaCha20Test
[INFO] Running com.chacha20.FileCipherTest
[INFO] Tests run: 4, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.329 s -- in com.chacha20.FileCipherTest
[INFO] Running com.chacha20.Poly1305Test
[INFO] Tests run: 3, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.006 s -- in com.chacha20.Poly1305Test
[INFO] 
[INFO] Results:
[INFO] 
[INFO] Tests run: 36, Failures: 0, Errors: 0, Skipped: 0
[INFO] 
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
```

---

## 🎯 Conclusion

The implementation passes all **36 unit tests** and official **RFC 8439 normative test vectors** across:
1. ChaCha20 Stream Cipher Core
2. Poly1305 Authenticator
3. ChaCha20-Poly1305 AEAD Construction
4. Buffered Stream File Processing Engine
