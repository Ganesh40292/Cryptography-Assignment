# Test Results: ChaCha20 Stream Cipher Implementation

**Course:** BCS703 Cryptography and Network Security  
**Standard:** RFC 8439 (IETF ChaCha20 Stream Cipher)  
**Execution Environment:** Java 17+ (Java 21 / Maven 3.9 / JUnit 5)  
**Status:** **ALL TESTS PASSED (15 / 15 Passed - 100% Success Rate)**

---

## Summary Table

| Test # | Category / Description | Input Parameters | Expected Result | Actual Result | Status |
|---|---|---|---|---|:---:|
| **TC-01** | Basic Encryption & Decryption Round-Trip | Key: `000102...1f`<br>Nonce: `000000000000004a00000000`<br>Counter: `1`<br>Plaintext: `"Cryptography and Network Security: ChaCha20 Stream Cipher"` | Decrypted plaintext matches original message exactly | Exact match verified (`msg == pt`) | **PASS** |
| **TC-02** | Short Plaintext Encryption | Key: `000102...1f`<br>Nonce: `000000000000004a00000000`<br>Counter: `1`<br>Plaintext: `"Hello"` (5 bytes) | Ciphertext length == 5 bytes; Decrypted string == `"Hello"` | Length = 5; Decrypted text: `"Hello"` | **PASS** |
| **TC-03** | Empty Plaintext Handling | Key: `000102...1f`<br>Nonce: `000000000000004a00000000`<br>Counter: `1`<br>Plaintext: `byte[0]` (0 bytes) | Ciphertext is empty byte array (`byte[0]`); no exceptions | Empty `byte[0]` returned; Decrypted is `byte[0]` | **PASS** |
| **TC-04** | Multi-Block Plaintext (> 64 bytes) | Key: `000102...1f`<br>Nonce: `000000000000004a00000000`<br>Counter: `1`<br>Plaintext: 1330 bytes across 21 ChaCha20 64-byte blocks | Proper counter incrementing per block; complete plaintext recovery | Exact byte-for-byte equality across all 21 blocks | **PASS** |
| **TC-05** | Key Sensitivity (Different Keys) | Key 1: `000102...1f`<br>Key 2: `ffffff...ff`<br>Nonce: `000000000000004a00000000`<br>Plaintext: `"Confidential Data Payload"` | Ciphertext 1 $\neq$ Ciphertext 2 | `cipherA` $\neq$ `cipherB` (distinct keystreams) | **PASS** |
| **TC-06** | Determinism Test | Key: `000102...1f`<br>Nonce: `000000000000004a00000000`<br>Counter: `1`<br>Plaintext: `"Deterministic Cipher Output Verification"` | Two identical runs produce byte-for-byte identical ciphertext | `cipher1.equals(cipher2)` | **PASS** |
| **TC-07** | Nonce Sensitivity (Different Nonce) | Key: `000102...1f`<br>Nonce 1: `...4a00000000`<br>Nonce 2: `...4a00000001`<br>Plaintext: `"Nonce Uniqueness is Critical for Security"` | Ciphertext 1 $\neq$ Ciphertext 2 | `cipherA` $\neq$ `cipherB` | **PASS** |
| **TC-08** | Counter Sensitivity (Different Counter) | Key: `000102...1f`<br>Nonce: `000000000000004a00000000`<br>Counter 1: `1`<br>Counter 2: `2`<br>Plaintext: `"Block Counter Increment Test"` | Ciphertext 1 $\neq$ Ciphertext 2 | `cipher1` $\neq$ `cipher2` | **PASS** |
| **TC-09** | **Official RFC 8439 Section 2.4.2 Test Vector** | Key: `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`<br>Nonce: `000000000000004a00000000`<br>Counter: `1`<br>Plaintext: `"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."` (114 bytes) | Ciphertext hex:<br>`6e2e359a2568f98041ba0728dd0d6981`<br>`e97e7aec1d4360c20a27afccfd9fae0b`<br>`f91b65c5524733ab8f593dabcd62b357`<br>`1639d624e65152ab8f530c359f0861d8`<br>`07ca0dbf500d6a6156a38e088a22b65e`<br>`52bc514d16ccf806818ce91ab7793736`<br>`5af90bbf74a35be6b40b8eedf2785e42`<br>`874d` | Generated hex matches RFC 8439 Section 2.4.2 verbatim (114 bytes) | **PASS** |
| **TC-10** | Arbitrary Round-Trip Integrity | Key: `fedcba98...`<br>Nonce: `123456...`<br>Counter: `99`<br>Plaintext: `"The quick brown fox jumps over the lazy dog 1234567890 !@#$%^&*()"` | `decrypt(encrypt(P)) == P` | Original plaintext recovered intact | **PASS** |
| **TC-11** | **Official RFC 8439 Section 2.1.1 Quarter Round Test Vector** | $a = \text{0x11111111}$<br>$b = \text{0x01020304}$<br>$c = \text{0x9b8d6f43}$<br>$d = \text{0x01234567}$ | $a = \text{0xea2a92f4}$<br>$b = \text{0xcb1cf8ce}$<br>$c = \text{0x4581472e}$<br>$d = \text{0x5881c4bb}$ | $a = \text{0xea2a92f4}$<br>$b = \text{0xcb1cf8ce}$<br>$c = \text{0x4581472e}$<br>$d = \text{0x5881c4bb}$ | **PASS** |
| **TC-12** | **Official RFC 8439 Section 2.3.2 Block Function Test Vector** | Key: `000102...1f`<br>Nonce: `000000090000004a00000000`<br>Counter: `1` | 64-byte keystream matching RFC 8439 Section 2.3.2 | Exact 64-byte match | **PASS** |
| **TC-13** | Input Validation: Invalid Key Length | Key: 16 bytes (expected 32 bytes) or `null` | Throws `IllegalArgumentException` with descriptive message | `IllegalArgumentException` thrown and caught | **PASS** |
| **TC-14** | Input Validation: Invalid Nonce Length | Nonce: 8 bytes (expected 12 bytes) or `null` | Throws `IllegalArgumentException` with descriptive message | `IllegalArgumentException` thrown and caught | **PASS** |
| **TC-15** | Hex Conversion Utilities | Raw bytes: `{0x00, 0xFF, 0x12, 0x34}`<br>Hex strings with spaces and delimiters | Correct bidirectional parsing; Rejection of odd length and non-hex chars | Validated conversions and exception handling | **PASS** |

---

## Detailed Test Logs (Maven Surefire Test Run)

```text
-------------------------------------------------------
 T E S T S
-------------------------------------------------------
Running com.chacha20.ChaCha20Test
===============================================================
                Running ChaCha20 Test Suite                    
===============================================================
[PASS] TEST 4: Long Plaintext (1330 bytes across multiple blocks)
[PASS] TEST 3: Empty Plaintext
[PASS] TEST 12: RFC 8439 Block Function Test Vector (Section 2.3.2)
[PASS] TEST 6: Same Parameters -> Same Ciphertext
[PASS] TEST 11: RFC 8439 Quarter Round Test Vector (Section 2.1.1)
[PASS] TEST 10: Arbitrary Round-Trip Integrity
[PASS] TEST 9: RFC 8439 Official Test Vector (Section 2.4.2)
[PASS] TEST 15: HexUtils Utility Functions
[PASS] TEST 14: Invalid Nonce Length Rejection
[PASS] TEST 13: Invalid Key Length Rejection
[PASS] TEST 2: Short Plaintext
[PASS] TEST 1: Basic Encryption/Decryption
[PASS] TEST 5: Different Keys -> Different Ciphertexts
[PASS] TEST 8: Different Counter -> Different Ciphertext
[PASS] TEST 7: Different Nonce -> Different Ciphertext
Tests run: 15, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.115 s -- in com.chacha20.ChaCha20Test

Results:
Tests run: 15, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

---

## Conclusion

The implementation has passed all unit tests and official RFC 8439 normative test vectors (Quarter Round, Block Function, and Stream Encryption). The cipher exhibits exact compliance with the IETF specification.
