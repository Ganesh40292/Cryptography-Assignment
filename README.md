# ChaCha20 CipherForge — Interactive ARX Cryptographic Engine & AEAD Studio

[![RFC 8439](https://img.shields.io/badge/RFC-8439%20Compliant-blue.svg)](https://www.rfc-editor.org/rfc/rfc8439)
[![Java 17+](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://www.oracle.com/java/)
[![JUnit 5](https://img.shields.io/badge/JUnit-36%20%2F%2036%20Pass-brightgreen.svg)](chacha20-cipher/test-results/TEST-RESULTS.md)
[![Lighthouse](https://img.shields.io/badge/Lighthouse-100%20%7C%20100%20%7C%20100%20%7C%20100-success.svg)](#-lighthouse-1341-audit-results)
[![License: Academic](https://img.shields.io/badge/License-Academic%20MIT-lightgrey.svg)](LICENSE)

An academic, production-grade, zero-dependency implementation of the **IETF ChaCha20 Stream Cipher**, **Poly1305 One-Time Authenticator**, and **ChaCha20-Poly1305 AEAD (RFC 8439)** developed in pure **Java 17+**, paired with a **3D Web Studio & Virtual Cryptographic Laboratory** built in Three.js and GSAP.

* **Course:** BCS703 — Cryptography and Network Security
* **Standard:** IETF RFC 8439 (*ChaCha20 and Poly1305 for IETF Protocols*)
* **Full Java Technical Specification:** See [`chacha20-cipher/README.md`](chacha20-cipher/README.md)
* **Comprehensive Test Log:** See [`chacha20-cipher/test-results/TEST-RESULTS.md`](chacha20-cipher/test-results/TEST-RESULTS.md)

---

## 🔗 Repository Details

* **GitHub Repository:** [https://github.com/Ganesh40292/Cryptography-Assignment.git](https://github.com/Ganesh40292/Cryptography-Assignment.git)
* **Default Branch:** `main`
* **Clone Command:**
  ```bash
  git clone https://github.com/Ganesh40292/Cryptography-Assignment.git
  cd Cryptography-Assignment
  ```

---

## 🏗️ System Architecture: Dual-Core Architecture

This project consists of two complementary layers that together form a complete cryptographic laboratory:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        CHACHA20 CIPHERFORGE REPOSITORY                                 │
├───────────────────────────────────────────┬────────────────────────────────────────────┤
│         JAVA 17+ CRYPTOGRAPHIC CORE       │         INTERACTIVE 3D WEB STUDIO          │
│               (Backend / CLI)             │                (Frontend)                  │
├───────────────────────────────────────────┼────────────────────────────────────────────┤
│ • Pure Java RFC 8439 Stream Cipher        │ • Pure JavaScript RFC 8439 Engine          │
│ • Poly1305 128-bit MAC Authenticator      │ • 3D Holographic ARX Reactor Forge         │
│ • ChaCha20-Poly1305 AEAD Pipeline (§2.8)  │ • 20-Round Interactive Step-by-Step Debug  │
│ • 64 KB Buffered Streaming File Cipher    │ • 4×4 512-Bit Matrix Live Permutation      │
│ • Multi-Trial Avalanche Diffusion Analyzer│ • Live Bit-Exact RFC Test Vector Probes   │
│ • Academic JVM Benchmark Suite (MB/s)     │ • Zero Blocking Initial Paint (Lighthouse) │
│ • 36-Test Automated JUnit 5 Suite         │ • Reduced-Motion & Accessibility Tree      │
└───────────────────────────────────────────┴────────────────────────────────────────────┘
```

---

## ⚡ 3D Holographic ARX Cryptographic Reactor Forge

The web studio features a 3D entrance animation sequence that visualizes the internal mechanics of ChaCha20:

1. **Automatic Initialization**: Triggers automatically on page load and refresh with seamless handover into the ambient background. Instant bypass available at any time via `[ESC]` or the `ENTER FORGE [ESC]` button.
2. **Concentric Counter-Rotating ARX Rings**:
   - Three glowing holographic Torus rings represent the fundamental operations of the quarter-round function:
     - **Addition [A]**: Outer Amber Gold ring (`#fbbf24`) rotating on the Z-axis.
     - **Rotation [R]**: Mid Electric Violet ring (`#a78bfa`) counter-rotating on the X-axis.
     - **XOR [X]**: Inner Cyber Cyan ring (`#22d3ee`) spinning on the Y-axis.
3. **512-Bit Matrix 3D Orbital Convergence**:
   - All 16 32-bit state words stream in along 3D orbital trajectories and lock into the canonical 4×4 state grid:
     - **Row 0**: 4 Constant words (`expand 32-byte k` in amber)
     - **Rows 1–2**: 8 Key words (256-bit secret key in blue/indigo)
     - **Row 3**: 32-bit Counter and 96-bit Nonce (cyber cyan)
4. **ARX 20-Round Shockwave & Lattice Flash**:
   - Expanding shockwave ring triggers as words lock into place.
   - Interconnecting cyan lattice lines illuminate all quarter-round column and diagonal dependencies.
   - 4×4 matrix tilts into a dynamic 3D isometric perspective.
5. **Futuristic Command Typography**:
   - Badge: `● ARX QUANTUM ENGINE · 512-BIT STATE REACTOR`
   - Title: `CHACHA 2.0 CIPHERFORGE` with electric cyan-to-violet holographic gradient
   - Subtitle: `Next-Gen High-Speed Stream Cipher · 256-Bit Fortress Security`
   - Stream Pill: `ARX PIPELINE: ⊞ ADD (mod 2³²) · ⋘ ROTATE · ⨁ XOR ┃ 20 ROUNDS ARMED`
6. **Ambient Interactive Space**:
   - After the entrance sequence, the matrix transitions into the deep-space particle backdrop behind the glass panels with subtle mouse parallax drift and floating hexadecimal glyphs.
   - Can be replayed at any time via the `↻ REPLAY 3D` button in the header.

---

## 🏆 Google Lighthouse 13.4.1 Audit Results

The web studio has undergone extensive performance, accessibility, SEO, and agentic browsing optimization:

| Category | Baseline Score | Final Score | Status | Key Enhancements |
|:---|:---:|:---:|:---:|:---|
| **Accessibility** | 95 / 100 | **100 / 100** | **PERFECT** | High-contrast WCAG AAA palettes, complete ARIA roles, valid `progressbar` bounds, zero accessibility tree violations. |
| **Best Practices** | 100 / 100 | **100 / 100** | **PERFECT** | Zero console errors/warnings, source maps enabled, security headers configured (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`). |
| **SEO** | 91 / 100 | **100 / 100** | **PERFECT** | Valid `robots.txt`, descriptive meta tags, OpenGraph protocol, single `h1` structure. |
| **Agentic Browsing** | 1 / 3 | **3 / 3 (100%)** | **PERFECT** | Machine-readable `/llms.txt` standard specification with Markdown links and structured API outline. |
| **Performance** | 56 / 100 | **80–90+ / 100** | **OPTIMIZED** | Vendor code-splitting (Three.js and GSAP split into independent cacheable chunks), critical bundle reduced by >90% (2.49 MB → 246 KiB), non-blocking initial paint. |

---

## 🧪 Comprehensive Verification & Test Suite (36 / 36 PASS)

Every component is verified through an automated JUnit 5 regression test suite and browser runtime probes:

| Suite | Class | Tests | Status | Verification Scope |
|:---|:---|:---:|:---:|:---|
| **ChaCha20 Core** | `ChaCha20Test` | **20** | **PASS** | RFC 8439 §2.1.1 (Quarter-Round), §2.3.2 (Block Function), §2.4.2 (Sunscreen Vector), ChaCha8 / ChaCha12 / ChaCha20 round variants, Unicode/UTF-8 multilingual & emoji round-trip, unauthenticated tampering demonstration, key/nonce length bounds, counter bounds. |
| **Poly1305 MAC** | `Poly1305Test` | **3** | **PASS** | Official RFC 8439 §2.5.2 test vector, empty message authentication, constant-time tag comparison. |
| **AEAD Authenticator** | `ChaCha20Poly1305Test` | **9** | **PASS** | RFC 8439 §2.8.2 AEAD vector, tampered ciphertext rejection, tampered AAD rejection, wrong key/nonce rejection, invalid tag rejection, empty payload with/without AAD. |
| **Streaming File I/O** | `FileCipherTest` | **4** | **PASS** | Same-path input/output collision protection, 12 file size boundary edge cases (0 B to 65,537 B), multi-chunk 250 KB and 1 MB large binary streaming. |
| **TOTAL** | | **36** | **36 / 36 PASS (100%)** | **Zero failures, zero errors, zero skipped.** |

---

## 📁 Repository Structure

```
Cryptography-Assignment/
├── README.md                                 # Root repository overview & documentation
├── .gitignore                                # Excludes target/, node_modules/, dist/, .vite/
├── chacha20-cipher/
│   ├── pom.xml                               # Maven build configuration (Java 17+, JUnit 5)
│   ├── README.md                             # 21-section technical specification & algorithmic analysis
│   ├── test-results/
│   │   └── TEST-RESULTS.md                   # Full 36-test execution logs and parameters
│   ├── src/
│   │   ├── main/java/com/chacha20/
│   │   │   ├── ChaCha20.java                 # RFC 8439 core cipher (Quarter-Round, Block, Rounds 8/12/20)
│   │   │   ├── Poly1305.java                 # RFC 8439 §2.5 128-bit MAC authenticator
│   │   │   ├── ChaCha20Poly1305.java         # RFC 8439 §2.8 AEAD construction with AAD
│   │   │   ├── FileCipher.java               # 64 KB buffered streaming file cipher & collision safety
│   │   │   ├── AvalancheAnalyzer.java        # Multi-trial statistical bit-diffusion analyzer
│   │   │   ├── BenchmarkRunner.java          # JVM throughput (MB/s) and latency profiler
│   │   │   ├── StateTracer.java              # Step-by-step 4×4 matrix ASCII visualizer
│   │   │   ├── HexUtils.java                 # Hex conversion, byte sanitation, delimiter stripping
│   │   │   ├── InputValidator.java           # Strict key, nonce, counter, tag validation
│   │   │   └── Main.java                     # Interactive 10-option CLI console application
│   │   └── test/java/com/chacha20/
│   │       ├── ChaCha20Test.java             # 20 tests (RFC vectors, Unicode, tampering, rounds)
│   │       ├── Poly1305Test.java             # 3 tests (RFC §2.5.2 vector, empty msg, constant-time)
│   │       ├── ChaCha20Poly1305Test.java     # 9 tests (RFC §2.8.2 AEAD, tampering, wrong key/AAD)
│   │       └── FileCipherTest.java           # 4 tests (same-path rejection, boundary sizes, 1 MB streaming)
│   └── web/
│       ├── index.html                        # Web Studio UI & semantic layout
│       ├── style.css                         # Dark glassmorphism styling & animations
│       ├── chacha20.js                       # Pure client-side JavaScript ChaCha20 engine
│       ├── scene.js                          # Three.js + GSAP 3D ARX Reactor Forge & particle field
│       ├── app.js                            # UI state, 20-round stepper, and RFC probes
│       ├── vite.config.js                    # Vite bundler configuration & code-splitting
│       ├── package.json                      # Web project dependencies (Three.js, GSAP, Vite)
│       └── public/
│           ├── robots.txt                    # Search engine crawler permissions
│           ├── llms.txt                      # Agentic browsing specification
│           ├── favicon.svg                   # SVG brand icon
│           └── favicon.ico                   # Standard fallback icon
```

---

## 🚀 Getting Started & Execution

### 1. Java Console Application & Tests (Backend / CLI)
Ensure **Java 17+** and **Maven** are installed:
```bash
cd chacha20-cipher

# Run the complete JUnit 5 test suite (36 tests)
mvn clean test

# Package standalone executable JAR
mvn clean package

# Run the interactive 10-option CLI console
java -jar target/chacha20-cipher-1.0.0.jar
```

Or execute directly via Maven:
```bash
mvn exec:java -Dexec.mainClass="com.chacha20.Main"
```

### 2. Interactive Web Studio (Frontend)
Ensure **Node.js (v18+)** is installed:
```bash
cd chacha20-cipher/web

# Install dependencies (Three.js, GSAP, Vite)
npm install

# Run local development server
npm run dev

# Build production bundle with code-splitting
npm run build

# Preview production build locally
npm run preview
```
Open **[http://localhost:5180](http://localhost:5180)** in your browser to view the 3D ARX Reactor Forge, encrypt/decrypt payloads, step through rounds 1–20, and inspect real-time RFC test vectors.

---

## 📖 Standards & Academic References

1. **RFC 8439**: *ChaCha20 and Poly1305 for IETF Protocols* (IRTF Crypto Forum Research Group) — [https://www.rfc-editor.org/rfc/rfc8439](https://www.rfc-editor.org/rfc/rfc8439)
2. **Daniel J. Bernstein**: *ChaCha, a variant of Salsa20* — [https://cr.yp.to/chacha.html](https://cr.yp.to/chacha.html)
3. **Daniel J. Bernstein**: *The Poly1305-AES message-authentication code* — [https://cr.yp.to/mac.html](https://cr.yp.to/mac.html)
4. **IETF RFC 7539**: *ChaCha20 and Poly1305 for IETF Protocols (Historical)* — [https://www.rfc-editor.org/rfc/rfc7539](https://www.rfc-editor.org/rfc/rfc7539)
