# ChaCha20 CipherForge — Interactive ARX Cryptographic Engine & AEAD Studio

[![RFC 8439](https://img.shields.io/badge/RFC-8439%20Compliant-blue.svg)](https://www.rfc-editor.org/rfc/rfc8439)
[![Java 17+](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://www.oracle.com/java/)
[![JUnit 5](https://img.shields.io/badge/JUnit-36%20%2F%2036%20Pass-brightgreen.svg)](chacha20-cipher/test-results/TEST-RESULTS.md)
[![Browser Probes](https://img.shields.io/badge/Probes-4%20%2F%204%20PASS%20(RFC%208439)-emerald.svg)](#-implementation-verification--automated-probes-44-pass)
[![Math Engine](https://img.shields.io/badge/Math-KaTeX%20Textbook%20LaTeX-9cf.svg)](https://katex.org/)
[![Lighthouse](https://img.shields.io/badge/Lighthouse-100%20%7C%20100%20%7C%20100%20%7C%20100-success.svg)](#-lighthouse-1341-audit-results)
[![Vercel](https://img.shields.io/badge/Deploy-Live%20on%20Vercel-success.svg?logo=vercel)](https://cryptography-assignment.vercel.app/)
[![License: Academic](https://img.shields.io/badge/License-Academic%20MIT-lightgrey.svg)](LICENSE)

---

## 🌐 Live Deployment & Interactive Studio

🚀 **Live URL:** [https://cryptography-assignment.vercel.app/](https://cryptography-assignment.vercel.app/)

Access the live, client-side 3D ChaCha20 virtual laboratory with interactive ARX state matrix visualization, 20-round stepper, textbook mathematical formulas, and instant RFC 8439 verification without any local installation.

---

An academic, production-grade, zero-dependency implementation of the **IETF ChaCha20 Stream Cipher**, **Poly1305 One-Time Authenticator**, and **ChaCha20-Poly1305 AEAD (RFC 8439)** developed in pure **Java 17+**, paired with a **3D Web Studio & Virtual Cryptographic Laboratory** built in Three.js, GSAP, and KaTeX.

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
│ • Poly1305 128-bit MAC Authenticator      │ • 3D Holographic ARX State Visualizer      │
│ • ChaCha20-Poly1305 AEAD Pipeline (§2.8)  │ • On-Demand Inspection Module Hub          │
│ • 64 KB Buffered Streaming File Cipher    │ • 4×4 512-Bit Matrix (Minimal Hex UI)      │
│ • Multi-Trial Avalanche Diffusion Analyzer│ • Quarter-Round ARX Live Sandbox           │
│ • Academic JVM Benchmark Suite (MB/s)     │ • 4/4 Bit-Exact Automated Diagnostic Probes│
│ • 36-Test Automated JUnit 5 Suite         │ • Formal Textbook Math Formulations (KaTeX)│
│ • ASCII State Tracer & Validation Engine  │ • Symmetrical Header Nav & Academic Footer │
└───────────────────────────────────────────┴────────────────────────────────────────────┘
```

---

## ⚡ 3D Holographic ARX Cryptographic Engine & State Visualizer

The web studio features a 3D entrance animation sequence that visualizes the internal mechanics of ChaCha20:

1. **Automatic Initialization**: Triggers automatically on page load and refresh with seamless handover into the ambient background. Instant bypass available at any time via `[ESC]` or the `START LAB [ESC]` button.
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
5. **Accurate Cryptographic Typography**:
   - Badge: `● ARX CRYPTOGRAPHIC ENGINE · 512-BIT INTERNAL STATE`
   - Title: `CHACHA20 CIPHERFORGE` with electric cyan-to-violet holographic gradient
   - Subtitle: `ChaCha20 Stream Cipher · 256-Bit Key · 96-Bit Nonce · 20 Rounds`
   - Stream Pill: `ARX PIPELINE: ⊞ ADD (mod 2³²) · ⋘ ROTATE · ⨁ XOR ┃ 20 ROUNDS · 10 DOUBLE ROUNDS`
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

## 🔬 Cryptographic Inspection Modules & On-Demand Architecture

The ChaCha20 CipherForge Web Studio integrates an **On-Demand Cryptographic Inspection Architecture**. Rather than cluttering the primary cipher interface, deep internal mechanics are compartmentalized into **4 interactive inspection modules** accessible via the top segmented navigation deck, the inspection hub, and the academic footer.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        ON-DEMAND INSPECTION MODULE SUITE                               │
├─────────────────────┬─────────────────────┬─────────────────────┬──────────────────────┤
│ ◫ STATE MATRIX      │ ⊕ QUARTER ROUND ARX │ ✓ RFC VERIFICATION  │ ∑ FORMULAS (KATEX)   │
├─────────────────────┼─────────────────────┼─────────────────────┼──────────────────────┤
│ • Minimal Hex Grid  │ • ARX Trio Metrics  │ • 4/4 Auto Probes   │ • 7 Formal Theorems  │
│ • State Anatomy     │ • 4-Stage Pipeline  │ • Canonical §2.1.1  │ • 16 Numbered Eqns   │
│ • 20-Round Stepper  │ • Live ARX Sandbox  │ • §2.3.2 Block Test │ • Springer/AMS Style │
│ • Word Diff Tracing │ • Col / Diag Models │ • §2.4.2 Encryption │ • Poly1305 Field Math│
└─────────────────────┴─────────────────────┴─────────────────────┴──────────────────────┘
```

### 1. ◫ 512-Bit State Matrix Analyzer (Refined Minimal UI)
* **Word Anatomy Breakdown:** Categorizes all 16 32-bit words into distinct color-coded semantic groups:
  * **Constants (Words 0–3):** `0x61707865`, `0x3320646e`, `0x79622d32`, `0x6b206574` (`"expand 32-byte k"` in little-endian).
  * **Key Words (Words 4–11):** 256-bit secret user key partitioned into 8 32-bit little-endian integers.
  * **Counter (Word 12):** 32-bit little-endian block counter ($0$ to $2^{32}-1$).
  * **Nonce (Words 13–15):** 96-bit unique initialization vector (3 32-bit little-endian words).
* **Minimal Clean Presentation:** Replaced long, cluttered binary/decimal strings with concise, high-contrast hexadecimal representations, eliminating visual noise.
* **20-Round Interactive Stepper:** Step forward, step backward, or auto-play through rounds 1 to 20 with real-time word perturbation diff highlighting.

### 2. ⊕ Quarter Round (ARX) Kernel & Interactive Sandbox
* **The ARX Cryptographic Trio:**
  * **Modular Addition ($\boxplus$):** $a \boxplus b \pmod{2^{32}}$ provides non-linear algebraic mixing over $\mathbb{Z}_{2^{32}}$.
  * **Bitwise XOR ($\oplus$):** $d \oplus a$ introduces non-linearity across vector space $\mathbb{F}_2^{32}$.
  * **Cyclic Rotation ($\lll$):** Bitwise left rotation by constant distances $r \in \{16, 12, 8, 7\}$ rapidly diffuses carry bits.
* **4-Stage Visual Execution Pipeline:** Color-coded register chips ($a$ Cyan, $b$ Indigo, $c$ Amber, $d$ Emerald) track the state across all 4 operational phases:
  1. $a \leftarrow a + b, \quad d \leftarrow (d \oplus a) \lll 16$
  2. $c \leftarrow c + d, \quad b \leftarrow (b \oplus c) \lll 12$
  3. $a \leftarrow a + b, \quad d \leftarrow (d \oplus a) \lll 8$
  4. $c \leftarrow c + d, \quad b \leftarrow (b \oplus c) \lll 7$
* **Live ARX Permutation Sandbox:** An interactive calculator allowing students and evaluators to input any four 32-bit words ($a, b, c, d$), click **Compute QR**, and view the instant transformed registers with automatic RFC 8439 §2.1.1 conformance verification.
* **Permutation Geometry:** Visual comparison between **Odd Column Rounds** ($\text{QR}(0,4,8,12)$, $\text{QR}(1,5,9,13)$, etc.) and **Even Diagonal Rounds** ($\text{QR}(0,5,10,15)$, $\text{QR}(1,6,11,12)$, etc.) preventing localized clustering and achieving 100% avalanche diffusion by Round 7.

### 3. ✓ Implementation Verification & Automated Probes (4 / 4 PASS)
Real-time browser-side cryptographic diagnostic engine executing bit-exact test vector assertions:
* **Block Function Test (§2.3.2):** `PASS · 64 B` — Validates the full 512-bit block transformation against official IETF reference keystream.
* **RFC 8439 Test Vector (§2.4.2):** `PASS · 114 B` — Tests full stream encryption over the canonical "Sunscreen" plaintext payload.
* **Decryption Round-Trip Test:** `PASS · XOR symmetric` — Confirms mathematical involutive symmetry ($D_K(E_K(P)) = P$).
* **Quarter-Round ARX Test (§2.1.1):** `PASS · §2.1.1 ARX` — Verified against the canonical IETF RFC vector:
  $$\text{Input: } a=\mathtt{0x11111111},\ b=\mathtt{0x01020304},\ c=\mathtt{0x9b8d6f43},\ d=\mathtt{0x01234567}$$
  $$\text{Transformed: } a'=\mathtt{0xea2a92f4},\ b'=\mathtt{0xcb1cf8ce},\ c'=\mathtt{0x4581472e},\ d'=\mathtt{0x5881c4bb}$$
  *(Resolved test vector anomaly where test input register $c$ was corrected to official IETF value $\mathtt{0x9b8d6f43}$).*
* **Telemetry Ribbon:** Displays audit status (`4 / 4 PASS`), bit-exact status (`100% Match`), execution latency (`< 0.2 ms`), and standards compliance (`RFC 8439 Strict`).

### 4. ∑ Formal Textbook Mathematical Formulations (KaTeX)
Renders textbook mathematical specifications locally using bundled **KaTeX** with Springer/AMS typographic conventions:
* **Definition 1 (ARX Primitives):** Formal group definitions of $\mathbb{Z}_{2^{32}}$, $\mathbb{F}_2^{32}$, and bit-shift rotations $\lll_r$.
* **Definition 2 (Quarter-Round Equations):** Equations $(1)$ through $(4)$ with exact modulus notations.
* **Definition 3 (State Matrix Algebra):** Algebraic representation of $\mathbf{S} \in \mathcal{M}_{4 \times 4}(\mathbb{Z}_{2^{32}})$ and little-endian byte-to-word deserialization $(5)–(6)$.
* **Definition 4 (Double-Round Permutations):** Column and diagonal vector mappings $(7)–(10)$.
* **Definition 5 (Keystream Generation):** Feed-forward matrix addition $\mathbf{S}^{(20)} \boxplus \mathbf{S}^{(0)}$ and serialization into 64-byte keystream block $\mathbf{Z} \in \{0,1\}^{512}$ $(11)–(12)$.
* **Definition 6 (Stream Cipher Encryption):** Invertible XOR stream symmetry $(13)$.
* **Definition 7 (Poly1305 MAC Authenticator):** Universal hash polynomial evaluation modulo the Mersenne-like prime $p = 2^{130} - 5$, clamp masking, and tag generation over $\mathbb{F}_{2^{130}-5}$ $(14)–(16)$.

### 5. 🏛️ Navigation & Comprehensive Academic Footer Architecture
* **Symmetrical Header Navigation:**
  * Segmented glassmorphic deck containing all 4 inspection switchers with color-coded thematic icons (Cyan, Amber, Emerald, Violet).
  * Single-axis alignment preventing wrapping or disorder across all standard screen sizes.
  * Responsive 2-tier and 2×2 grid conversions for compact and mobile screens.
* **Academic Multi-Column Footer:**
  * **Brand & Manifesto:** High-assurance compliance pills (`RFC 8439`, `256-Bit Key`, `Zero S-Boxes`, `36/36 Tests Pass`).
  * **Module Direct Links:** Direct interactive toggles to reveal any inspection panel and scroll smoothly into view.
  * **Standards & Foundational Papers:** Clickable citations for IETF RFC 8439, Bernstein (2008) ChaCha, Poly1305 MAC, and TLS 1.3 RFC 8446.
  * **Course Credentials:** Formal course metadata (`BCS703 — Cryptography & Network Security`, `Java 17 Standard Edition`, `Three.js WebGL & KaTeX Math`, live compliance indicator).
  * **Utility Bar:** Back to Top smooth scroll button and academic copyright notice.

---

## 📁 Repository Structure

```
Cryptography-Assignment/
├── README.md                                 # Root repository overview & documentation
├── DEPLOYMENT_GUIDE.md                       # Complete deployment manual (Vercel, Netlify, Pages)
├── TASK_IMPLEMENTATION_EXPLANATION.txt       # Formal academic task explanation & Viva preparation
├── package.json                              # Root npm delegation script for zero-config CI/CD
├── vercel.json                               # Root Vercel cloud deployment specification & headers
├── netlify.toml                              # Netlify build & security headers configuration
├── .gitignore                                # Excludes target/, node_modules/, dist/, .vite/
├── .github/
│   └── workflows/
│       └── deploy.yml                        # GitHub Pages automated deployment workflow
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
│       ├── index.html                        # Web Studio UI, on-demand inspection panels & academic footer
│       ├── style.css                         # Dark glassmorphism styling, KaTeX typography & responsive design
│       ├── chacha20.js                       # Pure client-side JavaScript ChaCha20 engine
│       ├── scene.js                          # Three.js + GSAP 3D ARX State Visualizer & particle field
│       ├── app.js                            # UI state, 20-round stepper, KaTeX rendering, ARX sandbox & probes
│       ├── vite.config.js                    # Vite bundler configuration & relative asset pathing
│       ├── vercel.json                       # Subfolder Vercel configuration fallback
│       ├── package.json                      # Web project dependencies (Three.js, GSAP, KaTeX, Vite)
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

# Install dependencies (Three.js, GSAP, KaTeX, Vite)
npm install

# Run local development server
npm run dev

# Build production bundle with code-splitting
npm run build

# Preview production build locally
npm run preview
```
Open **[http://localhost:8439](http://localhost:8439)** in your browser to view the 3D ARX State Visualizer, encrypt/decrypt payloads, step through rounds 1–20, and inspect real-time RFC test vectors.

### 3. Zero-Error Cloud Deployment (Vercel, Netlify & GitHub Pages)
The web application is fully hardened for one-click, zero-error cloud deployment:

* **Vercel (Recommended)**:
  1. Navigate to [vercel.com](https://vercel.com) and click **Add New...** > **Project**.
  2. Select the `Cryptography-Assignment` repository.
  3. Leave all default build settings (auto-detected via root [`vercel.json`](vercel.json) and [`package.json`](package.json)).
  4. Click **Deploy**. The site builds in ~2 seconds with zero configuration.
* **Asset 404 Prevention**: Bundled with `base: './'` in [`vite.config.js`](chacha20-cipher/web/vite.config.js) ensuring all chunks load correctly across custom domains and subpaths.
* **HTTP Security Headers**: Pre-configured with `nosniff`, `X-Frame-Options: DENY`, and `strict-origin-when-cross-origin`.
* **Step-by-Step Manual**: See [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md) for detailed Netlify and GitHub Pages instructions.

---

## 📝 Academic Task Submission & Viva Materials

For evaluators and academic demonstration:
* **Task Implementation & Mathematical Proof**: See [`TASK_IMPLEMENTATION_EXPLANATION.txt`](TASK_IMPLEMENTATION_EXPLANATION.txt) for a complete explanation of ARX quarter-round logic, the 512-bit state matrix, test vector verification, avalanche diffusion results, and benchmark metrics formatted for assignment submission.
* **Complete Technical Specification**: See [`chacha20-cipher/README.md`](chacha20-cipher/README.md) for the 21-section in-depth algorithmic documentation.
* **Official Test Verification Log**: See [`chacha20-cipher/test-results/TEST-RESULTS.md`](chacha20-cipher/test-results/TEST-RESULTS.md) for individual test parameters and RFC vector match proofs.

---

## 📖 Standards & Academic References

1. **RFC 8439**: *ChaCha20 and Poly1305 for IETF Protocols* (IRTF Crypto Forum Research Group) — [https://www.rfc-editor.org/rfc/rfc8439](https://www.rfc-editor.org/rfc/rfc8439)
2. **Daniel J. Bernstein**: *ChaCha, a variant of Salsa20* — [https://cr.yp.to/chacha.html](https://cr.yp.to/chacha.html)
3. **Daniel J. Bernstein**: *The Poly1305-AES message-authentication code* — [https://cr.yp.to/mac.html](https://cr.yp.to/mac.html)
4. **IETF RFC 7539**: *ChaCha20 and Poly1305 for IETF Protocols (Historical)* — [https://www.rfc-editor.org/rfc/rfc7539](https://www.rfc-editor.org/rfc/rfc7539)
