/**
 * RFC 8439 ChaCha20 Educational Engine (Client-side JavaScript)
 * Standard: IETF RFC 8439 (Sections 2.1 - 2.4)
 *
 * ARCHITECTURAL NOTICE:
 * This client-side implementation powers the interactive educational visualizer (in-browser
 * round-by-round state matrix inspection, quarter-round ARX animations, and keystream generation).
 * It executes purely within the browser and strictly mirrors the algorithmic semantics of
 * the Java core implementation (com.chacha20.ChaCha20), matching all RFC 8439 test vectors.
 * The comprehensive Java implementation additionally provides CLI, Poly1305, ChaCha20-Poly1305
 * AEAD authenticated encryption, streaming FileCipher, Avalanche analysis, and Benchmarking.
 */
class ChaCha20Engine {
    static CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]; // "expand 32-byte k"

    /**
     * 32-bit unsigned left rotation
     */
    static rotl(v, n) {
        return ((v << n) | (v >>> (32 - n))) >>> 0;
    }

    /**
     * Addition modulo 2^32
     */
    static add(a, b) {
        return (a + b) >>> 0;
    }

    /**
     * ChaCha20 Quarter Round operation (RFC 8439 Section 2.1)
     */
    static quarterRound(state, a, b, c, d) {
        state[a] = this.add(state[a], state[b]);
        state[d] = (state[d] ^ state[a]) >>> 0;
        state[d] = this.rotl(state[d], 16);

        state[c] = this.add(state[c], state[d]);
        state[b] = (state[b] ^ state[c]) >>> 0;
        state[b] = this.rotl(state[b], 12);

        state[a] = this.add(state[a], state[b]);
        state[d] = (state[d] ^ state[a]) >>> 0;
        state[d] = this.rotl(state[d], 8);

        state[c] = this.add(state[c], state[d]);
        state[b] = (state[b] ^ state[c]) >>> 0;
        state[b] = this.rotl(state[b], 7);
    }

    /**
     * Quarter round on 4 standalone numbers (returns steps array for animation)
     */
    static quarterRoundDetailed(a, b, c, d) {
        let steps = [];
        let curA = a >>> 0, curB = b >>> 0, curC = c >>> 0, curD = d >>> 0;

        // Step 1
        curA = this.add(curA, curB);
        curD = (curD ^ curA) >>> 0;
        curD = this.rotl(curD, 16);
        steps.push({ step: 1, formula: "a += b; d ^= a; d <<<= 16", a: curA, b: curB, c: curC, d: curD });

        // Step 2
        curC = this.add(curC, curD);
        curB = (curB ^ curC) >>> 0;
        curB = this.rotl(curB, 12);
        steps.push({ step: 2, formula: "c += d; b ^= c; b <<<= 12", a: curA, b: curB, c: curC, d: curD });

        // Step 3
        curA = this.add(curA, curB);
        curD = (curD ^ curA) >>> 0;
        curD = this.rotl(curD, 8);
        steps.push({ step: 3, formula: "a += b; d ^= a; d <<<= 8", a: curA, b: curB, c: curC, d: curD });

        // Step 4
        curC = this.add(curC, curD);
        curB = (curB ^ curC) >>> 0;
        curB = this.rotl(curB, 7);
        steps.push({ step: 4, formula: "c += d; b ^= c; b <<<= 7", a: curA, b: curB, c: curC, d: curD });

        return { final: [curA, curB, curC, curD], steps };
    }

    /**
     * Converts byte array to 32-bit word in little-endian order
     */
    static bytesToWordLE(bytes, offset) {
        return ((bytes[offset] & 0xFF) |
            ((bytes[offset + 1] & 0xFF) << 8) |
            ((bytes[offset + 2] & 0xFF) << 16) |
            ((bytes[offset + 3] & 0xFF) << 24)) >>> 0;
    }

    /**
     * Converts 32-bit word to 4 bytes in little-endian order
     */
    static wordToBytesLE(word, out, offset) {
        out[offset] = word & 0xFF;
        out[offset + 1] = (word >>> 8) & 0xFF;
        out[offset + 2] = (word >>> 16) & 0xFF;
        out[offset + 3] = (word >>> 24) & 0xFF;
    }

    /**
     * Constructs the 16-word initial state according to RFC 8439
     */
    static createInitialState(keyBytes, counter, nonceBytes) {
        if (keyBytes.length !== 32) throw new Error(`Key must be 32 bytes (got ${keyBytes.length})`);
        if (nonceBytes.length !== 12) throw new Error(`Nonce must be 12 bytes (got ${nonceBytes.length})`);

        let state = new Uint32Array(16);

        // Constants (0..3)
        state[0] = this.CONSTANTS[0];
        state[1] = this.CONSTANTS[1];
        state[2] = this.CONSTANTS[2];
        state[3] = this.CONSTANTS[3];

        // Key (4..11)
        for (let i = 0; i < 8; i++) {
            state[4 + i] = this.bytesToWordLE(keyBytes, i * 4);
        }

        // Counter (12)
        state[12] = counter >>> 0;

        // Nonce (13..15)
        for (let i = 0; i < 3; i++) {
            state[13 + i] = this.bytesToWordLE(nonceBytes, i * 4);
        }

        return state;
    }

    /**
     * Computes the 64-byte keystream block for a given state
     */
    static chachaBlock(keyBytes, counter, nonceBytes, recordRounds = false) {
        let initialState = this.createInitialState(keyBytes, counter, nonceBytes);
        let workingState = new Uint32Array(initialState);
        let roundSnapshots = [];

        if (recordRounds) {
            roundSnapshots.push({ round: 0, type: 'Initial State', state: Array.from(workingState) });
        }

        for (let r = 0; r < 10; r++) {
            // Column Round
            this.quarterRound(workingState, 0, 4, 8, 12);
            this.quarterRound(workingState, 1, 5, 9, 13);
            this.quarterRound(workingState, 2, 6, 10, 14);
            this.quarterRound(workingState, 3, 7, 11, 15);
            if (recordRounds) {
                roundSnapshots.push({ round: r * 2 + 1, type: `Column Round #${r + 1}`, state: Array.from(workingState) });
            }

            // Diagonal Round
            this.quarterRound(workingState, 0, 5, 10, 15);
            this.quarterRound(workingState, 1, 6, 11, 12);
            this.quarterRound(workingState, 2, 7, 8, 13);
            this.quarterRound(workingState, 3, 4, 9, 14);
            if (recordRounds) {
                roundSnapshots.push({ round: r * 2 + 2, type: `Diagonal Round #${r + 1}`, state: Array.from(workingState) });
            }
        }

        // Add initial state to working state (mod 2^32)
        let outputState = new Uint32Array(16);
        for (let i = 0; i < 16; i++) {
            outputState[i] = this.add(workingState[i], initialState[i]);
        }

        if (recordRounds) {
            roundSnapshots.push({ round: 21, type: 'Final Added State (Working + Initial)', state: Array.from(outputState) });
        }

        // Serialize to 64 bytes
        let keystream = new Uint8Array(64);
        for (let i = 0; i < 16; i++) {
            this.wordToBytesLE(outputState[i], keystream, i * 4);
        }

        return {
            initialState: Array.from(initialState),
            outputState: Array.from(outputState),
            keystream: keystream,
            snapshots: roundSnapshots
        };
    }

    /**
     * Encrypts/Decrypts data buffer with ChaCha20
     */
    static process(keyBytes, counter, nonceBytes, inputBytes) {
        if (!inputBytes || inputBytes.length === 0) {
            return {
                outputBytes: new Uint8Array(0),
                numBlocks: 0,
                blocks: []
            };
        }

        let outputBytes = new Uint8Array(inputBytes.length);
        let numBlocks = Math.ceil(inputBytes.length / 64);
        let blockDetails = [];

        for (let b = 0; b < numBlocks; b++) {
            let currentCounter = (counter + b) >>> 0;
            let blockResult = this.chachaBlock(keyBytes, currentCounter, nonceBytes, b === 0);
            let offset = b * 64;
            let len = Math.min(64, inputBytes.length - offset);

            for (let i = 0; i < len; i++) {
                outputBytes[offset + i] = inputBytes[offset + i] ^ blockResult.keystream[i];
            }

            blockDetails.push({
                blockIndex: b,
                counter: currentCounter,
                initialState: blockResult.initialState,
                outputState: blockResult.outputState,
                keystream: blockResult.keystream,
                snapshots: blockResult.snapshots,
                bytesProcessed: len
            });
        }

        return {
            outputBytes: outputBytes,
            numBlocks: numBlocks,
            blocks: blockDetails
        };
    }
}

// Utility Helpers for Browser App
const CryptoUtils = {
    bytesToHex(bytes) {
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    },

    hexToBytes(hex) {
        if (typeof hex !== 'string') {
            throw new Error('Hex input must be a string');
        }
        let clean = hex.replace(/[\s:-]/g, '');
        if (clean.length === 0) {
            return new Uint8Array(0);
        }
        if (clean.length % 2 !== 0) {
            throw new Error('Hex string length must be even');
        }
        if (!/^[0-9a-fA-F]+$/.test(clean)) {
            throw new Error('Hex string contains invalid hexadecimal characters');
        }
        let bytes = new Uint8Array(clean.length / 2);
        for (let i = 0; i < clean.length; i += 2) {
            let byte = parseInt(clean.substring(i, i + 2), 16);
            if (isNaN(byte)) {
                throw new Error(`Invalid hex character at index ${i}`);
            }
            bytes[i / 2] = byte;
        }
        return bytes;
    },

    textToBytes(text) {
        return new TextEncoder().encode(text);
    },

    bytesToText(bytes) {
        return new TextDecoder().decode(bytes);
    },

    randomBytes(len) {
        let arr = new Uint8Array(len);
        window.crypto.getRandomValues(arr);
        return arr;
    },

    formatHexDump(bytes, bytesPerLine = 16) {
        let lines = [];
        for (let i = 0; i < bytes.length; i += bytesPerLine) {
            let chunk = bytes.slice(i, i + bytesPerLine);
            let hexPart = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
            let asciiPart = Array.from(chunk).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
            let offset = i.toString(16).padStart(4, '0');
            lines.push(`${offset}  ${hexPart.padEnd(bytesPerLine * 3, ' ')} |${asciiPart}|`);
        }
        return lines.join('\n');
    }
};

// Expose globally for vanilla browser scripts and export for ES module bundlers
if (typeof window !== 'undefined') {
    window.ChaCha20Engine = ChaCha20Engine;
    window.CryptoUtils = CryptoUtils;
}
export { ChaCha20Engine, CryptoUtils };
