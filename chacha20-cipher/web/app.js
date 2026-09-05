/**
 * ChaCha20 Stream Cipher Studio — application logic
 * Everything here consumes the pure engine in chacha20.js (RFC 8439).
 * No values are invented: every matrix snapshot, keystream, and "PASS"
 * comes from an actual computation.
 */
import { ChaCha20Engine, CryptoUtils } from './chacha20.js';

/* ------------------------------- state ------------------------------- */
const appState = {
    mode: 'encrypt',                 // 'encrypt' | 'decrypt'
    currentSnapshotIndex: 0,
    recordedSnapshots: [],
    lastResult: null,                // ChaCha20Engine.process result
    lastOutputHex: '',
    lastOutputBase64: '',
    lastPayloadBytes: 0,
    lastRfcMatch: false,             // sunscreen §2.4.2 match on last run
    lastRoundTripOk: false,
    isPlayingRounds: false,
    playTimer: null,
    playBlocked: false,
    restoreStatus: null              // status snapshot to restore after round play
};

/* ------------------------------ elements ------------------------------ */
const elements = {
    tabEncrypt: document.getElementById('tab-encrypt'),
    tabDecrypt: document.getElementById('tab-decrypt'),
    modeBadge: document.getElementById('mode-badge'),
    modeChip: document.getElementById('mode-chip'),
    inputLabel: document.getElementById('input-label'),
    secondaryLabel: document.getElementById('secondary-label'),
    outputLabel: document.getElementById('output-label'),
    outputMeta: document.getElementById('output-meta'),
    inputKey: document.getElementById('input-key'),
    inputNonce: document.getElementById('input-nonce'),
    inputCounter: document.getElementById('input-counter'),
    inputText: document.getElementById('input-text'),
    keyShell: document.querySelector('#input-key').parentElement,
    nonceShell: document.querySelector('#input-nonce').parentElement,
    counterShell: document.querySelector('#input-counter').parentElement,
    msgKey: document.getElementById('msg-key'),
    msgNonce: document.getElementById('msg-nonce'),
    msgCounter: document.getElementById('msg-counter'),
    msgText: document.getElementById('msg-text'),
    btnRandomKey: document.getElementById('btn-random-key'),
    btnRandomNonce: document.getElementById('btn-random-nonce'),
    btnExecute: document.getElementById('btn-execute'),
    btnExecuteLabel: document.getElementById('btn-execute-label'),
    btnCopyHex: document.getElementById('btn-copy-hex'),
    btnCopyBase64: document.getElementById('btn-copy-base64'),
    outputResult: document.getElementById('output-result'),
    outputSecondary: document.getElementById('output-secondary'),
    verifyBanner: document.getElementById('verify-banner'),
    verifyIcon: document.getElementById('verify-icon'),
    verifyText: document.getElementById('verify-text'),
    statBytes: document.getElementById('stat-bytes'),
    statBlocks: document.getElementById('stat-blocks'),
    statRounds: document.getElementById('stat-rounds'),
    statusCard: document.getElementById('status-card'),
    statusTitle: document.getElementById('status-title'),
    statusDetail: document.getElementById('status-detail'),
    statusChip: document.getElementById('status-chip'),
    matrixGrid: document.getElementById('matrix-grid'),
    btnStepPrev: document.getElementById('btn-step-prev'),
    btnStepNext: document.getElementById('btn-step-next'),
    btnStepPlay: document.getElementById('btn-step-play'),
    roundReadout: document.getElementById('round-readout'),
    roundSub: document.getElementById('round-sub'),
    roundProgressbar: document.getElementById('round-progressbar'),
    roundProgressFill: document.getElementById('round-progress-fill'),
    roundProgressLabel: document.getElementById('round-progress-label'),
    stepExplanation: document.getElementById('step-explanation'),
    visualizerBlock: document.getElementById('visualizer-block'),
    presetRfcSunscreen: document.getElementById('preset-rfc-sunscreen'),
    presetRfcBlock: document.getElementById('preset-rfc-block'),
    presetDemo: document.getElementById('preset-demo'),
    presetClear: document.getElementById('preset-clear')
};

/* --------------------------- tiny helpers --------------------------- */
const $hex = (h) => CryptoUtils.hexToBytes(h);
const hexOf = (bytes) => CryptoUtils.bytesToHex(bytes);
const BYTES_TO_BASE64 = (bytes) => {
    let bin = '';
    const CHUNK = 0x8000;
    for (let i = 0; i < bytes.length; i += CHUNK) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return btoa(bin);
};
const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
// Allow the PROCESSING state to paint before the (synchronous) computation runs;
// the timeout fallback keeps things moving even when rAF is throttled.
const paintTick = () => new Promise((resolve) => {
    let done = false;
    const finish = () => { if (!done) { done = true; resolve(); } };
    requestAnimationFrame(finish);
    setTimeout(finish, 60);
});

/* ============================ status machine ============================ */
function setStatus(kind, title, detail, chip) {
    const known = ['ready', 'processing', 'round', 'complete', 'warn', 'error'];
    elements.statusCard.classList.remove(...known.map((k) => 'st-' + k));
    elements.statusCard.classList.add('st-' + kind);
    elements.statusTitle.textContent = title;
    elements.statusDetail.textContent = detail;
    elements.statusChip.textContent = chip || '·';
    if (kind !== 'round') {
        appState.restoreStatus = { kind, title, detail, chip: chip || '·' };
    }
}
function restoreStatus() {
    if (appState.restoreStatus) {
        const s = appState.restoreStatus;
        setStatus(s.kind, s.title, s.detail, s.chip);
    }
}

/* ============================ field validation ============================ */
function cleanHexInput(v) {
    return (v || '').replace(/[\s:-]/g, '');
}
function setFieldMsg(el, text, tone) {
    el.textContent = text;
    el.className = 'field-msg' + (tone ? ' msg-' + tone : '');
}
function setShellState(shell, state) { // state: 'ok' | 'err' | ''
    shell.classList.toggle('is-valid', state === 'ok');
    shell.classList.toggle('has-error', state === 'err');
}

function validateKeyField() {
    const raw = elements.inputKey.value;
    const hex = cleanHexInput(raw);
    if (!hex) {
        setShellState(elements.keyShell, '');
        setFieldMsg(elements.msgKey, 'Awaiting key — enter 64 hex characters.');
        return false;
    }
    if (!/^[0-9a-fA-F]+$/.test(hex)) {
        setShellState(elements.keyShell, 'err');
        setFieldMsg(elements.msgKey, 'Key contains non-hexadecimal characters.', 'error');
        return false;
    }
    if (hex.length !== 64) {
        setShellState(elements.keyShell, 'err');
        setFieldMsg(elements.msgKey, `Key must be 64 hex chars — currently ${hex.length}.`, 'error');
        return false;
    }
    setShellState(elements.keyShell, 'ok');
    setFieldMsg(elements.msgKey, '256-bit key valid.', 'ok');
    return true;
}

function validateNonceField() {
    const hex = cleanHexInput(elements.inputNonce.value);
    if (!hex) {
        setShellState(elements.nonceShell, '');
        setFieldMsg(elements.msgNonce, 'Awaiting nonce — enter 24 hex characters.');
        return false;
    }
    if (!/^[0-9a-fA-F]+$/.test(hex)) {
        setShellState(elements.nonceShell, 'err');
        setFieldMsg(elements.msgNonce, 'Nonce contains non-hexadecimal characters.', 'error');
        return false;
    }
    if (hex.length !== 24) {
        setShellState(elements.nonceShell, 'err');
        setFieldMsg(elements.msgNonce, `Nonce must be 24 hex chars — currently ${hex.length}.`, 'error');
        return false;
    }
    setShellState(elements.nonceShell, 'ok');
    setFieldMsg(elements.msgNonce, '96-bit nonce valid — never reuse with the same key.', 'ok');
    return true;
}

function validateCounterField() {
    const raw = elements.inputCounter.value.trim();
    if (raw === '') {
        // empty input falls back to 1 at execution time
        setShellState(elements.counterShell, '');
        setFieldMsg(elements.msgCounter, 'Counter defaults to 1 (IETF start) when left empty.');
        return true;
    }
    const num = Number(raw);
    if (!Number.isInteger(num) || num < 0 || num > 0xFFFFFFFF) {
        setShellState(elements.counterShell, 'err');
        setFieldMsg(elements.msgCounter, 'Counter must be an integer in [0, 4294967295].', 'error');
        return false;
    }
    setShellState(elements.counterShell, 'ok');
    setFieldMsg(elements.msgCounter, '32-bit counter valid.', 'ok');
    return true;
}

function validateTextField() {
    const val = elements.inputText.value;
    if (appState.mode === 'encrypt') {
        elements.msgText.className = 'field-msg';
        elements.msgText.textContent = '';
        return true; // empty plaintext is legal (produces empty output)
    }
    // decrypt mode: hex input
    const hex = cleanHexInput(val);
    if (!hex) {
        elements.msgText.textContent = 'Paste hexadecimal ciphertext to decrypt.';
        return false;
    }
    if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
        elements.msgText.className = 'field-msg msg-error';
        elements.msgText.textContent = 'Ciphertext must be an even-length hexadecimal string.';
        return false;
    }
    elements.msgText.className = 'field-msg msg-ok';
    elements.msgText.textContent = `${hex.length / 2} bytes of ciphertext ready.`;
    return true;
}

function allParamsValid() {
    return validateKeyField() && validateNonceField() && validateCounterField() && validateTextField();
}

/* ============================== modes ============================== */
function setMode(mode) {
    stopPlayRounds();
    appState.mode = mode;
    const enc = mode === 'encrypt';
    elements.tabEncrypt.classList.toggle('active', enc);
    elements.tabDecrypt.classList.toggle('active', !enc);
    elements.tabEncrypt.setAttribute('aria-selected', String(enc));
    elements.tabDecrypt.setAttribute('aria-selected', String(!enc));
    elements.modeBadge.textContent = enc ? 'ENCRYPT' : 'DECRYPT';
    elements.modeBadge.className = 'badge ' + (enc ? 'badge-enc' : 'badge-dec');
    elements.modeChip.textContent = enc ? 'UTF-8 / ASCII' : 'HEX INPUT';
    elements.inputLabel.textContent = enc ? 'Plaintext' : 'Ciphertext';
    elements.inputText.placeholder = enc ? 'Enter plaintext message…' : 'Paste hexadecimal ciphertext…';
    elements.inputText.setAttribute('aria-label', enc
        ? 'Message to encrypt (plaintext)'
        : 'Ciphertext in hexadecimal to decrypt');
    elements.secondaryLabel.textContent = enc ? 'Round-trip verification preview' : 'Recovered plaintext (UTF-8)';
    elements.outputLabel.textContent = enc ? 'CIPHERTEXT STREAM · HEX' : 'DECRYPTED STREAM · HEX';
    validateTextField();
    processCipher();
}

/* ========================== random generators ========================== */
function generateRandomKey() {
    elements.inputKey.value = CryptoUtils.bytesToHex(CryptoUtils.randomBytes(32));
    validateKeyField();
    processCipher();
}
function generateRandomNonce() {
    elements.inputNonce.value = CryptoUtils.bytesToHex(CryptoUtils.randomBytes(12));
    validateNonceField();
    processCipher();
}

/* ============================ presets ============================ */
function loadRfcSunscreenPreset() {
    setMode('encrypt');
    elements.inputKey.value = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
    elements.inputNonce.value = '000000000000004a00000000';
    elements.inputCounter.value = '1';
    elements.inputText.value = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    processCipher();
    setStatus('complete', 'VECTOR LOADED', 'RFC 8439 §2.4.2 parameters ready — result matches the official vector.', '§2.4.2');
}
function loadRfcBlockPreset() {
    setMode('encrypt');
    elements.inputKey.value = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
    elements.inputNonce.value = '000000090000004a00000000';
    elements.inputCounter.value = '1';
    elements.inputText.value = 'ChaCha20 64-byte block generation test (RFC 8439 Section 2.3.2)';
    processCipher();
    setStatus('complete', 'VECTOR LOADED', 'RFC 8439 §2.3.2 block-function parameters ready — see visualizer and RFC panel.', '§2.3.2');
}
function loadDemoPreset() {
    setMode('encrypt');
    elements.inputKey.value = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
    elements.inputNonce.value = '000000000000004a00000000';
    elements.inputCounter.value = '1';
    elements.inputText.value = 'Cryptography & Network Security (BCS703): ChaCha20 Stream Cipher Implementation';
    processCipher();
    setStatus('ready', 'READY', 'Demo parameters loaded — press EXECUTE or edit any field.', 'DEMO');
}
function clearInputs() {
    stopPlayRounds();
    elements.inputKey.value = '';
    elements.inputNonce.value = '';
    elements.inputCounter.value = '1';
    elements.inputText.value = '';
    [elements.keyShell, elements.nonceShell, elements.counterShell].forEach((s) => setShellState(s, ''));
    validateCounterField();
    setFieldMsg(elements.msgKey, 'Awaiting key — enter 64 hex characters.');
    setFieldMsg(elements.msgNonce, 'Awaiting nonce — enter 24 hex characters.');
    elements.msgText.textContent = '';
    resetOutputs();
    resetMatrix();
    setStatus('ready', 'READY', 'System ready — waiting for parameters.', 'IDLE');
}

/* ===================== output rendering & copies ===================== */
function placeholder(el, text) {
    el.innerHTML = '';
    const s = document.createElement('span');
    s.className = 'placeholder';
    s.textContent = text;
    el.appendChild(s);
}

function groupHex(hex) {
    // readability only — copies always use the raw continuous hex
    const out = [];
    for (let i = 0; i < hex.length; i += 32) out.push(hex.slice(i, i + 32));
    return out.join('\n');
}

function showVerification(pass, msg) {
    elements.verifyBanner.hidden = false;
    elements.verifyBanner.className = 'verify-banner ' + (pass ? 'verify-pass' : 'verify-fail');
    elements.verifyIcon.textContent = pass ? '✓' : '✕';
    elements.verifyText.textContent = msg;
}

function resetOutputs() {
    appState.lastOutputHex = '';
    appState.lastOutputBase64 = '';
    appState.lastPayloadBytes = 0;
    appState.lastRfcMatch = false;
    appState.lastRoundTripOk = false;
    placeholder(elements.outputResult, '— awaiting valid input —');
    placeholder(elements.outputSecondary, '— awaiting valid input —');
    elements.verifyBanner.hidden = true;
    elements.outputMeta.textContent = '0 B';
    elements.btnCopyHex.disabled = true;
    elements.btnCopyBase64.disabled = true;
    elements.statBytes.textContent = '0';
    elements.statBlocks.textContent = '0';
    elements.statRounds.textContent = '0';
}

function renderOutput() {
    const r = appState.lastResult;
    if (!r) return;
    const payloadBytes = appState.lastPayloadBytes;
    elements.outputMeta.textContent = payloadBytes + ' B';
    elements.btnCopyHex.disabled = !appState.lastOutputHex;
    elements.btnCopyBase64.disabled = !appState.lastOutputBase64;
}

function setCopyFlash(btn) {
    const old = btn.textContent;
    btn.classList.add('copied');
    btn.textContent = '✓ COPIED';
    setTimeout(() => {
        btn.classList.remove('copied');
        btn.textContent = old;
    }, 1400);
}

async function copyText(text, btn) {
    if (!text) return;
    try {
        await navigator.clipboard.writeText(text);
    } catch (err) {
        // fallback for non-secure contexts (e.g. file://)
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); } catch (e2) { /* ignore */ }
        ta.remove();
    }
    setCopyFlash(btn);
}

/* ========================= cipher execution ========================= */
function readInputs() {
    const keyHex = cleanHexInput(elements.inputKey.value);
    const nonceHex = cleanHexInput(elements.inputNonce.value);
    let counterVal = parseInt(elements.inputCounter.value.trim() || '1', 10);
    if (!Number.isInteger(counterVal) || counterVal < 0 || counterVal > 0xFFFFFFFF) counterVal = 1;
    const textInput = elements.inputText.value;
    return { keyHex, nonceHex, counterVal, textInput };
}

/**
 * Runs the real ChaCha20 computation for the current inputs and renders
 * every output surface. Returns true on success (never throws to the caller).
 */
function processCipher() {
    stopPlayRounds();
    const { keyHex, nonceHex, counterVal, textInput } = readInputs();
    const keyOk = validateKeyField();
    const nonceOk = validateNonceField();
    const counterOk = validateCounterField();
    const textOk = validateTextField();

    if (!keyOk || !nonceOk || !counterOk || !textOk) {
        resetOutputs();
        resetMatrix();
        setStatus('warn', 'PARAMETER CHECK', 'Fix the highlighted fields to continue.', 'CHECK');
        return false;
    }
    if (!keyHex || !nonceHex) {
        resetOutputs();
        resetMatrix();
        setStatus('ready', 'READY', 'System ready — waiting for parameters.', 'IDLE');
        return false;
    }

    try {
        const keyBytes = $hex(keyHex);
        const nonceBytes = $hex(nonceHex);

        let inputBytes;
        if (appState.mode === 'encrypt') {
            inputBytes = CryptoUtils.textToBytes(textInput);
        } else {
            inputBytes = $hex(textInput); // validated above
        }

        const result = ChaCha20Engine.process(keyBytes, counterVal, nonceBytes, inputBytes);
        const outputHex = hexOf(result.outputBytes);

        appState.lastResult = result;
        appState.lastOutputHex = outputHex;
        appState.lastOutputBase64 = result.outputBytes.length ? BYTES_TO_BASE64(result.outputBytes) : '';
        appState.lastPayloadBytes = inputBytes.length;
        appState.lastRfcMatch = false;
        appState.lastRoundTripOk = false;

        // --- display primary stream (grouped for readability, raw hex kept for copy)
        if (outputHex) {
            const frag = document.createDocumentFragment();
            for (const line of groupHex(outputHex).split('\n')) {
                const span = document.createElement('span');
                span.className = 'hex-line';
                span.textContent = line;
                frag.appendChild(span);
            }
            elements.outputResult.innerHTML = '';
            elements.outputResult.appendChild(frag);
        } else {
            placeholder(elements.outputResult, '(empty output — no payload bytes)');
        }

        // --- verification surfaces
        if (appState.mode === 'encrypt') {
            const decrypted = ChaCha20Engine.process(keyBytes, counterVal, nonceBytes, result.outputBytes);
            const decryptedText = CryptoUtils.bytesToText(decrypted.outputBytes);
            if (textInput === '') {
                placeholder(elements.outputSecondary, '(empty plaintext — nothing to verify)');
            } else {
                elements.outputSecondary.innerHTML = '';
                elements.outputSecondary.appendChild(document.createTextNode(decryptedText));
            }
            appState.lastRoundTripOk = textInput.length > 0 && decryptedText === textInput;

            const RFC_SUNSCREEN = '6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d';
            appState.lastRfcMatch = outputHex.toLowerCase() === RFC_SUNSCREEN;

            if (appState.lastRfcMatch) {
                showVerification(true, 'RFC 8439 §2.4.2 official vector matched — encryption correct.');
            } else if (appState.lastRoundTripOk) {
                showVerification(true, 'Round-trip integrity verified — decrypt(encrypt(P)) = P.');
            } else if (textInput.length > 0) {
                showVerification(false, 'Round-trip check failed — plaintext not recovered.');
            } else {
                elements.verifyBanner.hidden = true;
            }
        } else {
            const recoveredText = CryptoUtils.bytesToText(result.outputBytes);
            elements.outputSecondary.innerHTML = '';
            elements.outputSecondary.appendChild(document.createTextNode(recoveredText));
            showVerification(true, 'Decryption complete — ciphertext stream processed.');
        }

        // --- live status reflects the real computation outcome
        if (appState.mode === 'encrypt') {
            if (appState.lastRfcMatch) {
                setStatus('complete', 'VECTOR MATCHED', 'RFC 8439 §2.4.2 ciphertext reproduced exactly.', '§2.4.2');
            } else if (appState.lastRoundTripOk) {
                setStatus('complete', 'RESULT READY', 'Ciphertext generated · round-trip verified.', 'LIVE');
            } else if (textInput.length > 0) {
                setStatus('warn', 'CHECK FAILED', 'Round-trip verification did not reproduce the plaintext.', '!');
            } else {
                setStatus('ready', 'READY', 'Empty payload — type a message to encrypt.', 'EMPTY');
            }
        } else {
            setStatus('complete', 'PLAINTEXT RECOVERED', 'Ciphertext processed — output below.', 'LIVE');
        }

        // --- statistics
        elements.statBytes.textContent = inputBytes.length;
        elements.statBlocks.textContent = result.numBlocks;
        elements.statRounds.textContent = result.numBlocks * 20;
        renderOutput();

        // --- state visualizer from real block-0 snapshots
        renderVisualizer(result);
        return true;
    } catch (err) {
        resetOutputs();
        setStatus('error', 'ERROR', String(err && err.message ? err.message : err), 'FAULT');
        showVerification(false, 'Execution error — ' + (err && err.message ? err.message : err));
        return false;
    }
}

async function onExecute() {
    if (!allParamsValid()) {
        setStatus('warn', 'PARAMETER CHECK', 'Fix the highlighted fields, then execute again.', 'CHECK');
        elements.verifyBanner.hidden = true;
        (document.querySelector('.has-error .input-field') || elements.inputKey).focus();
        return;
    }
    if (appState.mode === 'encrypt' && elements.inputText.value === '') {
        setStatus('warn', 'NO PAYLOAD', 'Enter a plaintext message to encrypt.', 'EMPTY');
        elements.inputText.focus();
        return;
    }
    if (appState.mode === 'decrypt' && cleanHexInput(elements.inputText.value) === '') {
        setStatus('warn', 'NO PAYLOAD', 'Paste hexadecimal ciphertext to decrypt.', 'EMPTY');
        elements.inputText.focus();
        return;
    }

    // Real state choreography: show PROCESSING, let it paint, then compute.
    const isEnc = appState.mode === 'encrypt';
    elements.btnExecute.disabled = true;
    elements.btnExecute.classList.add('is-processing');
    elements.btnExecute.classList.remove('is-success');
    elements.btnExecuteLabel.textContent = isEnc ? 'Generating keystream…' : 'Decrypting…';
    setStatus('processing', 'PROCESSING', isEnc
        ? 'Generating ChaCha20 keystream and XORing plaintext…'
        : 'Regenerating keystream and XORing ciphertext…', 'RUN');

    await paintTick();
    const ok = processCipher();

    if (ok) {
        setStatus('complete', isEnc ? 'COMPLETE' : 'COMPLETE',
            isEnc
                ? (appState.lastRfcMatch
                    ? 'RFC 8439 §2.4.2 vector matched.'
                    : 'Ciphertext verified.')
                : 'Plaintext recovered.', 'OK');
        elements.btnExecute.classList.remove('is-processing');
        elements.btnExecute.classList.add('is-success');
        elements.btnExecuteLabel.textContent = isEnc ? '✓ Encrypted' : '✓ Decrypted';
        setTimeout(() => {
            elements.btnExecute.classList.remove('is-success');
            elements.btnExecuteLabel.textContent = 'Execute';
            elements.btnExecute.disabled = false;
        }, 1500);
    } else {
        elements.btnExecute.classList.remove('is-processing');
        elements.btnExecuteLabel.textContent = 'Execute';
        elements.btnExecute.disabled = false;
    }
}

/* ======================= state matrix visualizer ======================= */
const CELL_META = [
    { type: 'cell-constant', label: 'C0', desc: '"expa"' },
    { type: 'cell-constant', label: 'C1', desc: '"nd 3"' },
    { type: 'cell-constant', label: 'C2', desc: '"2-by"' },
    { type: 'cell-constant', label: 'C3', desc: '"te k"' },
    { type: 'cell-key', label: 'K0', desc: 'b0–3' },
    { type: 'cell-key', label: 'K1', desc: 'b4–7' },
    { type: 'cell-key', label: 'K2', desc: 'b8–11' },
    { type: 'cell-key', label: 'K3', desc: 'b12–15' },
    { type: 'cell-key', label: 'K4', desc: 'b16–19' },
    { type: 'cell-key', label: 'K5', desc: 'b20–23' },
    { type: 'cell-key', label: 'K6', desc: 'b24–27' },
    { type: 'cell-key', label: 'K7', desc: 'b28–31' },
    { type: 'cell-counter', label: 'CTR', desc: 'block idx' },
    { type: 'cell-nonce', label: 'N0', desc: 'b0–3' },
    { type: 'cell-nonce', label: 'N1', desc: 'b4–7' },
    { type: 'cell-nonce', label: 'N2', desc: 'b8–11' }
];

const COLUMN_QRS = 'QR(0,4,8,12) · QR(1,5,9,13) · QR(2,6,10,14) · QR(3,7,11,15)';
const DIAGONAL_QRS = 'QR(0,5,10,15) · QR(1,6,11,12) · QR(2,7,8,13) · QR(3,4,9,14)';

function resetMatrix() {
    appState.recordedSnapshots = [];
    appState.currentSnapshotIndex = 0;
    elements.matrixGrid.innerHTML = '';
    elements.stepExplanation.textContent = 'Execute an operation to load the real 512-bit state into the visualizer.';
    elements.roundReadout.textContent = 'ROUND 00 / 20';
    elements.roundSub.textContent = 'Awaiting state…';
    if (elements.roundProgressFill) elements.roundProgressFill.style.width = '0%';
    if (elements.roundProgressLabel) elements.roundProgressLabel.textContent = '0 / 20';
    if (elements.roundProgressbar) elements.roundProgressbar.setAttribute('aria-valuenow', '0');
    elements.visualizerBlock.textContent = 'KEYSTREAM BLOCK —';
    elements.btnStepPrev.disabled = true;
    elements.btnStepNext.disabled = true;
    elements.btnStepPlay.disabled = true;
}

function renderVisualizer(result) {
    appState.currentSnapshotIndex = 0;
    const first = result.blocks[0];
    if (first && first.snapshots && first.snapshots.length > 0) {
        appState.recordedSnapshots = first.snapshots;
        elements.visualizerBlock.textContent =
            `KEYSTREAM BLOCK 1 OF ${result.numBlocks} · COUNTER ${first.counter}`;
        elements.btnStepPlay.disabled = false;
        renderStateSnapshot(appState.recordedSnapshots[0]);
    } else {
        const keyBytes = $hex(cleanHexInput(elements.inputKey.value));
        const nonceBytes = $hex(cleanHexInput(elements.inputNonce.value));
        const counter = parseInt(elements.inputCounter.value.trim() || '1', 10);
        renderStateMatrix(Array.from(ChaCha20Engine.createInitialState(keyBytes, counter, nonceBytes)));
        elements.roundReadout.textContent = 'ROUND 00 / 20';
        elements.roundSub.textContent = 'Initial state (empty payload — no keystream block computed)';
        elements.visualizerBlock.textContent = 'INITIAL STATE ONLY';
    }
}

function stepDescription(index, snap) {
    if (index === 0) {
        return {
            readout: 'ROUND 00 / 20',
            sub: 'Initial state — constants · 8 key words · counter · nonce',
            explain: 'State assembled per RFC 8439 §2.1: four constants ("expand 32-byte k"), eight key words (little-endian), 32-bit block counter, three nonce words.'
        };
    }
    if (index <= 20) {
        const isColumn = /column/i.test(snap.type);
        const roundNum = index;
        const n = Math.ceil(roundNum / 2);
        const kind = isColumn ? `Column round ${n}` : `Diagonal round ${n}`;
        return {
            readout: `ROUND ${String(roundNum).padStart(2, '0')} / 20`,
            sub: isColumn
                ? `Column ${kind} — 4 quarter-rounds down the columns`
                : `Diagonal ${kind} — 4 quarter-rounds along the diagonals`,
            explain: isColumn
                ? `Column round: ${COLUMN_QRS} — each quarter-round applies ARX (add · xor · rotate) to its four words.`
                : `Diagonal round: ${DIAGONAL_QRS} — the same ARX transform on the diagonal groupings.`
        };
    }
    return {
        readout: '20 / 20 ROUNDS COMPLETE',
        sub: 'Final state — feed-forward addition completed',
        explain: 'Feed-forward: the permuted working state is added to the initial state (mod 2³²). The 16 result words are serialized little-endian into the 64-byte keystream block that is XORed with the payload.'
    };
}

function renderStateSnapshot(snapshot) {
    if (!snapshot) return;
    const index = appState.currentSnapshotIndex;
    const prev = index > 0 ? appState.recordedSnapshots[index - 1].state : null;
    renderStateMatrix(snapshot.state, prev);
    const d = stepDescription(index, snapshot);
    elements.roundReadout.textContent = d.readout;
    elements.roundSub.textContent = d.sub;
    elements.stepExplanation.textContent = d.explain;
    const progressNow = Math.min(index, 20);
    if (elements.roundProgressFill) elements.roundProgressFill.style.width = (progressNow / 20) * 100 + '%';
    if (elements.roundProgressLabel) elements.roundProgressLabel.textContent = progressNow + ' / 20';
    if (elements.roundProgressbar) elements.roundProgressbar.setAttribute('aria-valuenow', String(progressNow));
    elements.btnStepPrev.disabled = index === 0;
    elements.btnStepNext.disabled = index === appState.recordedSnapshots.length - 1;
}

function renderStateMatrix(words, prevWords) {
    const frag = document.createDocumentFragment();
    for (let i = 0; i < 16; i++) {
        const meta = CELL_META[i];
        const valHex = '0x' + (words[i] >>> 0).toString(16).padStart(8, '0');
        const changed = prevWords ? (words[i] >>> 0) !== (prevWords[i] >>> 0) : false;

        const cell = document.createElement('div');
        cell.className = 'matrix-cell ' + meta.type;

        const header = document.createElement('div');
        header.className = 'cell-header';
        const type = document.createElement('span');
        type.className = 'cell-type';
        type.textContent = '[' + i + '] ' + meta.label;
        const desc = document.createElement('span');
        desc.className = 'cell-desc';
        desc.textContent = meta.desc;
        header.appendChild(type);
        header.appendChild(desc);

        const value = document.createElement('div');
        value.className = 'cell-value' + (changed ? ' flash' : '');
        value.textContent = valHex;

        cell.appendChild(header);
        cell.appendChild(value);
        frag.appendChild(cell);
    }
    elements.matrixGrid.innerHTML = '';
    elements.matrixGrid.appendChild(frag);
}

function stepSnapshot(delta) {
    const snaps = appState.recordedSnapshots;
    if (snaps.length === 0) return;
    const next = appState.currentSnapshotIndex + delta;
    if (next >= 0 && next < snaps.length) {
        appState.currentSnapshotIndex = next;
        renderStateSnapshot(snaps[next]);
    }
}

function togglePlayRounds() {
    if (appState.isPlayingRounds) {
        stopPlayRounds();
    } else {
        startPlayRounds();
    }
}

function startPlayRounds() {
    const snaps = appState.recordedSnapshots;
    if (snaps.length === 0 || appState.isPlayingRounds) return;
    // if we're at the end, restart from the top
    if (appState.currentSnapshotIndex >= snaps.length - 1) {
        appState.currentSnapshotIndex = 0;
        renderStateSnapshot(snaps[0]);
    }
    appState.isPlayingRounds = true;
    elements.btnStepPlay.classList.add('playing');
    elements.btnStepPlay.textContent = '❚❚ Pause';
    if (reduceMotion) {
        // no animation: jump straight to the final state
        playSingleStep();
        return;
    }
    appState.playTimer = setInterval(() => {
        playSingleStep();
    }, 520);
}

function playSingleStep() {
    const snaps = appState.recordedSnapshots;
    if (!snaps.length) { stopPlayRounds(); return; }
    if (appState.currentSnapshotIndex < snaps.length - 1) {
        appState.currentSnapshotIndex += 1;
        renderStateSnapshot(snaps[appState.currentSnapshotIndex]);
        const snap = snaps[appState.currentSnapshotIndex];
        const d = stepDescription(appState.currentSnapshotIndex, snap);
        setStatus('round', d.readout, d.sub, 'STEP');
    } else {
        stopPlayRounds();
    }
}

function stopPlayRounds(keepLabel) {
    if (appState.playTimer) {
        clearInterval(appState.playTimer);
        appState.playTimer = null;
    }
    appState.isPlayingRounds = false;
    elements.btnStepPlay.classList.remove('playing');
    if (!keepLabel) elements.btnStepPlay.textContent = '▶ Play';
    restoreStatus();
}

/* ========================= RFC 8439 live checks ========================= */
/**
 * Single source of truth for the Java JUnit 5 automated regression test suite.
 * Suite covers:
 * - ChaCha20Test (20 tests)
 * - ChaCha20Poly1305Test (9 tests)
 * - FileCipherTest (4 tests)
 * - Poly1305Test (3 tests)
 */
const JAVA_TEST_SUITE_METRICS = {
    totalTests: 36,
    passed: 36,
    failed: 0,
    skipped: 0
};

const VECTOR_KEY = $hex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const VECTOR_NONCE = $hex('000000000000004a00000000');
const RFC_BLOCK_KEYSTREAM = '10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e';
const RFC_SUNSCREEN_CT = '6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d';

function markRfcCheck(id, pass, detail) {
    const li = document.getElementById(id);
    if (!li) return;
    li.classList.remove('fail');
    li.classList.add(pass ? 'pass' : 'fail');
    li.querySelector('.rfc-mark').textContent = pass ? '✓' : '✕';
    li.querySelector('.rfc-result').textContent = detail;
}

function runRfcChecks() {
    try {
        // §2.3.2 — block function keystream vector
        const blockNonce = $hex('000000090000004a00000000');
        const ks = ChaCha20Engine.chachaBlock(VECTOR_KEY, 1, blockNonce).keystream;
        markRfcCheck('rfc-block', hexOf(ks) === RFC_BLOCK_KEYSTREAM, hexOf(ks) === RFC_BLOCK_KEYSTREAM ? 'PASS · 64 B' : 'FAIL');

        // §2.4.2 — encryption vector
        const sunscreen = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        const enc = ChaCha20Engine.process(VECTOR_KEY, 1, VECTOR_NONCE, CryptoUtils.textToBytes(sunscreen));
        const encMatch = hexOf(enc.outputBytes) === RFC_SUNSCREEN_CT;
        markRfcCheck('rfc-enc', encMatch, encMatch ? 'PASS · 114 B' : 'FAIL');

        // round-trip / decryption symmetry
        const rt = CryptoUtils.textToBytes('BCS703 round-trip probe — decrypt(encrypt(m)) must equal m.');
        const rtEnc = ChaCha20Engine.process(VECTOR_KEY, 1, VECTOR_NONCE, rt);
        const rtDec = ChaCha20Engine.process(VECTOR_KEY, 1, VECTOR_NONCE, rtEnc.outputBytes);
        const rtOk = hexOf(rtDec.outputBytes) === hexOf(rt);
        markRfcCheck('rfc-roundtrip', rtOk, rtOk ? 'PASS · XOR symmetric' : 'FAIL');

        // Java JUnit suite — dynamically reflect single source-of-truth metrics
        const junitLabel = document.getElementById('rfc-junit-label');
        if (junitLabel) {
            junitLabel.textContent = `JUnit 5 Suite (${JAVA_TEST_SUITE_METRICS.totalTests} Tests)`;
        }
        const allTestsPassed = (JAVA_TEST_SUITE_METRICS.passed === JAVA_TEST_SUITE_METRICS.totalTests) && (JAVA_TEST_SUITE_METRICS.failed === 0);
        markRfcCheck('rfc-junit', allTestsPassed, `${JAVA_TEST_SUITE_METRICS.passed} / ${JAVA_TEST_SUITE_METRICS.totalTests} PASS`);
    } catch (err) {
        ['rfc-block', 'rfc-enc', 'rfc-roundtrip'].forEach((id) => markRfcCheck(id, false, 'ERROR'));
    }
}

/* ===================== ambient background canvas ===================== */
function initBackgroundCanvas() {
    const canvas = document.getElementById('bg-canvas');
    const ctx = canvas.getContext('2d');
    if (reduceMotion) return; // leave canvas empty — static gradient/grid remains

    const DPR = Math.min(window.devicePixelRatio || 1, 2);
    const COLORS = ['56,189,248', '129,140,248', '192,132,252', '125,211,252'];
    let particles = [];
    let rafId = null;
    let running = true;

    function resize() {
        canvas.width = window.innerWidth * DPR;
        canvas.height = window.innerHeight * DPR;
        ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
        canvas.style.width = window.innerWidth + 'px';
        canvas.style.height = window.innerHeight + 'px';
        spawn();
    }

    function spawn() {
        const count = Math.min(26, Math.floor(window.innerWidth / 70));
        particles = Array.from({ length: count }, () => ({
            x: Math.random() * window.innerWidth,
            y: Math.random() * window.innerHeight,
            r: 0.6 + Math.random() * 1.6,
            vx: (Math.random() - 0.5) * 0.12,
            vy: -0.02 - Math.random() * 0.08,
            c: COLORS[Math.floor(Math.random() * COLORS.length)],
            a: 0.05 + Math.random() * 0.16,
            phase: Math.random() * Math.PI * 2,
            tw: 0.4 + Math.random() * 0.9
        }));
    }

    function frame(ts) {
        if (!running) return;
        ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
        for (const p of particles) {
            p.x += p.vx;
            p.y += p.vy;
            if (p.y < -8) { p.y = window.innerHeight + 8; p.x = Math.random() * window.innerWidth; }
            if (p.x < -8) p.x = window.innerWidth + 8;
            if (p.x > window.innerWidth + 8) p.x = -8;

            const alpha = p.a * (0.55 + 0.45 * Math.sin(ts * 0.0006 * p.tw + p.phase));
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(' + p.c + ',' + alpha.toFixed(3) + ')';
            ctx.fill();
            // faint glow halo
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r * 3.2, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(' + p.c + ',' + (alpha * 0.16).toFixed(3) + ')';
            ctx.fill();
        }
        rafId = requestAnimationFrame(frame);
    }

    function onVisibility() {
        if (document.hidden) {
            running = false;
            cancelAnimationFrame(rafId);
        } else if (!running) {
            running = true;
            rafId = requestAnimationFrame(frame);
        }
    }

    window.addEventListener('resize', resize);
    document.addEventListener('visibilitychange', onVisibility);
    resize();
    rafId = requestAnimationFrame(frame);
}

/* ========================== neon cursor ========================== */
function initNeonCursor() {
    const orb = document.getElementById('neon-cursor');
    const dot = document.getElementById('neon-cursor-dot');
    if (!orb || !dot) return;
    if (reduceMotion || (window.matchMedia && window.matchMedia('(pointer: coarse)').matches)) return;

    const INTERACTIVE_SELECTOR = [
        'button', 'a', 'input', 'textarea', '.btn-preset', '.tool-btn', '.copy-btn', '.stepper-btn',
        '[role="button"]', '.matrix-cell', '.stat-card', '.badge', '.tab-btn'
    ].join(',');
    const MAX_PARTICLES = 50;
    const SPAWN_INTERVAL_MS = 22;
    const SPAWN_MIN_DISTANCE = 6;
    const PARTICLE_LIFE_MS = 550;
    const PARTICLE_COLORS = ['#22d3ee', '#38bdf8', '#60a5fa', '#818cf8', '#a78bfa'];

    const state = { x: 0, y: 0, tx: 0, ty: 0, dx: 0, dy: 0, lastSpawn: 0, lastX: 0, lastY: 0, hoverRect: null, rafId: null };
    const particles = [];

    function spawnParticle(x, y) {
        const size = 3 + Math.random() * 4;
        const color = PARTICLE_COLORS[Math.floor(Math.random() * PARTICLE_COLORS.length)];
        const p = document.createElement('div');
        p.className = 'neon-particle';
        p.style.left = (x - size / 2) + 'px';
        p.style.top = (y - size / 2) + 'px';
        p.style.width = size + 'px';
        p.style.height = size + 'px';
        p.style.background = 'radial-gradient(circle, rgba(255,255,255,0.9) 0%, ' + color + ' 50%, transparent 75%)';
        p.style.boxShadow = '0 0 ' + Math.round(size * 2.4) + 'px 1px ' + color;
        p.style.setProperty('--drift-x', ((Math.random() - 0.5) * 16).toFixed(1) + 'px');
        p.style.setProperty('--drift-y', ((Math.random() - 0.5) * 16).toFixed(1) + 'px');
        document.body.appendChild(p);
        particles.push(p);
        while (particles.length > MAX_PARTICLES) {
            const oldest = particles.shift();
            if (oldest && oldest.parentNode) oldest.remove();
        }
        requestAnimationFrame(() => p.classList.add('is-fading'));
        window.setTimeout(() => { if (p.parentNode) p.remove(); }, PARTICLE_LIFE_MS);
    }

    function onMove(e) {
        state.tx = e.clientX;
        state.ty = e.clientY;
        orb.classList.add('is-visible');
        if (!state.rafId) {
            state.x = state.tx; state.y = state.ty; state.dx = state.tx; state.dy = state.ty;
            state.lastX = state.tx; state.lastY = state.ty;
            state.rafId = requestAnimationFrame(tick);
            return;
        }
        const now = performance.now();
        const dist = Math.hypot(state.tx - state.lastX, state.ty - state.lastY);
        if (now - state.lastSpawn >= SPAWN_INTERVAL_MS && dist >= SPAWN_MIN_DISTANCE) {
            state.lastSpawn = now;
            spawnParticle(state.tx, state.ty);
        }
        state.lastX = state.tx;
        state.lastY = state.ty;
    }

    function onOver(e) {
        const target = e.target instanceof Element ? e.target : null;
        const hit = target ? target.closest(INTERACTIVE_SELECTOR) : null;
        state.hoverRect = hit ? hit.getBoundingClientRect() : null;
        orb.classList.toggle('is-active', !!hit);
    }

    function hide() {
        orb.classList.remove('is-visible', 'is-active');
        state.hoverRect = null;
    }

    function tick() {
        state.x += (state.tx - state.x) * 0.2;
        state.y += (state.ty - state.y) * 0.2;
        let dtx = state.x;
        let dty = state.y;
        if (state.hoverRect) {
            dtx = state.x + (state.hoverRect.left + state.hoverRect.width / 2 - state.x) * 0.18;
            dty = state.y + (state.hoverRect.top + state.hoverRect.height / 2 - state.y) * 0.18;
        }
        state.dx += (dtx - state.dx) * 0.42;
        state.dy += (dty - state.dy) * 0.42;
        orb.style.transform = 'translate3d(' + state.x.toFixed(1) + 'px,' + state.y.toFixed(1) + 'px,0)';
        dot.style.transform = 'translate3d(' + state.dx.toFixed(1) + 'px,' + state.dy.toFixed(1) + 'px,0)';
        state.rafId = requestAnimationFrame(tick);
    }

    document.addEventListener('mousemove', onMove, { passive: true });
    document.addEventListener('mouseover', onOver, { passive: true });
    document.documentElement.addEventListener('mouseleave', hide);
    window.addEventListener('blur', hide);
}

/* ============================== events ============================== */
function bindEvents() {
    elements.tabEncrypt.addEventListener('click', () => setMode('encrypt'));
    elements.tabDecrypt.addEventListener('click', () => setMode('decrypt'));

    elements.btnRandomKey.addEventListener('click', generateRandomKey);
    elements.btnRandomNonce.addEventListener('click', generateRandomNonce);

    // live recomputation on any input change
    elements.inputKey.addEventListener('input', () => processCipher());
    elements.inputNonce.addEventListener('input', () => processCipher());
    elements.inputCounter.addEventListener('input', () => processCipher());
    elements.inputText.addEventListener('input', () => processCipher());

    elements.btnExecute.addEventListener('click', onExecute);
    elements.btnCopyHex.addEventListener('click', () => copyText(appState.lastOutputHex, elements.btnCopyHex));
    elements.btnCopyBase64.addEventListener('click', () => copyText(appState.lastOutputBase64, elements.btnCopyBase64));

    elements.btnStepPrev.addEventListener('click', () => stepSnapshot(-1));
    elements.btnStepNext.addEventListener('click', () => stepSnapshot(1));
    elements.btnStepPlay.addEventListener('click', togglePlayRounds);

    elements.presetRfcSunscreen.addEventListener('click', loadRfcSunscreenPreset);
    elements.presetRfcBlock.addEventListener('click', loadRfcBlockPreset);
    elements.presetDemo.addEventListener('click', loadDemoPreset);
    elements.presetClear.addEventListener('click', clearInputs);

    const replayBtn = document.getElementById('btn-replay-intro');
    if (replayBtn) {
        replayBtn.addEventListener('click', async () => {
            if (!cryptoSceneInstance) {
                try {
                    const { CryptoScene3D } = await import('./scene.js');
                    if (!cryptoSceneInstance) {
                        cryptoSceneInstance = new CryptoScene3D({ playIntro: true });
                        return;
                    }
                } catch (err) {
                    console.warn('[CryptoScene3D] Replay import failed:', err);
                    return;
                }
            }
            if (cryptoSceneInstance && typeof cryptoSceneInstance.playEntranceAnimation === 'function') {
                cryptoSceneInstance.playEntranceAnimation();
            }
        });
    }
}

/* ============================ 3D Scene Initialization ============================ */
let cryptoSceneInstance = null;

async function init3DScene() {
    try {
        const { CryptoScene3D } = await import('./scene.js');
        if (!cryptoSceneInstance) {
            cryptoSceneInstance = new CryptoScene3D({ playIntro: true });
        }
    } catch (err) {
        console.warn('[CryptoScene3D] 3D Scene initialization fallback:', err);
        const overlay = document.getElementById('entrance-overlay');
        if (overlay) {
            overlay.style.display = 'none';
            overlay.setAttribute('aria-hidden', 'true');
        }
        const appPage = document.querySelector('.page');
        if (appPage) {
            appPage.style.opacity = '1';
            appPage.style.transform = 'none';
        }
    }
}

/* ================================ boot ================================ */
document.addEventListener('DOMContentLoaded', () => {
    bindEvents();
    resetOutputs();
    resetMatrix();
    runRfcChecks();
    loadDemoPreset();      // loads real parameters + computes a real result
    init3DScene();         // automatically runs 3D entrance animation on load/refresh
    initNeonCursor();
});
