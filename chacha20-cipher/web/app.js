/**
 * ChaCha20 Stream Cipher Interactive Frontend Application
 */

// Application State
let appState = {
    mode: 'encrypt', // 'encrypt' | 'decrypt'
    currentSnapshotIndex: 0,
    recordedSnapshots: [],
    lastProcessedResult: null,
    isPlayingRounds: false,
    playTimer: null
};

// DOM Elements
const elements = {
    // Mode tabs
    tabEncrypt: document.getElementById('tab-encrypt'),
    tabDecrypt: document.getElementById('tab-decrypt'),
    modeBadge: document.getElementById('mode-badge'),

    // Input fields
    inputKey: document.getElementById('input-key'),
    inputNonce: document.getElementById('input-nonce'),
    inputCounter: document.getElementById('input-counter'),
    inputText: document.getElementById('input-text'),
    inputLabel: document.getElementById('input-label'),

    // Buttons
    btnRandomKey: document.getElementById('btn-random-key'),
    btnRandomNonce: document.getElementById('btn-random-nonce'),
    btnExecute: document.getElementById('btn-execute'),
    btnCopyOutput: document.getElementById('btn-copy-output'),

    // Outputs
    outputBox: document.getElementById('output-result'),
    outputSecondary: document.getElementById('output-secondary'),
    secondaryLabel: document.getElementById('secondary-label'),
    verifyBanner: document.getElementById('verify-banner'),

    // Stats
    statBytes: document.getElementById('stat-bytes'),
    statBlocks: document.getElementById('stat-blocks'),
    statRounds: document.getElementById('stat-rounds'),

    // State Matrix visualizer
    matrixGrid: document.getElementById('matrix-grid'),

    // Stepper controls
    btnStepPrev: document.getElementById('btn-step-prev'),
    btnStepNext: document.getElementById('btn-step-next'),
    btnStepPlay: document.getElementById('btn-step-play'),
    stepperInfo: document.getElementById('stepper-info'),

    // Preset buttons
    presetRfcSunscreen: document.getElementById('preset-rfc-sunscreen'),
    presetRfcBlock: document.getElementById('preset-rfc-block'),
    presetDemo: document.getElementById('preset-demo'),
    presetClear: document.getElementById('preset-clear')
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
    bindEvents();
    loadDemoPreset();
    processCipher();
});

function bindEvents() {
    // Mode toggles
    elements.tabEncrypt.addEventListener('click', () => setMode('encrypt'));
    elements.tabDecrypt.addEventListener('click', () => setMode('decrypt'));

    // Random generators
    elements.btnRandomKey.addEventListener('click', generateRandomKey);
    elements.btnRandomNonce.addEventListener('click', generateRandomNonce);

    // Live execution triggers
    elements.inputKey.addEventListener('input', () => processCipher());
    elements.inputNonce.addEventListener('input', () => processCipher());
    elements.inputCounter.addEventListener('input', () => processCipher());
    elements.inputText.addEventListener('input', () => processCipher());
    elements.btnExecute.addEventListener('click', () => processCipher());

    // Copy button
    elements.btnCopyOutput.addEventListener('click', copyOutputToClipboard);

    // Stepper buttons
    elements.btnStepPrev.addEventListener('click', () => stepSnapshot(-1));
    elements.btnStepNext.addEventListener('click', () => stepSnapshot(1));
    elements.btnStepPlay.addEventListener('click', togglePlayRounds);

    // Presets
    elements.presetRfcSunscreen.addEventListener('click', loadRfcSunscreenPreset);
    elements.presetRfcBlock.addEventListener('click', loadRfcBlockPreset);
    elements.presetDemo.addEventListener('click', loadDemoPreset);
    elements.presetClear.addEventListener('click', clearInputs);
}

function setMode(mode) {
    appState.mode = mode;
    if (mode === 'encrypt') {
        elements.tabEncrypt.classList.add('active');
        elements.tabDecrypt.classList.remove('active');
        elements.modeBadge.textContent = 'Encryption Mode (Text -> Hex)';
        elements.inputLabel.textContent = 'Plaintext (UTF-8 / ASCII)';
        elements.secondaryLabel.textContent = 'Decrypted Verification Preview';
        elements.btnExecute.innerHTML = '<span>🔒 Encrypt Plaintext</span>';
    } else {
        elements.tabDecrypt.classList.add('active');
        elements.tabEncrypt.classList.remove('active');
        elements.modeBadge.textContent = 'Decryption Mode (Hex -> Text)';
        elements.inputLabel.textContent = 'Ciphertext (Hexadecimal)';
        elements.secondaryLabel.textContent = 'Recovered Plaintext (UTF-8)';
        elements.btnExecute.innerHTML = '<span>🔓 Decrypt Ciphertext</span>';
    }
    processCipher();
}

function generateRandomKey() {
    let keyBytes = CryptoUtils.randomBytes(32);
    elements.inputKey.value = CryptoUtils.bytesToHex(keyBytes);
    processCipher();
}

function generateRandomNonce() {
    let nonceBytes = CryptoUtils.randomBytes(12);
    elements.inputNonce.value = CryptoUtils.bytesToHex(nonceBytes);
    processCipher();
}

function clearInputs() {
    elements.inputKey.value = '';
    elements.inputNonce.value = '';
    elements.inputCounter.value = '1';
    elements.inputText.value = '';
    elements.outputBox.textContent = '';
    elements.outputSecondary.textContent = '';
    elements.verifyBanner.style.display = 'none';
}

function loadRfcSunscreenPreset() {
    setMode('encrypt');
    elements.inputKey.value = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
    elements.inputNonce.value = '000000000000004a00000000';
    elements.inputCounter.value = '1';
    elements.inputText.value = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    processCipher();
}

function loadRfcBlockPreset() {
    setMode('encrypt');
    elements.inputKey.value = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
    elements.inputNonce.value = '000000090000004a00000000';
    elements.inputCounter.value = '1';
    elements.inputText.value = 'ChaCha20 64-byte block generation test (RFC 8439 Section 2.3.2)';
    processCipher();
}

function loadDemoPreset() {
    setMode('encrypt');
    elements.inputKey.value = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
    elements.inputNonce.value = '000000000000004a00000000';
    elements.inputCounter.value = '1';
    elements.inputText.value = 'Cryptography & Network Security (BCS703): ChaCha20 Stream Cipher Implementation';
    processCipher();
}

function processCipher() {
    try {
        let keyHex = elements.inputKey.value.trim();
        let nonceHex = elements.inputNonce.value.trim();
        let counterVal = parseInt(elements.inputCounter.value.trim() || '1', 10);
        let textInput = elements.inputText.value;

        if (!keyHex || !nonceHex) {
            elements.verifyBanner.style.display = 'none';
            return;
        }

        let keyBytes = CryptoUtils.hexToBytes(keyHex);
        let nonceBytes = CryptoUtils.hexToBytes(nonceHex);

        if (keyBytes.length !== 32) {
            showError(`Key must be 32 bytes (64 hex characters). Currently ${keyBytes.length} bytes.`);
            return;
        }
        if (nonceBytes.length !== 12) {
            showError(`Nonce must be 12 bytes (24 hex characters). Currently ${nonceBytes.length} bytes.`);
            return;
        }

        let inputBytes;
        if (appState.mode === 'encrypt') {
            inputBytes = CryptoUtils.textToBytes(textInput);
        } else {
            inputBytes = CryptoUtils.hexToBytes(textInput);
        }

        // Execute ChaCha20
        let result = ChaCha20Engine.process(keyBytes, counterVal, nonceBytes, inputBytes);
        appState.lastProcessedResult = result;

        // Display results
        let outputHex = CryptoUtils.bytesToHex(result.outputBytes);
        elements.outputBox.textContent = outputHex || '(empty)';

        if (appState.mode === 'encrypt') {
            // Verify round trip decryption
            let decrypted = ChaCha20Engine.process(keyBytes, counterVal, nonceBytes, result.outputBytes);
            let decryptedText = CryptoUtils.bytesToText(decrypted.outputBytes);
            elements.outputSecondary.textContent = decryptedText;

            // Check against RFC 8439 Section 2.4.2 if applicable
            let rfcExpected = '6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d';
            if (outputHex.toLowerCase() === rfcExpected) {
                showVerification(true, 'RFC 8439 Section 2.4.2 Official Test Vector Match: PASS!');
            } else if (textInput.length > 0 && decryptedText === textInput) {
                showVerification(true, 'Round-Trip Integrity Verified: Decrypt(Encrypt(Plaintext)) == Plaintext (PASS)');
            } else {
                elements.verifyBanner.style.display = 'none';
            }
        } else {
            let recoveredText = CryptoUtils.bytesToText(result.outputBytes);
            elements.outputSecondary.textContent = recoveredText;
            showVerification(true, 'Decryption Complete: Successfully processed ciphertext stream');
        }

        // Update Stats
        elements.statBytes.textContent = inputBytes.length;
        elements.statBlocks.textContent = result.numBlocks;
        elements.statRounds.textContent = result.numBlocks * 20;

        // Update State Visualizer snapshots
        if (result.blocks.length > 0 && result.blocks[0].snapshots) {
            appState.recordedSnapshots = result.blocks[0].snapshots;
            appState.currentSnapshotIndex = 0;
            renderStateSnapshot(appState.recordedSnapshots[0]);
        } else {
            // Render initial state directly
            let initialState = ChaCha20Engine.createInitialState(keyBytes, counterVal, nonceBytes);
            renderStateMatrix(Array.from(initialState), 'Initial 512-bit State Matrix');
        }

    } catch (e) {
        showError(e.message);
    }
}

function showVerification(pass, msg) {
    elements.verifyBanner.style.display = 'flex';
    elements.verifyBanner.className = pass ? 'verify-banner verify-pass' : 'verify-banner verify-fail';
    elements.verifyBanner.innerHTML = `<span>${pass ? '✅' : '❌'}</span><span>${msg}</span>`;
}

function showError(msg) {
    elements.verifyBanner.style.display = 'flex';
    elements.verifyBanner.className = 'verify-banner verify-fail';
    elements.verifyBanner.innerHTML = `<span>⚠️</span><span>${msg}</span>`;
}

function renderStateSnapshot(snapshot) {
    if (!snapshot) return;
    renderStateMatrix(snapshot.state, snapshot.type);
    elements.stepperInfo.textContent = `Snapshot: ${snapshot.type} (${appState.currentSnapshotIndex + 1}/${appState.recordedSnapshots.length})`;
    elements.btnStepPrev.disabled = (appState.currentSnapshotIndex === 0);
    elements.btnStepNext.disabled = (appState.currentSnapshotIndex === appState.recordedSnapshots.length - 1);
}

function renderStateMatrix(words, label) {
    elements.matrixGrid.innerHTML = '';
    const cellMetadata = [
        { type: 'cell-constant', label: 'Constant (c0)', desc: '"expa"' },
        { type: 'cell-constant', label: 'Constant (c1)', desc: '"nd 3"' },
        { type: 'cell-constant', label: 'Constant (c2)', desc: '"2-by"' },
        { type: 'cell-constant', label: 'Constant (c3)', desc: '"te k"' },
        { type: 'cell-key', label: 'Key (k0)', desc: 'Bytes 0..3' },
        { type: 'cell-key', label: 'Key (k1)', desc: 'Bytes 4..7' },
        { type: 'cell-key', label: 'Key (k2)', desc: 'Bytes 8..11' },
        { type: 'cell-key', label: 'Key (k3)', desc: 'Bytes 12..15' },
        { type: 'cell-key', label: 'Key (k4)', desc: 'Bytes 16..19' },
        { type: 'cell-key', label: 'Key (k5)', desc: 'Bytes 20..23' },
        { type: 'cell-key', label: 'Key (k6)', desc: 'Bytes 24..27' },
        { type: 'cell-key', label: 'Key (k7)', desc: 'Bytes 28..31' },
        { type: 'cell-counter', label: 'Counter (c)', desc: 'Block index' },
        { type: 'cell-nonce', label: 'Nonce (n0)', desc: 'Bytes 0..3' },
        { type: 'cell-nonce', label: 'Nonce (n1)', desc: 'Bytes 4..7' },
        { type: 'cell-nonce', label: 'Nonce (n2)', desc: 'Bytes 8..11' }
    ];

    for (let i = 0; i < 16; i++) {
        let meta = cellMetadata[i];
        let valHex = '0x' + (words[i] >>> 0).toString(16).padStart(8, '0');
        let cell = document.createElement('div');
        cell.className = `matrix-cell ${meta.type}`;
        cell.innerHTML = `
            <div class="cell-header">
                <span class="cell-type">[${i}] ${meta.label}</span>
                <span class="cell-desc">${meta.desc}</span>
            </div>
            <div class="cell-value">${valHex}</div>
        `;
        elements.matrixGrid.appendChild(cell);
    }
}

function stepSnapshot(delta) {
    let nextIdx = appState.currentSnapshotIndex + delta;
    if (nextIdx >= 0 && nextIdx < appState.recordedSnapshots.length) {
        appState.currentSnapshotIndex = nextIdx;
        renderStateSnapshot(appState.recordedSnapshots[appState.currentSnapshotIndex]);
    }
}

function togglePlayRounds() {
    if (appState.isPlayingRounds) {
        clearInterval(appState.playTimer);
        appState.isPlayingRounds = false;
        elements.btnStepPlay.textContent = '▶ Play';
    } else {
        appState.isPlayingRounds = true;
        elements.btnStepPlay.textContent = '⏸ Pause';
        appState.playTimer = setInterval(() => {
            if (appState.currentSnapshotIndex < appState.recordedSnapshots.length - 1) {
                stepSnapshot(1);
            } else {
                appState.currentSnapshotIndex = 0;
                stepSnapshot(0);
            }
        }, 500);
    }
}

function copyOutputToClipboard() {
    let text = elements.outputBox.textContent;
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
        let originalText = elements.btnCopyOutput.textContent;
        elements.btnCopyOutput.textContent = 'Copied!';
        setTimeout(() => {
            elements.btnCopyOutput.textContent = originalText;
        }, 1500);
    });
}
