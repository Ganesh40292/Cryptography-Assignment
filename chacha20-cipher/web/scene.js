/**
 * CryptoScene3D — Three.js + GSAP Living Cryptographic State & Particle Field
 *
 * Implements:
 * 1. 3D Cinematic Entrance Animation (~3.5 seconds):
 *    - Stage 1: Dark start with central luminous seed particle.
 *    - Stage 2: 16 particles organize into 4x4 state matrix in 3D perspective.
 *    - Stage 3: Progressive connecting lines form between row/column neighbors.
 *    - Stage 4: Gentle 3D perspective rotation (yaw/pitch) with floating depth.
 *    - Stage 5: Computational pulse traveling through ARX column/diagonal edges.
 *    - Stage 6: Elegant typography reveal ("CHACHA20 CIPHERFORGE — Interactive ARX Cryptographic Engine").
 *    - Stage 7: Smooth camera pushback / fade-out into ambient background layer while main UI fades in.
 *
 * 2. Ambient Background ("Cryptographic Particle Field"):
 *    - 16-node 4x4 state matrix gently floating in deep 3D space with subtle ARX energy pulses.
 *    - Ambient data particles slowly drifting with computational depth.
 *    - Floating hexadecimal data glyphs with low opacity (ambient machine data).
 *    - Interactive mouse parallax with smooth damping.
 *    - Graceful WebGL fallback if Three.js or WebGL is not supported.
 *    - Full reduced-motion compliance (`prefers-reduced-motion: reduce`).
 *    - Replay entrance capability via header replay button.
 */

import * as THREE from 'three';
import gsap from 'gsap';

export class CryptoScene3D {
    constructor(options = {}) {
        this.options = options;
        this.container = document.getElementById('three-canvas-container');
        this.overlay = document.getElementById('entrance-overlay');
        this.appPage = document.querySelector('.page');
        this.btnReplay = document.getElementById('btn-replay-intro');
        this.btnSkip = document.getElementById('btn-skip-intro');

        this.reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        this.scene = null;
        this.camera = null;
        this.renderer = null;
        this.rafId = null;
        this.isRunning = false;

        // 3D Objects
        this.matrixGroup = null;
        this.nodeMeshes = [];
        this.nodePositions = []; // Target 4x4 positions
        this.lineSegments = null;
        this.pulseParticles = null;
        this.ambientField = null;
        this.hexSprites = [];

        // ARX Cryptographic Reactor Forge Rings
        this.arxGroup = null;
        this.arxRingAdd = null;
        this.arxRingRot = null;
        this.arxRingXor = null;
        this.shockwave = null;

        // Animation / State
        this.entranceTimeline = null;
        this.mouse = { x: 0, y: 0, targetX: 0, targetY: 0 };
        this.startTime = performance.now();
        window.cryptoScene = this;

        this.init(options);
    }

    init(options = {}) {
        if (!this.container) return;

        // Check WebGL availability
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) throw new Error('WebGL not supported');
        } catch (e) {
            console.warn('[CryptoScene3D] WebGL not available, utilizing CSS fallback background.');
            this.fallbackToCss();
            return;
        }

        this.setupScene();
        this.createMatrixStructure();
        this.createArxForge();
        this.createAmbientField();
        this.createHexFragments();
        this.bindEvents();

        this.startLoop();

        if (options && options.playIntro && !this.reduceMotion) {
            this.playEntranceAnimation();
        } else {
            this.skipIntroInstant();
        }
    }

    setupScene() {
        const width = window.innerWidth;
        const height = window.innerHeight;

        this.scene = new THREE.Scene();
        this.scene.fog = new THREE.FogExp2(0x040711, 0.022);

        this.camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
        this.camera.position.set(0, 0, 18);

        this.renderer = new THREE.WebGLRenderer({
            antialias: true,
            alpha: true,
            powerPreference: 'high-performance'
        });
        this.renderer.setSize(width, height);
        this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
        this.renderer.setClearColor(0x040711, 0);

        this.container.appendChild(this.renderer.domElement);
    }

    createMatrixStructure() {
        this.matrixGroup = new THREE.Group();
        this.scene.add(this.matrixGroup);

        // 4x4 Grid geometry setup
        // ChaCha20 state has 16 words:
        // Row 0: Constants (Amber glow)
        // Row 1 & 2: Key (Indigo/Blue glow)
        // Row 3: Counter + Nonce (Rose & Cyan glow)
        const SPACING = 2.0;
        const OFFSET = (3 * SPACING) / 2;

        const sphereGeo = new THREE.SphereGeometry(0.16, 16, 16);

        const rowColors = [
            0xfbbf24, // Constants: Amber
            0x60a5fa, // Key 0..3: Blue
            0x818cf8, // Key 4..7: Indigo
            0x22d3ee  // Counter & Nonce: Cyan
        ];

        this.nodeMeshes = [];
        this.nodePositions = [];

        // Create glowing sprite texture for nodes
        const glowCanvas = document.createElement('canvas');
        glowCanvas.width = 64;
        glowCanvas.height = 64;
        const gctx = glowCanvas.getContext('2d');
        const grad = gctx.createRadialGradient(32, 32, 0, 32, 32, 30);
        grad.addColorStop(0, 'rgba(255,255,255,1)');
        grad.addColorStop(0.3, 'rgba(34,211,238,0.8)');
        grad.addColorStop(0.7, 'rgba(99,102,241,0.2)');
        grad.addColorStop(1, 'rgba(0,0,0,0)');
        gctx.fillStyle = grad;
        gctx.fillRect(0, 0, 64, 64);
        const glowTex = new THREE.CanvasTexture(glowCanvas);

        for (let row = 0; row < 4; row++) {
            for (let col = 0; col < 4; col++) {
                const index = row * 4 + col;
                const tx = col * SPACING - OFFSET;
                const ty = -(row * SPACING - OFFSET);
                // Slight initial Z variation for 3D depth
                const tz = ((row + col) % 2 === 0 ? 0.35 : -0.35);

                this.nodePositions.push({ x: tx, y: ty, z: tz });

                const mat = new THREE.MeshBasicMaterial({
                    color: rowColors[row],
                    transparent: true,
                    opacity: 0.95
                });
                const mesh = new THREE.Mesh(sphereGeo, mat);

                // Add outer aura sprite
                const spriteMat = new THREE.SpriteMaterial({
                    map: glowTex,
                    color: rowColors[row],
                    transparent: true,
                    opacity: 0.65,
                    blending: THREE.AdditiveBlending
                });
                const sprite = new THREE.Sprite(spriteMat);
                sprite.scale.set(1.1, 1.1, 1.0);
                mesh.add(sprite);

                // Start near center during entrance initialization
                mesh.position.set(0, 0, 0);
                mesh.scale.set(0, 0, 0);

                // Calculate 3D orbital spawn positions for dynamic convergence
                const orbitAngle = (index / 16) * Math.PI * 4.0;
                const orbitRadius = 6.8 + (index % 4) * 0.9;

                mesh.userData = {
                    baseX: tx,
                    baseY: ty,
                    baseZ: tz,
                    orbitX: Math.cos(orbitAngle) * orbitRadius,
                    orbitY: Math.sin(orbitAngle) * (orbitRadius * 0.65),
                    orbitZ: -5 + (index / 15) * 10,
                    row,
                    col,
                    index
                };

                this.matrixGroup.add(mesh);
                this.nodeMeshes.push(mesh);
            }
        }

        // Connecting lines between row and column neighbors
        const lineCoords = [];
        for (let r = 0; r < 4; r++) {
            for (let c = 0; c < 4; c++) {
                const i = r * 4 + c;
                // Horizontal connection
                if (c < 3) {
                    const right = r * 4 + (c + 1);
                    lineCoords.push(this.nodePositions[i], this.nodePositions[right]);
                }
                // Vertical connection
                if (r < 3) {
                    const down = (r + 1) * 4 + c;
                    lineCoords.push(this.nodePositions[i], this.nodePositions[down]);
                }
            }
        }

        const lineGeo = new THREE.BufferGeometry();
        const positions = new Float32Array(lineCoords.length * 3);
        for (let i = 0; i < lineCoords.length; i++) {
            positions[i * 3] = lineCoords[i].x;
            positions[i * 3 + 1] = lineCoords[i].y;
            positions[i * 3 + 2] = lineCoords[i].z;
        }
        lineGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));

        const lineMat = new THREE.LineBasicMaterial({
            color: 0x38bdf8,
            transparent: true,
            opacity: 0.0,
            blending: THREE.AdditiveBlending
        });

        this.lineSegments = new THREE.LineSegments(lineGeo, lineMat);
        this.matrixGroup.add(this.lineSegments);
    }

    createArxForge() {
        this.arxGroup = new THREE.Group();
        this.scene.add(this.arxGroup);

        // Ring 1: Addition [A] (Amber Gold)
        const geoAdd = new THREE.TorusGeometry(3.6, 0.048, 16, 100);
        const matAdd = new THREE.MeshBasicMaterial({
            color: 0xfbbf24,
            transparent: true,
            opacity: 0,
            blending: THREE.AdditiveBlending
        });
        this.arxRingAdd = new THREE.Mesh(geoAdd, matAdd);
        this.arxRingAdd.rotation.x = Math.PI / 4;
        this.arxGroup.add(this.arxRingAdd);

        // Ring 2: Rotation [R] (Electric Violet / Indigo)
        const geoRot = new THREE.TorusGeometry(2.6, 0.044, 16, 90);
        const matRot = new THREE.MeshBasicMaterial({
            color: 0xa78bfa,
            transparent: true,
            opacity: 0,
            blending: THREE.AdditiveBlending
        });
        this.arxRingRot = new THREE.Mesh(geoRot, matRot);
        this.arxRingRot.rotation.x = -Math.PI / 5;
        this.arxRingRot.rotation.y = Math.PI / 6;
        this.arxGroup.add(this.arxRingRot);

        // Ring 3: XOR [X] (Cyber Cyan Core)
        const geoXor = new THREE.TorusGeometry(1.6, 0.042, 16, 80);
        const matXor = new THREE.MeshBasicMaterial({
            color: 0x22d3ee,
            transparent: true,
            opacity: 0,
            blending: THREE.AdditiveBlending
        });
        this.arxRingXor = new THREE.Mesh(geoXor, matXor);
        this.arxRingXor.rotation.y = Math.PI / 4;
        this.arxGroup.add(this.arxRingXor);

        // 20-Round ARX Computational Shockwave
        const geoShock = new THREE.RingGeometry(0.1, 0.45, 48);
        const matShock = new THREE.MeshBasicMaterial({
            color: 0x67e8f9,
            transparent: true,
            opacity: 0,
            side: THREE.DoubleSide,
            blending: THREE.AdditiveBlending
        });
        this.shockwave = new THREE.Mesh(geoShock, matShock);
        this.shockwave.rotation.x = -Math.PI / 2;
        this.arxGroup.add(this.shockwave);
    }

    createAmbientField() {
        // Computational particle field surrounding the cryptographic matrix
        const count = 320;
        const geo = new THREE.BufferGeometry();
        const positions = new Float32Array(count * 3);
        const scales = new Float32Array(count);

        for (let i = 0; i < count; i++) {
            positions[i * 3] = (Math.random() - 0.5) * 36;
            positions[i * 3 + 1] = (Math.random() - 0.5) * 26;
            positions[i * 3 + 2] = (Math.random() - 0.5) * 30 - 4;
            scales[i] = Math.random() * 0.8 + 0.2;
        }

        geo.setAttribute('position', new THREE.BufferAttribute(positions, 3));

        // Canvas point texture for subtle circular particles
        const pCanvas = document.createElement('canvas');
        pCanvas.width = 32;
        pCanvas.height = 32;
        const pctx = pCanvas.getContext('2d');
        const pgrad = pctx.createRadialGradient(16, 16, 0, 16, 16, 15);
        pgrad.addColorStop(0, 'rgba(255,255,255,0.9)');
        pgrad.addColorStop(0.4, 'rgba(56,189,248,0.6)');
        pgrad.addColorStop(1, 'rgba(0,0,0,0)');
        pctx.fillStyle = pgrad;
        pctx.fillRect(0, 0, 32, 32);
        const pTex = new THREE.CanvasTexture(pCanvas);

        const mat = new THREE.PointsMaterial({
            size: 0.42,
            map: pTex,
            transparent: true,
            opacity: 0.35,
            blending: THREE.AdditiveBlending,
            depthWrite: false
        });

        this.ambientField = new THREE.Points(geo, mat);
        this.scene.add(this.ambientField);
    }

    createHexFragments() {
        // Ambient low-contrast floating hexadecimal fragments
        const fragments = ['6e2e', '359a', '0f13', 'a806', '1ae1', '7f3c', 'b512', 'c7d1', 'e97e', '4581', 'ea2a', 'cb1c'];
        this.hexSprites = [];

        fragments.forEach((hex, i) => {
            const canvas = document.createElement('canvas');
            canvas.width = 128;
            canvas.height = 64;
            const ctx = canvas.getContext('2d');
            ctx.font = 'bold 26px "JetBrains Mono", monospace';
            ctx.fillStyle = 'rgba(34, 211, 238, 0.45)';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(hex, 64, 32);

            const tex = new THREE.CanvasTexture(canvas);
            const spriteMat = new THREE.SpriteMaterial({
                map: tex,
                transparent: true,
                opacity: 0.22,
                blending: THREE.AdditiveBlending
            });
            const sprite = new THREE.Sprite(spriteMat);
            sprite.scale.set(1.6, 0.8, 1);

            sprite.position.set(
                (Math.random() - 0.5) * 20,
                (Math.random() - 0.5) * 14,
                (Math.random() - 0.5) * 10 - 2
            );

            sprite.userData = {
                baseY: sprite.position.y,
                speed: 0.2 + Math.random() * 0.3,
                phase: Math.random() * Math.PI * 2
            };

            this.scene.add(sprite);
            this.hexSprites.push(sprite);
        });
    }

    playEntranceAnimation() {
        if (!this.overlay) return;

        this.overlay.removeAttribute('aria-hidden');
        this.overlay.style.display = 'flex';
        this.overlay.style.opacity = '1';
        this.overlay.style.pointerEvents = 'all';

        const introSeed = document.getElementById('intro-seed');
        const introBadge = document.getElementById('intro-badge');
        const introTitle = document.getElementById('intro-title');
        const introSub = document.getElementById('intro-sub');
        const introStream = document.getElementById('intro-status-stream');

        if (introSeed) gsap.set(introSeed, { opacity: 0, scale: 0.2 });
        if (introBadge) gsap.set(introBadge, { opacity: 0, y: 10 });
        if (introTitle) gsap.set(introTitle, { opacity: 0, y: 14 });
        if (introSub) gsap.set(introSub, { opacity: 0, y: 10 });
        if (introStream) gsap.set(introStream, { opacity: 0, y: 8 });

        if (this.appPage) {
            this.appPage.style.opacity = '0';
            this.appPage.style.transform = 'translateY(24px)';
        }

        if (this.entranceTimeline) {
            this.entranceTimeline.kill();
        }

        // Setup Camera & 3D Objects
        this.camera.position.set(0, 0, 9);
        this.matrixGroup.position.set(0, 0, 0);
        this.matrixGroup.rotation.set(0, 0, 0);

        if (this.arxGroup) {
            this.arxGroup.position.set(0, 0, 0);
            this.arxGroup.scale.set(1, 1, 1);
            this.arxRingAdd.material.opacity = 0;
            this.arxRingRot.material.opacity = 0;
            this.arxRingXor.material.opacity = 0;
            this.shockwave.material.opacity = 0;
            this.shockwave.scale.set(1, 1, 1);
        }

        // Place nodes in deep orbital space
        this.nodeMeshes.forEach((mesh) => {
            mesh.position.set(mesh.userData.orbitX, mesh.userData.orbitY, mesh.userData.orbitZ);
            mesh.scale.set(0.01, 0.01, 0.01);
        });

        if (this.lineSegments) {
            this.lineSegments.material.opacity = 0;
        }

        const tl = gsap.timeline({
            onComplete: () => {
                this.transitionToMainApp();
            }
        });
        this.entranceTimeline = tl;

        // --- STAGE 1: ARX Quantum Core Ignition ---
        tl.to(introSeed, {
            opacity: 1,
            scale: 2.2,
            duration: 0.55,
            ease: 'power2.out'
        });

        // ARX concentric rings illuminate and accelerate counter-spinning
        if (this.arxGroup) {
            tl.to([this.arxRingAdd.material, this.arxRingRot.material, this.arxRingXor.material], {
                opacity: 0.85,
                duration: 0.5,
                stagger: 0.08,
                ease: 'power2.out'
            }, '<+0.1');

            tl.to(this.arxRingAdd.rotation, { z: Math.PI * 2, duration: 2.2, ease: 'power1.inOut' }, '<');
            tl.to(this.arxRingRot.rotation, { x: -Math.PI * 2, duration: 2.0, ease: 'power1.inOut' }, '<');
            tl.to(this.arxRingXor.rotation, { y: Math.PI * 2, duration: 2.4, ease: 'power1.inOut' }, '<');
        }

        // --- STAGE 2: 512-Bit Matrix Spiral Convergence ---
        tl.to(introSeed, {
            opacity: 0,
            scale: 0.4,
            duration: 0.35,
            ease: 'power2.in'
        }, '0.65');

        // Master sync label for 16-word matrix convergence (starts with seed compression)
        tl.addLabel('matrixConvergence', '0.65');

        // All 16 words stream inward from 3D orbits into the 4x4 matrix
        this.nodeMeshes.forEach((mesh, idx) => {
            const delay = idx * 0.032;
            tl.to(mesh.position, {
                x: mesh.userData.baseX,
                y: mesh.userData.baseY,
                z: mesh.userData.baseZ,
                duration: 0.9,
                ease: 'power3.out'
            }, `matrixConvergence+=${delay}`);

            tl.to(mesh.scale, {
                x: 1.25,
                y: 1.25,
                z: 1.25,
                duration: 0.65,
                ease: 'back.out(2.2)'
            }, `matrixConvergence+=${delay}`);

            tl.to(mesh.scale, {
                x: 1.0,
                y: 1.0,
                z: 1.0,
                duration: 0.25,
                ease: 'power1.out'
            }, `matrixConvergence+=${delay + 0.65}`);
        });

        // Camera eases back to frame the completed matrix
        tl.to(this.camera.position, {
            z: 12.5,
            duration: 1.1,
            ease: 'power2.out'
        }, 'matrixConvergence+=0.2');

        // --- STAGE 3: ARX 20-Round Shockwave & Grid Flash ---
        tl.addLabel('matrixLocked', 'matrixConvergence+=1.15');

        if (this.lineSegments) {
            tl.to(this.lineSegments.material, {
                opacity: 0.85,
                duration: 0.3,
                ease: 'power2.out'
            }, 'matrixLocked');

            tl.to(this.lineSegments.material, {
                opacity: 0.32,
                duration: 0.6,
                ease: 'power1.inOut'
            }, '>');
        }

        if (this.shockwave) {
            tl.fromTo(this.shockwave.scale, 
                { x: 0.2, y: 0.2, z: 0.2 },
                { x: 38.0, y: 38.0, z: 38.0, duration: 0.95, ease: 'power2.out' },
                'matrixLocked'
            );
            tl.fromTo(this.shockwave.material,
                { opacity: 0.95 },
                { opacity: 0, duration: 0.9, ease: 'power2.out' },
                'matrixLocked'
            );
        }

        // Energetic matrix rotation into 3D perspective
        tl.to(this.matrixGroup.rotation, {
            x: 0.24,
            y: -0.38,
            z: 0.06,
            duration: 1.2,
            ease: 'power3.out'
        }, 'matrixLocked+=0.1');

        // --- STAGE 4: Futuristic Typography Reveal ---
        tl.to(introBadge, {
            opacity: 1,
            y: 0,
            duration: 0.45,
            ease: 'power3.out'
        }, 'matrixLocked+=0.3');

        tl.to(introTitle, {
            opacity: 1,
            y: 0,
            duration: 0.55,
            ease: 'power3.out'
        }, 'matrixLocked+=0.45');

        tl.to(introSub, {
            opacity: 1,
            y: 0,
            duration: 0.45,
            ease: 'power2.out'
        }, 'matrixLocked+=0.6');

        if (introStream) {
            tl.to(introStream, {
                opacity: 1,
                y: 0,
                duration: 0.4,
                ease: 'power2.out'
            }, 'matrixLocked+=0.75');
        }

        // Brief cinematic pause to absorb the beauty (~1.1s)
        tl.to({}, { duration: 1.1 });

        // --- STAGE 5: Seamless Handover to Ambient Deep Space ---
        if (this.arxGroup) {
            tl.to([this.arxRingAdd.material, this.arxRingRot.material, this.arxRingXor.material], {
                opacity: 0,
                duration: 0.9,
                ease: 'power2.inOut'
            });
            tl.to(this.arxGroup.scale, {
                x: 2.2,
                y: 2.2,
                z: 2.2,
                duration: 0.9,
                ease: 'power2.inOut'
            }, '<');
        }

        tl.to(this.matrixGroup.position, {
            z: -4.5,
            y: -0.8,
            duration: 1.1,
            ease: 'power3.inOut'
        }, '<');

        tl.to(this.camera.position, {
            z: 16.5,
            duration: 1.1,
            ease: 'power3.inOut'
        }, '<');

        tl.to(this.overlay, {
            opacity: 0,
            duration: 0.75,
            ease: 'power2.inOut'
        }, '<');
    }

    transitionToMainApp() {
        if (this.overlay) {
            this.overlay.style.pointerEvents = 'none';
            this.overlay.style.display = 'none';
            this.overlay.setAttribute('aria-hidden', 'true');
        }

        if (this.appPage) {
            gsap.to(this.appPage, {
                opacity: 1,
                y: 0,
                duration: 0.8,
                ease: 'power3.out'
            });
        }
    }

    skipIntroInstant() {
        if (this.entranceTimeline) {
            this.entranceTimeline.kill();
        }

        if (this.overlay) {
            this.overlay.style.display = 'none';
            this.overlay.style.pointerEvents = 'none';
            this.overlay.setAttribute('aria-hidden', 'true');
        }

        if (this.arxGroup) {
            this.arxRingAdd.material.opacity = 0;
            this.arxRingRot.material.opacity = 0;
            this.arxRingXor.material.opacity = 0;
            this.shockwave.material.opacity = 0;
        }

        // Set state matrix into its ambient background position
        this.camera.position.set(0, 0, 16.5);
        this.matrixGroup.position.set(0, -0.8, -4.5);
        this.matrixGroup.rotation.set(0.18, -0.25, 0.04);

        this.nodeMeshes.forEach((mesh) => {
            mesh.scale.set(1, 1, 1);
            mesh.position.set(mesh.userData.baseX, mesh.userData.baseY, mesh.userData.baseZ);
        });

        if (this.lineSegments) {
            this.lineSegments.material.opacity = 0.28;
        }

        if (this.appPage) {
            this.appPage.style.opacity = '1';
            this.appPage.style.transform = 'translateY(0)';
        }
    }

    fallbackToCss() {
        if (this.overlay) {
            this.overlay.style.display = 'none';
            this.overlay.setAttribute('aria-hidden', 'true');
        }
        if (this.appPage) {
            this.appPage.style.opacity = '1';
            this.appPage.style.transform = 'none';
        }
    }

    bindEvents() {
        window.addEventListener('resize', () => this.onResize());

        // Mouse Parallax for ambient 3D depth
        window.addEventListener('mousemove', (e) => {
            const nx = (e.clientX / window.innerWidth) * 2 - 1;
            const ny = -(e.clientY / window.innerHeight) * 2 + 1;
            this.mouse.targetX = nx * 0.45;
            this.mouse.targetY = ny * 0.35;
        }, { passive: true });

        // Skip intro button & Escape key listener
        if (this.btnSkip) {
            this.btnSkip.addEventListener('click', () => this.skipIntroInstant());
        }
        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.overlay && this.overlay.style.display !== 'none') {
                this.skipIntroInstant();
            }
        });

        // Replay button in header
        if (this.btnReplay) {
            this.btnReplay.addEventListener('click', () => {
                this.playEntranceAnimation();
            });
        }

        // Tab visibility management to conserve CPU / GPU
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.stopLoop();
            } else {
                this.startLoop();
            }
        });
    }

    onResize() {
        if (!this.camera || !this.renderer) return;
        const width = window.innerWidth;
        const height = window.innerHeight;
        this.camera.aspect = width / height;
        this.camera.updateProjectionMatrix();
        this.renderer.setSize(width, height);
    }

    startLoop() {
        if (this.isRunning) return;
        this.isRunning = true;

        const tick = () => {
            if (!this.isRunning) return;
            this.renderFrame();
            this.rafId = requestAnimationFrame(tick);
        };
        this.rafId = requestAnimationFrame(tick);
    }

    stopLoop() {
        this.isRunning = false;
        if (this.rafId) {
            cancelAnimationFrame(this.rafId);
            this.rafId = null;
        }
    }

    renderFrame() {
        const elapsed = (performance.now() - this.startTime) * 0.001;

        // Smooth mouse damping
        this.mouse.x += (this.mouse.targetX - this.mouse.x) * 0.05;
        this.mouse.y += (this.mouse.targetY - this.mouse.y) * 0.05;

        // Subtle ambient matrix drift
        if (this.matrixGroup && (!this.entranceTimeline || !this.entranceTimeline.isActive())) {
            this.matrixGroup.rotation.y = -0.25 + Math.sin(elapsed * 0.35) * 0.08 + this.mouse.x * 0.3;
            this.matrixGroup.rotation.x = 0.18 + Math.cos(elapsed * 0.28) * 0.06 + this.mouse.y * 0.25;

            // Micro-pulsing on matrix nodes simulating ARX cycles
            this.nodeMeshes.forEach((mesh, idx) => {
                const phase = elapsed * 1.5 + idx * 0.4;
                const scale = 1.0 + Math.sin(phase) * 0.08;
                mesh.scale.set(scale, scale, scale);
            });
        }

        // Ambient particles slow rotational drift
        if (this.ambientField) {
            this.ambientField.rotation.y = elapsed * 0.018;
            this.ambientField.rotation.x = elapsed * 0.009;
        }

        // Hex fragments subtle floating drift
        if (this.hexSprites) {
            this.hexSprites.forEach((sp) => {
                sp.position.y = sp.userData.baseY + Math.sin(elapsed * sp.userData.speed + sp.userData.phase) * 0.45;
            });
        }

        this.renderer.render(this.scene, this.camera);
    }
}
