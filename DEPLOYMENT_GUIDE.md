# ChaCha20 CipherForge — Universal Cloud Deployment Guide

This repository is now pre-configured for **Universal 1-Click Deployment** to **Vercel**, **Netlify**, or **GitHub Pages**. All required configuration files, build scripts, relative asset paths (`base: './'`), and security headers are in place.

---

## Option 1: Deploy to Vercel (Recommended — Fastest & Easiest)

Vercel will automatically detect `vercel.json` and build the web studio without any manual configuration.

### Steps:
1. Go to [https://vercel.com](https://vercel.com) and log in with your GitHub account.
2. Click **"Add New..."** → **"Project"**.
3. Select your repository: `Ganesh40292/Cryptography-Assignment`.
4. Vercel will automatically read `vercel.json`:
   - **Framework Preset**: Vite
   - **Build Command**: `cd chacha20-cipher/web && npm install && npm run build`
   - **Output Directory**: `chacha20-cipher/web/dist`
5. Click **"Deploy"**.
6. In ~45 seconds, your application will be live at `https://your-project.vercel.app`!

---

## Option 2: Deploy to Netlify

Netlify will automatically detect `netlify.toml` in the repository root.

### Steps:
1. Go to [https://app.netlify.com](https://app.netlify.com) and log in with GitHub.
2. Click **"Add new site"** → **"Import an existing project"**.
3. Select **GitHub** and authorize your `Cryptography-Assignment` repository.
4. Netlify will automatically detect `netlify.toml`:
   - **Base directory**: `chacha20-cipher/web`
   - **Build command**: `npm run build`
   - **Publish directory**: `dist`
5. Click **"Deploy Site"**.
6. Your application will be live at `https://your-site-name.netlify.app`!

---

## Option 3: Deploy to GitHub Pages (100% Free inside GitHub)

A dedicated GitHub Actions workflow (`.github/workflows/deploy.yml`) is already configured.

### Steps:
1. Push your changes to GitHub whenever you are ready:
   ```bash
   git add .
   git commit -m "Configure universal deployment for Vercel, Netlify, and GitHub Pages"
   git push origin main
   ```
2. In your GitHub repository:
   - Go to **Settings** → **Pages** (in the left sidebar).
   - Under **Build and deployment** → **Source**, select:
     👉 **GitHub Actions** (instead of "Deploy from a branch").
3. Go to the **Actions** tab in your repository. The `Deploy ChaCha20 Web Studio to GitHub Pages` workflow will run automatically!
4. Once completed, your live site will be available at:
   `https://Ganesh40292.github.io/Cryptography-Assignment/`

---

## What Was Configured:

| File | Purpose |
|:---|:---|
| `chacha20-cipher/web/vite.config.js` | Added `base: './'` so all asset links are relative and never break on root domains or GitHub Pages subpaths. |
| `package.json` (Root) | Added root-level `build` script delegating to `chacha20-cipher/web`. |
| `vercel.json` | Configured Vercel build command, output directory (`dist`), and security headers. |
| `netlify.toml` | Configured Netlify base folder, publish directory, build command, and headers. |
| `.github/workflows/deploy.yml` | Automated GitHub Pages CI/CD workflow using official GitHub Actions. |
| `dist/` | Verified production build passes with 0 errors and all assets resolving correctly. |
