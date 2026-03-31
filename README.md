# 🛡️ PhishGuard AI — Zero Trust Intrusion Detection System

> **Heuristic-based real-time phishing detection and zero-trust browsing protection for Chrome.**

PhishGuard AI is a privacy-first Chrome extension that treats **every website as untrusted by default**. Using a Zero Trust security model, it scans and verifies every navigation before granting access — even to sites you've visited before. No data is ever sent to external servers; all analysis runs locally on your device.

---

## 🔐 Zero Trust Architecture

PhishGuard AI implements a **"never trust, always verify"** approach to web browsing:

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  User navigates │────▶│  TRUST DECISION   │────▶│     OUTCOME     │
│   to a URL      │     │  GATEWAY          │     │                 │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                              │
                    ┌─────────┴──────────┐
                    ▼                    ▼
            ┌──────────────┐    ┌──────────────┐
            │  KNOWN SAFE  │    │  UNVERIFIED  │
            │  (70+ trust  │    │  (All other  │
            │   domains)   │    │   domains)   │
            │              │    │              │
            │  → Instant   │    │  → Scanning  │
            │    access    │    │    interstitial│
            └──────────────┘    └──────────────┘
                                      │
                              ┌───────┴───────┐
                              ▼               ▼
                        ┌──────────┐   ┌──────────┐
                        │  SAFE    │   │ PHISHING │
                        │ Score<30 │   │ Score≥60 │
                        │          │   │          │
                        │ → Allow  │   │ → Block  │
                        │ + learn  │   │ + warn   │
                        └──────────┘   └──────────┘
```

### Core Principles

| Principle | Implementation |
|---|---|
| **Never Trust** | Every non-whitelisted URL is intercepted and routed through a scanning interstitial before the page loads |
| **Always Verify** | 15+ heuristic checks run on every URL: structure analysis, brand impersonation detection, homograph attack scanning, TLD reputation |
| **Least Privilege** | Only minimal Chrome permissions are requested. No network calls, no external APIs, no data collection |
| **Continuous Validation** | Even after a site is allowed, the DOM content script continues monitoring for runtime threats (credential grabbers, malicious scripts) |
| **Defense in Depth** | Multi-layer protection: URL analysis → scanning gate → DOM inspection → content scoring → real-time badge alerts |

---

## ✨ Features

| Feature | Description |
|---|---|
| **Scanning Interstitial** | Every unknown site passes through an animated scanning gate before loading — the user never touches an unverified page |
| **URL Risk Scoring** | 15+ factor heuristic analysis: URL structure, domain patterns, brand impersonation, homograph attacks, suspicious TLDs |
| **Deep DOM Scan** | Post-load inspection of forms, inline scripts, and external script sources for data-theft patterns |
| **Brand Impersonation Detection** | Catches domains mimicking PayPal, Google, Amazon, etc. (e.g. `paypa1-secure.xyz`) |
| **Homograph Attack Detection** | Flags Cyrillic/Unicode characters disguised as Latin letters in domains |
| **Automatic Trust Learning** | Safe domains are learned over time and bypass future scans (ML-lite approach) |
| **Triple-Confirmation Bypass** | Blocked sites require 3 explicit steps before the user can proceed — showing all detected risks |
| **100% Local Analysis** | Zero network requests — all scoring on-device using `chrome.storage.local` |

---

## 🏗️ Architecture

```
extension/
├── manifest.json                # Extension manifest (MV3)
├── README.md                    # Documentation
├── assets/
│   └── icons/                   # Extension icons (16, 48, 128px)
├── src/
│   ├── background/
│   │   └── background.js        # Service worker: analysis engine, navigation gateway, LRU cache
│   ├── content/
│   │   └── content.js           # Content script: DOM-level heuristic scanner
│   └── ui/
│       ├── scanning/
│       │   ├── scanning.html    # Zero-trust scanning interstitial
│       │   ├── scanning.css     # Radar animation, progress bar
│       │   └── scanning.js      # Analysis orchestration, auto-redirect
│       ├── popup/
│       │   ├── popup.html       # Extension popup with risk gauge
│       │   ├── popup.css        # Premium dark theme
│       │   └── popup.js         # Auto-scan current tab, manual scan
│       └── blocked/
│           ├── blocked.html     # Threat warning page
│           ├── blocked.css      # Animated danger UI
│           └── blocked.js       # Triple-step bypass flow
```

---

## 🔬 How It Works

### 1. Zero Trust Gateway (`background.js`)
Every navigation is intercepted at the `webNavigation.onBeforeNavigate` level:
- **Trusted domains** (70+ hardcoded + learned) → instant access
- **Unknown domains** → routed to scanning interstitial for verification
- **Allowed URLs** (user-bypassed) → temporary 30s pass-through

### 2. URL Analysis Engine
Scored across **15+ risk factors**:
- Protocol (HTTP vs HTTPS)
- URL & domain length anomalies
- IP-based hostnames
- Subdomain depth & dot/dash density
- Brand impersonation (PayPal, Google, Amazon, etc.)
- Homograph attacks (Cyrillic character substitution)
- Suspicious TLDs (`.xyz`, `.click`, `.buzz`, `.icu`, `.tk`)
- URL shortener detection
- Special character density
- Non-standard ports
- Double file extensions
- Data URI / JavaScript protocol injection

Results cached in an LRU cache (500 entries) with pre-compiled regex.

### 3. Deep DOM Scanner (`content.js`)
Post-load content inspection:
- **Password fields** on untrusted domains
- **Cross-domain form actions** submitting credentials externally
- **Inline script analysis** for theft keywords (`document.cookie`, Discord webhooks, Telegram bots)
- **`onsubmit` handler inspection** for obfuscated fetch/redirect attacks

### 4. Scoring Thresholds

| Score | Verdict | Action |
|-------|---------|--------|
| 0–29 | ✅ Safe | Auto-whitelisted, instant future access |
| 30–59 | ⚠️ Suspicious | Brief warning, badge alert, allowed through |
| 60–100 | 🚫 Phishing | Full page block with triple-confirmation bypass |

---

## 🚀 Installation & Setup

### Step 1: Get the Code
```bash
git clone https://github.com/SanketKumarKar/Phishing-Gaurd-AI-Extension-Zero-Trust-Intrusion-System-.git
```
Or download as ZIP from GitHub and extract it.

### Step 2: Open Chrome Extensions Page
- Open Google Chrome
- Type `chrome://extensions/` in the address bar and press Enter
- You'll see the Extensions management page

### Step 3: Enable Developer Mode
- Look at the **top-right corner** of the extensions page
- Toggle the **"Developer mode"** switch to **ON**
- Three new buttons will appear: "Load unpacked", "Pack extension", "Update"

### Step 4: Load the Extension
1. Click the **"Load unpacked"** button
2. A file browser dialog will open
3. Navigate to the cloned/extracted folder
4. Select the **`extension/`** folder (the one containing `manifest.json`)
5. Click **"Select Folder"**

### Step 5: Verify Installation
- ✅ The **PhishGuard AI** card should appear on the extensions page
- ✅ A **shield icon** appears in your Chrome toolbar (top-right)
- ✅ If the icon isn't visible, click the **puzzle piece** 🧩 icon and **pin** PhishGuard AI

### Step 6: Test It
- Open any new website → you should see the **scanning animation** before the page loads
- Visit `google.com` → should load **instantly** (trusted domain)
- Try a suspicious URL like `http://192.168.1.1/login` → should get **blocked**
- Click the PhishGuard AI icon to see the **popup with risk gauge**

### Updating After Code Changes
If you modify the code:
1. Go to `chrome://extensions/`
2. Find PhishGuard AI
3. Click the **🔄 reload** button (circular arrow icon)
4. The extension will reload with your latest changes

### Troubleshooting
| Issue | Fix |
|---|---|
| Extension won't load | Make sure you selected the folder containing `manifest.json`, not a parent folder |
| No scanning animation | Reload the extension and try a non-trusted domain |
| Icon not visible | Click the puzzle piece 🧩 in Chrome toolbar → pin PhishGuard AI |
| Errors in console | Go to `chrome://extensions/` → click "Errors" under the extension card |

---

## 🎨 Design

**Techy Minimalist** dark theme:
- **Typography**: JetBrains Mono (data) + Inter (UI)
- **Colors**: Deep black (#05050a) with neon cyan (#00f0ff) and danger red (#ff3366)
- **Style**: Grid backgrounds, radar animations, glassmorphic panels, micro-animations

---

## 🔒 Privacy

- **Zero network requests** — all analysis performed locally
- **No telemetry** — no usage data collected
- **No API keys** — fully self-contained
- **No cloud dependency** — works offline
- Scan history stored in `chrome.storage.local`, never leaves your browser

---

## 📋 Permissions

| Permission | Reason |
|---|---|
| `webNavigation` | Intercept navigations for zero-trust gateway |
| `storage` | Store scan history, trusted domains, user preferences |
| `activeTab` | Access current tab URL for popup auto-scan |
| `scripting` | Inject content script for DOM analysis |
| `tabs` | Read tab URLs for scanning interstitial routing |

---

## 🛠️ Tech Stack

- **Manifest V3** (Chrome Extension)
- **Vanilla JavaScript** (zero dependencies, no frameworks)
- **Chrome APIs**: `webNavigation`, `storage`, `action`, `scripting`, `runtime`, `tabs`
- **Design**: Custom CSS with CSS variables, Google Fonts

---

## 📄 License

MIT License — free to use, modify, and distribute.
