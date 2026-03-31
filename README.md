# 🛡️ PhishGuard AI

> **Heuristic-based real-time phishing detection and zero-trust browsing protection for Chrome.**

PhishGuard AI is a privacy-first Chrome extension that analyzes URLs and page content locally on your device to detect phishing attempts. No data is ever sent to external servers.

---

## ✨ Features

| Feature | Description |
|---|---|
| **URL Risk Scoring** | Multi-factor heuristic analysis of URL structure, domain patterns, and suspicious keywords. |
| **Deep DOM Scan** | Inspects page forms, inline scripts, and external script sources for data-theft patterns (credential grabbers, cookie exfiltration). |
| **Automatic Whitelisting** | Learns safe domains over time. Includes 40+ pre-verified trusted domains (Google, GitHub, Amazon, etc.). |
| **Double-Confirmation Block** | Phishing sites trigger a zero-trust warning page requiring two explicit confirmations before bypass. |
| **Non-Intrusive Warnings** | Suspicious (but not definitively phishing) sites show a badge warning instead of blocking. |
| **100% Local Analysis** | Zero data exfiltration — all scoring happens on-device using `chrome.storage.local`. |

---

## 🏗️ Architecture

```
extension/
├── manifest.json              # Extension manifest (MV3)
├── assets/
│   └── icons/                 # Extension icons (16, 48, 128px)
├── src/
│   ├── background/
│   │   └── background.js      # Service worker: URL analysis engine, navigation interception, LRU cache
│   ├── content/
│   │   └── content.js         # Content script: DOM-level heuristic scanner
│   └── ui/
│       ├── popup/
│       │   ├── popup.html     # Extension popup interface
│       │   ├── popup.css      # Techy minimalist dark theme
│       │   └── popup.js       # Popup logic & manual scan
│       └── blocked/
│           ├── blocked.html   # Zero-trust warning page
│           ├── blocked.css    # Warning page styles
│           └── blocked.js     # Double-confirmation flow
```

---

## 🔬 How It Works

### 1. URL Analysis Engine (`background.js`)
Every navigation is intercepted and scored across **12+ risk factors**:

- Protocol check (HTTP vs HTTPS)
- URL & domain length anomalies
- IP-based hostnames
- Subdomain depth
- Suspicious keywords (`login`, `verify`, `banking`, etc.)
- URL shortener detection
- Special character density
- Non-standard port usage

Results are cached in an LRU cache (500 entries) with pre-compiled regex for performance.

### 2. Deep DOM Scanner (`content.js`)
After a page loads, the content script inspects:

- **Password fields** on untrusted domains
- **Cross-domain form actions** that submit credentials to external servers
- **Inline script analysis** for theft keywords (`document.cookie`, Discord webhooks, Telegram bots)
- **`onsubmit` handler inspection** for obfuscated fetch/redirect attacks

### 3. Scoring Thresholds

| Score | Verdict | Action |
|-------|---------|--------|
| 0–29 | ✅ Safe | No action, domain auto-whitelisted |
| 30–59 | ⚠️ Suspicious | Badge warning on extension icon |
| 60–100 | 🚫 Phishing | Page blocked with zero-trust confirmation |

---

## 🚀 Installation (Developer Mode)

1. Clone or download this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable **Developer mode** (toggle in top-right)
4. Click **Load unpacked** and select the `extension/` folder
5. The PhishGuard AI icon will appear in your toolbar

---

## 🎨 Design

The extension uses a **Techy Minimalist** dark theme:
- **Typography**: JetBrains Mono (data) + Inter (UI)
- **Colors**: Dark background (#0a0a0f) with neon cyan (#00f0ff) accents
- **Style**: Glassmorphism panels, smooth micro-animations

---

## 🔒 Privacy

- **Zero network requests** — all analysis is performed locally
- **No telemetry** — no usage data is collected
- **No API keys** — the extension is fully self-contained
- Scan history is stored in `chrome.storage.local` and never leaves your browser

---

## 📋 Permissions

| Permission | Reason |
|---|---|
| `webNavigation` | Intercept page navigations for real-time URL analysis |
| `storage` | Store scan history, trusted domains, and user preferences |
| `activeTab` | Access the current tab URL for manual scans |
| `scripting` | Inject content script for DOM-level analysis |

---

## 🛠️ Tech Stack

- **Manifest V3** (Chrome Extension)
- **Vanilla JavaScript** (no frameworks)
- **Chrome APIs**: `webNavigation`, `storage`, `action`, `scripting`, `runtime`
- **Design**: Custom CSS with CSS variables, Google Fonts

---

## 📄 License

MIT License — free to use, modify, and distribute.
# Phishing-Gaurd-AI-Extension-Zero-Trust-Intrusion-System-
