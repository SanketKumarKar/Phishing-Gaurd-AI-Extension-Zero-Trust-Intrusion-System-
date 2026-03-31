/* ═══════════════════════════════════════════════════════════════
   PhishGuard AI — Background Service Worker (v2)
   ─────────────────────────────────────────────────────────────
   Routes ALL untrusted navigations through a scanning
   interstitial. The scanning page handles the verdict.
   ═══════════════════════════════════════════════════════════════ */

// ── Trusted Reputation System ───────────────────────────────────

const TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "amazon.in", "amazon.com",
    "microsoft.com", "github.com", "stackoverflow.com",
    "facebook.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "gmail.com", "netflix.com", "paypal.com",
    "apple.com", "drive.google.com", "accounts.google.com",
    "reddit.com", "wikipedia.org", "medium.com", "notion.so",
    "slack.com", "zoom.us", "shopify.com", "stripe.com",
    "cloudflare.com", "vercel.app", "npmjs.com", "docker.com",
    "figma.com", "whatsapp.com", "telegram.org", "discord.com",
    "twitch.tv", "spotify.com", "pinterest.com", "quora.com",
    "ebay.com", "walmart.com", "target.com", "bestbuy.com",
    "cnn.com", "bbc.com", "nytimes.com", "reuters.com",
    "adobe.com", "canva.com", "dropbox.com", "box.com",
    "atlassian.com", "trello.com", "jira.com", "bitbucket.org",
    "heroku.com", "netlify.com", "firebase.google.com",
    "console.cloud.google.com", "aws.amazon.com",
    "azure.microsoft.com", "digitalocean.com",
    "w3schools.com", "mdn.io", "developer.mozilla.org",
    "codepen.io", "codesandbox.io", "replit.com",
    "kaggle.com", "huggingface.co", "openai.com",
];

async function isTrusted(hostname) {
    const isHardcoded = TRUSTED_DOMAINS.some(domain =>
        hostname === domain || hostname.endsWith("." + domain)
    );
    if (isHardcoded) return true;

    const { localTrustedDomains = [] } = await chrome.storage.local.get("localTrustedDomains");
    return localTrustedDomains.includes(hostname);
}

// ── URL Analysis Engine ─────────────────────────────────────────

const REGEX_HTTP = /^https?:\/\//i;
const REGEX_IP = /^\d{1,3}(\.\d{1,3}){3}$/;
const REGEX_SPECIALS = /[!$%^*|~`{}\[\]]/g;
const REGEX_DOT = /\./g;
const REGEX_DASH = /-/g;
const REGEX_HOMOGRAPH = /[а-яёА-ЯЁ\u0400-\u04FF\u0500-\u052F]/; // Cyrillic in domain

const analysisCache = new Map();
const CACHE_LIMIT = 500;

function analyzeUrlSync(inputUrl, trustDiscount = 0) {
    let url = inputUrl.trim();
    if (!REGEX_HTTP.test(url)) url = "http://" + url;

    let parsed;
    try { parsed = new URL(url); } catch { return null; }

    const hostname = parsed.hostname;
    const fullUrl = parsed.href;

    // Check cache
    const cacheKey = fullUrl;
    if (analysisCache.has(cacheKey)) {
        const cached = { ...analysisCache.get(cacheKey) };
        cached.riskScore = Math.max(0, cached.riskScore - trustDiscount);
        if (cached.riskScore < 30) cached.verdict = "Safe";
        else if (cached.riskScore < 60) cached.verdict = "Suspicious";
        else cached.verdict = "Phishing";
        return cached;
    }

    // ── Feature Extraction ──
    const isHttps = parsed.protocol === "https:";
    const urlLength = fullUrl.length;
    const domainLength = hostname.length;
    const path = parsed.pathname + parsed.search;
    const dotCount = (hostname.match(REGEX_DOT) || []).length;
    const dashCount = (hostname.match(REGEX_DASH) || []).length;
    const atSymbol = fullUrl.includes("@");
    const isIP = REGEX_IP.test(hostname);
    const hasPort = !!parsed.port;
    const specialChars = (fullUrl.match(REGEX_SPECIALS) || []).length;
    const subdomainCount = hostname.split(".").length - 2;
    const hasHomograph = REGEX_HOMOGRAPH.test(hostname);

    // Brand impersonation: domain contains brand but isn't the real brand
    const brandKeywords = [
        "paypal", "amazon", "apple", "microsoft", "google", "facebook",
        "netflix", "instagram", "twitter", "linkedin", "dropbox", "chase",
        "wellsfargo", "bankofamerica", "citibank", "hsbc",
    ];
    const brandHits = brandKeywords.filter(b => hostname.includes(b));
    const isBrandImpersonation = brandHits.length > 0 && !TRUSTED_DOMAINS.some(
        td => hostname === td || hostname.endsWith("." + td)
    );

    const suspiciousKeywords = [
        "login", "signin", "verify", "update", "secure", "account",
        "banking", "confirm", "password", "credential", "wallet",
        "suspended", "unusual", "alert", "urgent", "expire",
    ];
    const keywordHits = suspiciousKeywords.filter(kw => fullUrl.toLowerCase().includes(kw));

    const shortenDomains = [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
        "rb.gy", "cutt.ly", "shorturl.at",
    ];
    const isShortened = shortenDomains.some(d => hostname.includes(d));

    // Suspicious TLDs
    const suspiciousTLDs = [
        ".xyz", ".top", ".club", ".work", ".click", ".loan", ".review",
        ".stream", ".gq", ".cf", ".tk", ".ml", ".ga", ".buzz", ".icu",
    ];
    const hasSuspiciousTLD = suspiciousTLDs.some(tld => hostname.endsWith(tld));

    // ── Risk Scoring (Aggressive for real phishing) ──
    let riskScore = 0;

    // Protocol
    if (!isHttps) riskScore += 10;

    // URL structure
    if (urlLength > 75) riskScore += 5;
    if (urlLength > 100) riskScore += 5;
    if (urlLength > 150) riskScore += 8;
    if (domainLength > 30) riskScore += 8;
    if (domainLength > 50) riskScore += 10;

    // Domain anomalies
    if (dotCount > 3) riskScore += 8;
    if (dotCount > 5) riskScore += 10;
    if (dashCount > 2) riskScore += 5;
    if (dashCount > 4) riskScore += 8;
    if (atSymbol) riskScore += 25;
    if (isIP) riskScore += 35;
    if (hasPort && parsed.port !== "80" && parsed.port !== "443") riskScore += 15;
    if (specialChars > 2) riskScore += 8;
    if (specialChars > 5) riskScore += 10;
    if (subdomainCount > 2) riskScore += 8;
    if (subdomainCount > 4) riskScore += 12;

    // Homograph attack (Cyrillic characters in domain)
    if (hasHomograph) riskScore += 40;

    // Brand impersonation (highest risk)
    if (isBrandImpersonation) riskScore += 35;

    // Keywords in URL
    riskScore += keywordHits.length * 5;

    // URL shortener
    if (isShortened) riskScore += 15;

    // Suspicious TLD
    if (hasSuspiciousTLD) riskScore += 12;

    // Path depth (deeply nested paths are suspicious)
    const pathDepth = (path.match(/\//g) || []).length;
    if (pathDepth > 5) riskScore += 5;

    // Double extensions in path (e.g. .html.php)
    if (/\.\w+\.\w+$/.test(path)) riskScore += 8;

    // Data URI or javascript: in href
    if (fullUrl.includes("data:") || fullUrl.includes("javascript:")) riskScore += 40;

    // Store original score
    const originalScore = Math.min(riskScore, 100);

    // Apply trust discount
    riskScore = Math.max(0, riskScore - trustDiscount);
    riskScore = Math.min(riskScore, 100);

    let verdict;
    if (riskScore < 30) verdict = "Safe";
    else if (riskScore < 60) verdict = "Suspicious";
    else verdict = "Phishing";

    // Detailed risk factors for UI display
    const riskFactors = [];
    if (!isHttps) riskFactors.push("No HTTPS encryption");
    if (isIP) riskFactors.push("IP address used instead of domain");
    if (isBrandImpersonation) riskFactors.push("Brand impersonation: " + brandHits.join(", "));
    if (hasHomograph) riskFactors.push("Homograph attack detected (Cyrillic characters)");
    if (hasSuspiciousTLD) riskFactors.push("Suspicious top-level domain");
    if (isShortened) riskFactors.push("URL shortener (hides real destination)");
    if (keywordHits.length > 0) riskFactors.push("Suspicious keywords: " + keywordHits.join(", "));
    if (urlLength > 100) riskFactors.push("Abnormally long URL (" + urlLength + " chars)");
    if (subdomainCount > 2) riskFactors.push("Excessive subdomains (" + subdomainCount + ")");
    if (atSymbol) riskFactors.push("@ symbol in URL (credential injection)");
    if (hasPort) riskFactors.push("Non-standard port: " + parsed.port);
    if (domainLength > 30) riskFactors.push("Unusually long domain name");

    // Cache result
    if (analysisCache.size >= CACHE_LIMIT) {
        const firstKey = analysisCache.keys().next().value;
        analysisCache.delete(firstKey);
    }
    analysisCache.set(cacheKey, {
        url: fullUrl, verdict, riskScore: originalScore, hostname, riskFactors
    });

    return { url: fullUrl, verdict, riskScore, hostname, riskFactors };
}


// ── Navigation Interception ────────────────────────────────────

const IGNORE_PATTERNS = [
    /^chrome/i, /^about:/i, /^chrome-extension:/i,
    /^edge:/i, /^brave:/i, /^moz-extension:/i, /^devtools:/i,
];

function shouldIgnore(url) {
    return IGNORE_PATTERNS.some(p => p.test(url));
}

// In-memory set of URLs that have been scanned and cleared.
// Prevents infinite loop: scanning page redirects → onBeforeNavigate fires again.
const clearedUrls = new Set();

function markCleared(url) {
    clearedUrls.add(url);
    // Auto-expire after 30 seconds to allow re-scanning on revisit
    setTimeout(() => clearedUrls.delete(url), 30000);
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return;

    const url = details.url;
    if (shouldIgnore(url)) return;

    // Don't intercept our own extension pages
    if (url.startsWith(chrome.runtime.getURL(""))) return;

    // Skip if this URL was just cleared by the scanning page
    if (clearedUrls.has(url)) return;

    // Check if protection is enabled
    const { protectionEnabled = true } = await chrome.storage.local.get("protectionEnabled");
    if (!protectionEnabled) return;

    // Check if user already allowed this URL
    const { allowedUrls = [] } = await chrome.storage.local.get("allowedUrls");
    if (allowedUrls.some(entry => entry.url === url)) return;

    // Check if trusted domain — if so, skip scanning page
    try {
        const parsed = new URL(url);
        const trusted = await isTrusted(parsed.hostname);
        if (trusted) {
            chrome.action.setBadgeText({ text: "✓", tabId: details.tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#00ff88", tabId: details.tabId });
            setTimeout(() => {
                chrome.action.setBadgeText({ text: "", tabId: details.tabId });
            }, 2000);
            return;
        }
    } catch {
        return;
    }

    // Route through scanning interstitial
    const scanPageUrl = chrome.runtime.getURL("src/ui/scanning/scanning.html") +
        `?target=${encodeURIComponent(url)}`;

    chrome.tabs.update(details.tabId, { url: scanPageUrl });
});


// ── Message handler ────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // Scanning page tells us a URL is cleared — mark it so navigation goes through
    if (message.type === "clearUrl" && message.url) {
        markCleared(message.url);
        sendResponse({ ok: true });
        return;
    }

    if (message.type === "analyzeUrl") {
        (async () => {
            const { allowedUrls = [] } = await chrome.storage.local.get("allowedUrls");
            const userTrustEntry = allowedUrls.find(entry => entry.url === message.url);
            const trustDiscount = userTrustEntry ? 50 : 0;

            const result = analyzeUrlSync(message.url, trustDiscount);

            // Auto-whitelist safe sites
            if (result && result.verdict === "Safe") {
                const { localTrustedDomains = [] } = await chrome.storage.local.get("localTrustedDomains");
                if (result.hostname && !localTrustedDomains.includes(result.hostname)) {
                    const updatedDomains = [...localTrustedDomains, result.hostname].slice(-200);
                    await chrome.storage.local.set({ localTrustedDomains: updatedDomains });
                }
            }

            // Store in scan history
            if (result) {
                const { scanHistory = [] } = await chrome.storage.local.get("scanHistory");
                const entry = {
                    url: result.url,
                    verdict: result.verdict,
                    riskScore: result.riskScore,
                    riskFactors: result.riskFactors || [],
                    timestamp: Date.now(),
                };
                const updated = [entry, ...scanHistory.filter(h => h.url !== result.url)].slice(0, 50);
                await chrome.storage.local.set({ scanHistory: updated });
            }

            // Update badge
            if (result && sender.tab) {
                if (result.verdict === "Suspicious") {
                    chrome.action.setBadgeText({ text: "!", tabId: sender.tab.id });
                    chrome.action.setBadgeBackgroundColor({ color: "#F59E0B", tabId: sender.tab.id });
                } else if (result.verdict === "Phishing") {
                    chrome.action.setBadgeText({ text: "×", tabId: sender.tab.id });
                    chrome.action.setBadgeBackgroundColor({ color: "#EF4444", tabId: sender.tab.id });
                } else {
                    chrome.action.setBadgeText({ text: "✓", tabId: sender.tab.id });
                    chrome.action.setBadgeBackgroundColor({ color: "#00ff88", tabId: sender.tab.id });
                    setTimeout(() => {
                        chrome.action.setBadgeText({ text: "", tabId: sender.tab.id });
                    }, 3000);
                }
            }

            sendResponse(result);
        })();
        return true;
    }

    if (message.type === "content_analysis_result" && sender.tab) {
        (async () => {
            const data = message.data;
            const url = message.url;

            try {
                const urlObj = new URL(url);
                if (await isTrusted(urlObj.hostname)) return;
            } catch { return; }

            const analysis = analyzeUrlSync(url);
            if (!analysis) return;

            let finalScore = analysis.riskScore;

            if (data.suspiciousFormTarget) finalScore += 40;
            if (data.suspiciousScriptDetected) finalScore += 35;
            if (data.suspiciousSubmitHandler) finalScore += 30;
            if (data.hasPasswordField && analysis.riskScore > 25) finalScore += 15;
            if (data.loginKeywordsDetected && analysis.riskScore > 25) finalScore += 10;

            finalScore = Math.min(100, finalScore);

            if (finalScore >= 60 && analysis.riskScore < 60) {
                const blockedPageUrl = chrome.runtime.getURL("src/ui/blocked/blocked.html") +
                    `?url=${encodeURIComponent(url)}` +
                    `&verdict=Phishing` +
                    `&score=${finalScore}`;
                chrome.tabs.update(sender.tab.id, { url: blockedPageUrl });
            }
        })();
    }
    return true;
});
