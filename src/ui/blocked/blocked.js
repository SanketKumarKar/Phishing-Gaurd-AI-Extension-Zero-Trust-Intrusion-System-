/* ═══════════════════════════════════════════════════════════════
   PhishGuard AI — Blocked Page Logic v2
   ═══════════════════════════════════════════════════════════════ */

document.addEventListener("DOMContentLoaded", () => {
    const params = new URLSearchParams(window.location.search);
    const blockedUrl = params.get("url") || "Unknown URL";
    const verdict = params.get("verdict") || "Phishing";
    const score = parseInt(params.get("score") || "75", 10);

    // ── Populate UI ──
    document.getElementById("blockedUrl").textContent = blockedUrl;
    document.getElementById("scoreValue").textContent = score;
    document.getElementById("timestamp").textContent = new Date().toLocaleString();

    // Animate score bar
    setTimeout(() => {
        document.getElementById("scoreFill").style.width = score + "%";
    }, 300);

    // Generate risk factors from URL analysis
    const riskList = document.getElementById("riskList");
    riskList.innerHTML = "";
    const factors = generateRiskFactors(blockedUrl, score);
    factors.forEach(f => {
        const li = document.createElement("li");
        li.textContent = f;
        riskList.appendChild(li);
    });

    // ── Elements ──
    const showRisksBtn = document.getElementById("showRisksBtn");
    const riskPanel = document.getElementById("riskPanel");
    const proceedBtn = document.getElementById("proceedBtn");
    const confirmBtn = document.getElementById("confirmBtn");
    const goBackBtn = document.getElementById("goBackBtn");

    // ── Step 1: Show risk details ──
    showRisksBtn.addEventListener("click", () => {
        riskPanel.classList.remove("hidden");
        showRisksBtn.classList.add("hidden");
        proceedBtn.classList.remove("hidden");
    });

    // ── Step 2: First proceed ──
    proceedBtn.addEventListener("click", () => {
        proceedBtn.classList.add("hidden");
        confirmBtn.classList.remove("hidden");
    });

    // ── Step 3: Final confirmation ──
    confirmBtn.addEventListener("click", () => {
        chrome.storage.local.get({ allowedUrls: [] }, ({ allowedUrls }) => {
            const alreadyAllowed = allowedUrls.some(entry => entry.url === blockedUrl);
            if (!alreadyAllowed) {
                allowedUrls.push({
                    url: blockedUrl,
                    trusted: true,
                    timestamp: Date.now()
                });
                chrome.storage.local.set({ allowedUrls }, () => {
                    window.location.href = blockedUrl;
                });
            } else {
                window.location.href = blockedUrl;
            }
        });
    });

    // ── Go Back ──
    goBackBtn.addEventListener("click", () => {
        if (window.history.length > 1) {
            window.history.back();
        } else {
            window.location.href = "https://www.google.com";
        }
    });
});

function generateRiskFactors(url, score) {
    const factors = [];
    try {
        const parsed = new URL(url);
        const hostname = parsed.hostname;

        if (parsed.protocol !== "https:") factors.push("No HTTPS encryption detected");
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) factors.push("IP address used instead of domain name");
        if (url.length > 100) factors.push("Abnormally long URL (" + url.length + " characters)");
        if (hostname.split(".").length > 4) factors.push("Excessive subdomains in domain");
        if (url.includes("@")) factors.push("@ symbol detected (credential injection risk)");

        const brands = ["paypal", "amazon", "apple", "microsoft", "google", "facebook", "netflix", "instagram"];
        const found = brands.filter(b => hostname.includes(b));
        if (found.length > 0) factors.push("Possible brand impersonation: " + found.join(", "));

        const susKeywords = ["login", "signin", "verify", "secure", "account", "password", "banking", "confirm"];
        const hits = susKeywords.filter(kw => url.toLowerCase().includes(kw));
        if (hits.length > 0) factors.push("Suspicious keywords: " + hits.join(", "));

        const susTLDs = [".xyz", ".top", ".club", ".click", ".buzz", ".icu", ".tk", ".ml", ".ga"];
        if (susTLDs.some(tld => hostname.endsWith(tld))) factors.push("Suspicious top-level domain");

        if (parsed.port && parsed.port !== "80" && parsed.port !== "443") {
            factors.push("Non-standard port: " + parsed.port);
        }
    } catch {
        factors.push("URL could not be fully parsed");
    }

    if (factors.length === 0) factors.push("Multiple heuristic signals triggered (score: " + score + ")");
    return factors;
}
