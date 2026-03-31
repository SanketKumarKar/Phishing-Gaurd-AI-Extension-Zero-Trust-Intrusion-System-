/* ═══════════════════════════════════════════════════════════════
   PhishGuard AI — Scanning Interstitial Logic
   ─────────────────────────────────────────────────────────────
   Receives the target URL via query param, asks background.js
   to analyze it, then either redirects (safe) or shows blocked.
   ═══════════════════════════════════════════════════════════════ */

(function () {
    const params = new URLSearchParams(window.location.search);
    const targetUrl = params.get("target");

    const progressFill = document.getElementById("progressFill");
    const scanStep = document.getElementById("scanStep");
    const scanUrl = document.getElementById("scanUrl");
    const container = document.querySelector(".scan-container");

    if (!targetUrl) {
        scanStep.textContent = "ERROR: No target URL provided.";
        return;
    }

    // Show the URL being scanned
    try {
        const parsed = new URL(targetUrl);
        scanUrl.textContent = parsed.hostname + parsed.pathname;
    } catch {
        scanUrl.textContent = targetUrl.substring(0, 80);
    }

    // Helper: tell background to mark URL as cleared, then redirect
    function clearAndRedirect(url) {
        chrome.runtime.sendMessage({ type: "clearUrl", url }, () => {
            window.location.href = url;
        });
    }

    // Scanning steps with timed progress
    const steps = [
        { text: "Analyzing URL structure...", progress: 20, delay: 300 },
        { text: "Checking domain reputation...", progress: 40, delay: 600 },
        { text: "Scanning for threat patterns...", progress: 60, delay: 900 },
        { text: "Evaluating risk score...", progress: 80, delay: 1200 },
    ];

    steps.forEach(({ text, progress, delay }) => {
        setTimeout(() => {
            scanStep.textContent = text;
            progressFill.style.width = progress + "%";
        }, delay);
    });

    // Send analysis request to background after visual progress
    setTimeout(() => {
        chrome.runtime.sendMessage({ type: "analyzeUrl", url: targetUrl }, (result) => {
            if (chrome.runtime.lastError || !result) {
                progressFill.style.width = "100%";
                scanStep.textContent = "Analysis complete. Redirecting...";
                container.classList.add("safe");
                setTimeout(() => clearAndRedirect(targetUrl), 500);
                return;
            }

            progressFill.style.width = "100%";

            if (result.verdict === "Phishing") {
                // BLOCKED
                container.classList.add("danger");
                scanStep.textContent = "⚠ THREAT DETECTED — Blocking access";
                setTimeout(() => {
                    const blockedPageUrl = chrome.runtime.getURL("src/ui/blocked/blocked.html") +
                        `?url=${encodeURIComponent(targetUrl)}` +
                        `&verdict=${encodeURIComponent(result.verdict)}` +
                        `&score=${result.riskScore}`;
                    window.location.href = blockedPageUrl;
                }, 1200);
            } else if (result.verdict === "Suspicious") {
                // SUSPICIOUS — brief warning then proceed
                container.classList.add("safe");
                scanStep.textContent = "⚠ Minor risk — Proceeding with caution";
                setTimeout(() => clearAndRedirect(targetUrl), 1200);
            } else {
                // SAFE — redirect
                container.classList.add("safe");
                scanStep.textContent = "✓ Verified safe — Redirecting...";
                setTimeout(() => clearAndRedirect(targetUrl), 600);
            }
        });
    }, 1500);
})();
