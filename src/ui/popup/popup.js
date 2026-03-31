/* ═══════════════════════════════════════════════════════════════
   PhishGuard AI — Popup Logic v2 (Auto-scan + Risk Gauge)
   ═══════════════════════════════════════════════════════════════ */

document.addEventListener("DOMContentLoaded", () => {
    const toggleBtn = document.getElementById("toggleBtn");
    const scanStatus = document.getElementById("scanStatus");
    const currentUrlEl = document.getElementById("currentUrl");
    const gaugeArc = document.getElementById("gaugeArc");
    const gaugeValue = document.getElementById("gaugeValue");
    const verdictBadge = document.getElementById("verdictBadge");
    const riskFactorsEl = document.getElementById("riskFactors");
    const factorsList = document.getElementById("factorsList");
    const urlInput = document.getElementById("urlInput");
    const scanBtn = document.getElementById("scanBtn");
    const statSafe = document.getElementById("statSafe");
    const statSuspicious = document.getElementById("statSuspicious");
    const statPhishing = document.getElementById("statPhishing");
    const historyList = document.getElementById("historyList");
    const historyEmpty = document.getElementById("historyEmpty");
    const historyCount = document.getElementById("historyCount");
    const systemTime = document.getElementById("systemTime");

    // ── Clock ──
    const updateTime = () => {
        systemTime.textContent = new Date().toLocaleTimeString('en-GB', { hour12: false });
    };
    setInterval(updateTime, 1000);
    updateTime();

    // ── Init ──
    loadProtectionState();
    loadHistory();
    autoScanCurrentTab();

    // ── Toggle ──
    toggleBtn.addEventListener("click", async () => {
        const { protectionEnabled = true } = await chrome.storage.local.get("protectionEnabled");
        const newState = !protectionEnabled;
        await chrome.storage.local.set({ protectionEnabled: newState });
        updateToggleUI(newState);
    });

    function updateToggleUI(enabled) {
        toggleBtn.className = "toggle " + (enabled ? "active" : "off");
    }

    async function loadProtectionState() {
        const { protectionEnabled = true } = await chrome.storage.local.get("protectionEnabled");
        updateToggleUI(protectionEnabled);
    }

    // ── Auto-scan current tab ──
    function autoScanCurrentTab() {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (!tabs[0] || !tabs[0].url) {
                scanStatus.textContent = "No tab";
                scanStatus.classList.add("done");
                return;
            }

            const tabUrl = tabs[0].url;

            // Skip chrome:// and extension pages
            if (tabUrl.startsWith("chrome") || tabUrl.startsWith("about:") || tabUrl.startsWith("chrome-extension:")) {
                currentUrlEl.textContent = "Browser internal page";
                scanStatus.textContent = "Skipped";
                scanStatus.classList.add("done");
                gaugeValue.textContent = "—";
                verdictBadge.textContent = "N/A";
                return;
            }

            try {
                const parsed = new URL(tabUrl);
                currentUrlEl.textContent = parsed.hostname + parsed.pathname.substring(0, 40);
            } catch {
                currentUrlEl.textContent = tabUrl.substring(0, 50);
            }

            scanStatus.textContent = "Scanning...";
            displayResult({ verdict: "Analyzing", riskScore: 0, riskFactors: [] }, true);

            chrome.runtime.sendMessage({ type: "analyzeUrl", url: tabUrl }, (result) => {
                scanStatus.classList.add("done");
                if (!result) {
                    scanStatus.textContent = "Analysis complete";
                    displayResult({ verdict: "Safe", riskScore: 0, riskFactors: [] });
                    return;
                }
                scanStatus.textContent = result.verdict.toUpperCase();
                displayResult(result);
                loadHistory(); // Refresh after scan
            });
        });
    }

    // ── Display result in gauge ──
    function displayResult(result, isLoading = false) {
        const score = result.riskScore || 0;
        const v = (result.verdict || "safe").toLowerCase();

        // Animate gauge arc (total arc length = 157)
        const offset = 157 - (157 * score / 100);
        gaugeArc.style.strokeDashoffset = isLoading ? "157" : offset;
        gaugeArc.style.transition = "stroke-dashoffset 1s cubic-bezier(0.4, 0, 0.2, 1)";

        // Score number
        gaugeValue.textContent = isLoading ? "..." : score;
        if (v === "safe") gaugeValue.style.color = "#00ff88";
        else if (v === "suspicious") gaugeValue.style.color = "#ffaa00";
        else if (v === "phishing") gaugeValue.style.color = "#ff3366";
        else gaugeValue.style.color = "#5a5e78";

        // Verdict badge
        verdictBadge.className = "verdict-badge " + v;
        const labels = {
            safe: "✓ VERIFIED SAFE",
            suspicious: "⚠ SUSPICIOUS",
            phishing: "✕ PHISHING DETECTED",
            analyzing: "◌ ANALYZING..."
        };
        verdictBadge.textContent = labels[v] || result.verdict.toUpperCase();

        // Risk factors
        if (result.riskFactors && result.riskFactors.length > 0) {
            riskFactorsEl.classList.remove("hidden");
            factorsList.innerHTML = "";
            result.riskFactors.forEach(f => {
                const li = document.createElement("li");
                li.textContent = f;
                factorsList.appendChild(li);
            });
        } else {
            riskFactorsEl.classList.add("hidden");
        }
    }

    // ── Manual Scan ──
    scanBtn.addEventListener("click", () => performManualScan());
    urlInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") performManualScan();
    });

    function performManualScan() {
        const url = urlInput.value.trim();
        if (!url) return;

        scanStatus.textContent = "Scanning...";
        scanStatus.classList.remove("done");
        currentUrlEl.textContent = url.substring(0, 60);
        displayResult({ verdict: "Analyzing", riskScore: 0, riskFactors: [] }, true);

        chrome.runtime.sendMessage({ type: "analyzeUrl", url }, (result) => {
            scanStatus.classList.add("done");

            if (!result) {
                scanStatus.textContent = "Error";
                displayResult({ verdict: "Safe", riskScore: 0, riskFactors: [] });
                return;
            }

            scanStatus.textContent = result.verdict.toUpperCase();
            displayResult(result);
            loadHistory();
        });
    }

    // ── History ──
    async function loadHistory() {
        const { scanHistory = [] } = await chrome.storage.local.get("scanHistory");

        const stats = { safe: 0, suspicious: 0, phishing: 0 };
        scanHistory.forEach(h => {
            const key = h.verdict.toLowerCase();
            if (stats[key] !== undefined) stats[key]++;
        });
        statSafe.textContent = stats.safe;
        statSuspicious.textContent = stats.suspicious;
        statPhishing.textContent = stats.phishing;

        historyCount.textContent = scanHistory.length;

        // Clear old items
        historyList.querySelectorAll(".history-item").forEach(el => el.remove());

        if (scanHistory.length === 0) {
            historyEmpty.style.display = "block";
            return;
        }

        historyEmpty.style.display = "none";

        scanHistory.slice(0, 8).forEach(entry => {
            const v = entry.verdict.toLowerCase();
            const item = document.createElement("div");
            item.className = "history-item";

            let displayUrl;
            try {
                const parsed = new URL(entry.url);
                displayUrl = parsed.hostname;
            } catch {
                displayUrl = entry.url.substring(0, 30);
            }

            item.innerHTML = `
                <span class="history-dot ${v}"></span>
                <span class="history-url">${escapeHtml(displayUrl)}</span>
                <span class="history-score">${entry.riskScore}%</span>
            `;
            historyList.appendChild(item);
        });
    }

    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }
});
