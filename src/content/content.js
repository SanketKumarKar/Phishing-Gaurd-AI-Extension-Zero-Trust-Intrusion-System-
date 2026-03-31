/* ═══════════════════════════════════════════════════════════════
   PhishGuard AI — Content Analysis Script
   ─────────────────────────────────────────────────────────────
   Analyzes page DOM for sensitive forms and suspicious data
   submission targets (data-theft heuristics).
   ═══════════════════════════════════════════════════════════════ */

(function () {
    const analyzePageContent = () => {
        const results = {
            hasPasswordField: false,
            suspiciousFormTarget: false,
            externalFormAction: null,
            loginKeywordsDetected: false
        };

        // 1. Check for password fields
        const passwordFields = document.querySelectorAll('input[type="password"]');
        if (passwordFields.length > 0) {
            results.hasPasswordField = true;
        }

        // 2. Check for suspicious keywords in the text (visible labels)
        const loginKeywords = ["login", "sign in", "password", "bank", "verify account", "secure login"];
        const bodyText = document.body.innerText.toLowerCase();
        results.loginKeywordsDetected = loginKeywords.some(kw => bodyText.includes(kw));

        // 3. Analyze External and Inline Scripts for theft patterns
        const scripts = document.scripts;
        let suspiciousScriptFound = false;

        const theftKeywords = [
            ".php?log=", "grabber", "stealer", 
            "discord.com/api/webhooks", "telegram.org/bot",
            "document.cookie"
        ];

        for (let i = 0; i < scripts.length; i++) {
            const script = scripts[i];
            
            // Analyze external script source
            if (script.src) {
                try {
                    const scriptUrl = new URL(script.src);
                    if (theftKeywords.some(kw => scriptUrl.href.includes(kw))) {
                        suspiciousScriptFound = true;
                        break;
                    }
                } catch (e) {
                    // Ignore parsing errors
                }
            } 
            
            // Analyze inline script content
            if (script.textContent) {
                const content = script.textContent.toLowerCase();
                // Extremely basic check for exfiltration logic
                if (theftKeywords.some(kw => content.includes(kw)) && content.includes("fetch(")) {
                    suspiciousScriptFound = true;
                    break;
                }
            }
        }
        
        results.suspiciousScriptDetected = suspiciousScriptFound;

        // 4. Analyze Form Actions and Interpreted onSubmit Handlers
        const forms = document.forms;
        const currentDomain = window.location.hostname;
        let suspiciousSubmitHandler = false;

        for (let i = 0; i < forms.length; i++) {
            const form = forms[i];
            const action = form.action;

            if (action) {
                try {
                    const actionUrl = new URL(action, window.location.href);
                    const actionDomain = actionUrl.hostname;

                    // If form submits to a different domain and contains sensitive inputs
                    if (actionDomain !== currentDomain && actionDomain !== "") {
                        const hasSensitiveInput = form.querySelector('input[type="password"], input[type="email"], input[name*="user"], input[name*="login"]');
                        if (hasSensitiveInput) {
                            results.suspiciousFormTarget = true;
                            results.externalFormAction = actionDomain;
                            break; 
                        }
                    }
                } catch (e) {
                    // Ignore invalid URLs
                }
            }
            
            // Check for inline onsubmit handler that might do malicious background fetch or redirect
            const onsubmitAttr = form.getAttribute('onsubmit');
            if (onsubmitAttr) {
                const onsubmitLower = onsubmitAttr.toLowerCase();
                if (
                    onsubmitLower.includes('fetch(') || 
                    onsubmitLower.includes('xmlhttprequest') ||
                    onsubmitLower.includes('window.location') ||
                    onsubmitLower.includes('=>') ||
                    theftKeywords.some(kw => onsubmitLower.includes(kw))
                ) {
                     suspiciousSubmitHandler = true;
                }
            }
        }
        
        results.suspiciousSubmitHandler = suspiciousSubmitHandler;

        // Send findings to background script
        chrome.runtime.sendMessage({
            type: "content_analysis_result",
            data: results,
            url: window.location.href
        });
    };

    // Run after a short delay to ensure dynamic content is loaded
    setTimeout(analyzePageContent, 1500);
})();
