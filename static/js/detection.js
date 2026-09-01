/**
 * Detection & Evidence Page — live threat score, risk state, evidence chain,
 * sector heatmap, MITRE mapping, simulate-event control.
 */
(function () {
    "use strict";

    var POLL_MS = 2000;
    var CIRCUMFERENCE = 2 * Math.PI * 52; // ~326.7

    var SECTOR_NAMES = {
        military: "Military", government: "Government", telecom: "Telecom",
        energy: "Energy", banking: "Banking & Finance", healthcare: "Healthcare",
        education: "Education", commercial: "Commercial"
    };

    var SECTOR_ICONS = {
        military: "\u2694\uFE0F", government: "\uD83C\uDFDB\uFE0F", telecom: "\uD83D\uDCE1",
        energy: "\u26A1", banking: "\uD83C\uDFE6", healthcare: "\uD83C\uDFE5",
        education: "\uD83C\uDF93", commercial: "\uD83C\uDFEC"
    };

    var SEVERITY_COLORS = {
        info: "#64748b", low: "#38bdf8", medium: "#f59e0b",
        high: "#ef4444", critical: "#f43f5e", none: "#334155"
    };

    var RISK_COLORS = {
        normal: "#34b872", suspicious: "#d49a3c",
        high_risk: "#d44848", critical: "#f43f5e"
    };

    var RISK_LABELS = {
        normal: "Normal", suspicious: "Suspicious",
        high_risk: "High Risk", critical: "Critical"
    };

    // ------------------------------------------------------------------
    // API
    // ------------------------------------------------------------------

    function api(url, cb, method) {
        var xhr = new XMLHttpRequest();
        xhr.open(method || "GET", url, true);
        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4) {
                try { cb(JSON.parse(xhr.responseText)); }
                catch (e) { cb(null); }
            }
        };
        xhr.send();
    }

    function postApi(url, cb) {
        api(url, cb, "POST");
    }

    // ------------------------------------------------------------------
    // Polling
    // ------------------------------------------------------------------

    function poll() {
        api("/api/detection", function (data) {
            if (!data) return;
            renderStats(data);
            renderScore(data);
            renderRiskLadder(data.risk_level || "normal");
            renderSectorHeatmap(data.sector_heatmap || []);
            renderAlerts(data);
            renderMitre(data.mitre_techniques || []);
            renderEvidence(data.evidence_chain || []);
            renderAttackPath();
        });
    }

    // ------------------------------------------------------------------
    // Stats row
    // ------------------------------------------------------------------

    function renderStats(data) {
        setText("statConfidence", (data.confidence_pct || 0) + "%");
        var riskLabel = RISK_LABELS[data.risk_level] || "Normal";
        var riskEl = document.getElementById("statRiskLevel");
        if (riskEl) {
            riskEl.textContent = riskLabel;
            var riskColor = RISK_COLORS[data.risk_level] || RISK_COLORS.normal;
            riskEl.style.color = riskColor;
        }
        setText("statEvidence", data.total_evidence || 0);
        setText("statAlerts", data.active_alerts || 0);
        setText("statTechniques", (data.mitre_techniques || []).length);
    }

    function setText(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    // ------------------------------------------------------------------
    // Threat Score ring
    // ------------------------------------------------------------------

    function renderScore(data) {
        var score = data.threat_score || 0;
        var pct = Math.round(score * 100);
        var arc = document.getElementById("scoreArc");
        var val = document.getElementById("scoreValue");
        var badge = document.getElementById("severityBadge");

        var offset = CIRCUMFERENCE - (score * CIRCUMFERENCE);
        arc.style.strokeDashoffset = offset;
        val.textContent = pct;

        var sev = data.severity || "none";
        var color = SEVERITY_COLORS[sev] || SEVERITY_COLORS.none;
        arc.style.stroke = color;
        badge.textContent = sev.toUpperCase();
        badge.style.background = color + "22";
        badge.style.color = color;
        badge.style.borderColor = color + "44";
    }

    // ------------------------------------------------------------------
    // Risk Ladder
    // ------------------------------------------------------------------

    function renderRiskLadder(currentLevel) {
        var steps = document.querySelectorAll(".risk-step");
        var levels = ["normal", "suspicious", "high_risk", "critical"];
        var currentIdx = levels.indexOf(currentLevel);
        if (currentIdx < 0) currentIdx = 0;

        for (var i = 0; i < steps.length; i++) {
            var level = steps[i].getAttribute("data-level");
            var levelIdx = levels.indexOf(level);
            if (levelIdx <= currentIdx) {
                steps[i].classList.add("risk-step--active");
            } else {
                steps[i].classList.remove("risk-step--active");
            }
            // Highlight current level
            if (levelIdx === currentIdx) {
                steps[i].classList.add("risk-step--current");
            } else {
                steps[i].classList.remove("risk-step--current");
            }
        }
    }

    // ------------------------------------------------------------------
    // Sector Heatmap
    // ------------------------------------------------------------------

    function renderSectorHeatmap(heatmap) {
        var el = document.getElementById("sectorHeatmap");
        if (!heatmap || heatmap.length === 0) {
            el.innerHTML = '<p class="det-card__empty">No sector activity recorded yet.</p>';
            return;
        }
        var html = "";
        // Sort by evidence count descending
        var sorted = heatmap.slice().sort(function (a, b) { return b.evidence_count - a.evidence_count; });
        sorted.forEach(function (s) {
            var name = SECTOR_NAMES[s.sector] || s.sector;
            var icon = SECTOR_ICONS[s.sector] || "\uD83D\uDD35";
            var intensity = Math.min(1.0, s.max_signal);
            var barWidth = Math.round(intensity * 100);
            var barColor = intensity >= 0.7 ? "#d44848" : (intensity >= 0.4 ? "#d49a3c" : "#34b872");
            html += '<div class="det-sector-tile">';
            html += '  <div class="det-sector-tile__header">';
            html += '    <span class="det-sector-tile__icon">' + icon + '</span>';
            html += '    <span class="det-sector-tile__name">' + name + '</span>';
            html += '    <span class="det-sector-tile__count">' + s.evidence_count + ' events</span>';
            html += '  </div>';
            html += '  <div class="det-sector-tile__bar"><div class="det-sector-tile__bar-fill" style="width:' + barWidth + '%;background:' + barColor + '"></div></div>';
            html += '  <div class="det-sector-tile__meta">';
            html += '    <code>' + s.latest_technique + '</code> ' + escHtml(s.latest_technique_name || "");
            html += '  </div>';
            html += '</div>';
        });
        el.innerHTML = html;
    }

    // ------------------------------------------------------------------
    // Alerts
    // ------------------------------------------------------------------

    function renderAlerts(data) {
        var list = document.getElementById("alertList");
        var count = document.getElementById("alertCount");
        var alerts = data.alerts || [];
        count.textContent = alerts.length;

        if (alerts.length === 0) {
            list.innerHTML = '<li class="det-alert-list__empty">No active alerts.</li>';
            return;
        }
        var html = "";
        // Show newest first
        for (var i = alerts.length - 1; i >= 0; i--) {
            var a = alerts[i];
            var sevColor = SEVERITY_COLORS[a.severity] || "#64748b";
            html += '<li class="det-alert" style="border-left-color:' + sevColor + '">';
            html += '<span class="det-alert__badge" style="background:' + sevColor + '22;color:' + sevColor + '">' + a.severity.toUpperCase() + '</span>';
            html += '<strong class="det-alert__title">' + escHtml(a.title) + '</strong>';
            html += '<p class="det-alert__desc">' + escHtml(a.description) + '</p>';
            html += '</li>';
        }
        list.innerHTML = html;
    }

    // ------------------------------------------------------------------
    // MITRE techniques
    // ------------------------------------------------------------------

    function renderMitre(techniques) {
        var grid = document.getElementById("mitreGrid");
        if (!techniques || techniques.length === 0) {
            grid.innerHTML = '<p class="det-card__empty">No techniques observed yet.</p>';
            return;
        }
        var html = "";
        techniques.forEach(function (t) {
            html += '<div class="mitre-card">';
            html += '<div class="mitre-card__id">' + t.technique + '</div>';
            html += '<div class="mitre-card__name">' + escHtml(t.name) + '</div>';
            html += '<div class="mitre-card__meta">' + t.occurrences + 'x in ' + t.sectors.join(", ") + '</div>';
            html += '</div>';
        });
        grid.innerHTML = html;
    }

    // ------------------------------------------------------------------
    // Evidence Chain (ordered by time, newest first)
    // ------------------------------------------------------------------

    function renderEvidence(chain) {
        var el = document.getElementById("evidenceTimeline");
        if (!chain || chain.length === 0) {
            el.innerHTML = '<p class="det-card__empty">No evidence collected yet. Run the simulation or click "Simulate Attack Event" to generate events.</p>';
            return;
        }
        var html = "";
        // Show newest first
        for (var i = chain.length - 1; i >= 0; i--) {
            var ev = chain[i];
            var sevColor = SEVERITY_COLORS[ev.severity] || "#64748b";
            var ts = ev.timestamp ? ev.timestamp.substring(11, 19) : "";
            var confPct = Math.round(ev.confidence * 100);
            html += '<div class="ev-item" style="border-left-color:' + sevColor + '">';
            html += '<div class="ev-item__header">';
            html += '<span class="ev-item__num">#' + ev.evidence_id + '</span>';
            html += '<span class="ev-item__time">' + ts + '</span>';
            html += '<code class="ev-item__mitre">' + ev.mitre_technique + '</code>';
            html += '<span class="ev-item__sector">' + (SECTOR_NAMES[ev.sector] || ev.sector) + '</span>';
            html += '</div>';
            html += '<p class="ev-item__desc">' + escHtml(ev.description) + '</p>';
            html += '<div class="ev-item__meta">';
            html += 'Confidence: <strong>' + confPct + '%</strong> ';
            html += 'Signal: ' + Math.round(ev.signal_strength * 100) + '% ';
            html += 'Targets: ' + ev.targets.join(", ");
            html += '</div>';
            html += '</div>';
        }
        el.innerHTML = html;
    }

    // ------------------------------------------------------------------
    // Attack path (from twin)
    // ------------------------------------------------------------------

    function renderAttackPath() {
        var el = document.getElementById("detAttackPath");
        api("/api/twin", function (twin) {
            if (!twin || !twin.attack_paths || twin.attack_paths.length === 0) {
                el.innerHTML = '<p class="det-card__empty">No attack path recorded.</p>';
                return;
            }
            var path = twin.attack_paths[0];
            var html = '<div class="attack-path-chain">';
            for (var i = 0; i < path.length; i++) {
                var sid = path[i];
                var icon = SECTOR_ICONS[sid] || "\uD83D\uDD35";
                var name = sid.charAt(0).toUpperCase() + sid.slice(1);
                html += '<div class="ap-node ap-node--compromised">';
                html += '<span class="ap-node__icon">' + icon + '</span>';
                html += '<span class="ap-node__name">' + name + '</span>';
                html += '</div>';
                if (i < path.length - 1) html += '<div class="ap-arrow">\u2192</div>';
            }
            html += '</div>';
            el.innerHTML = html;
        });
    }

    // ------------------------------------------------------------------
    // Simulate Attack Event control
    // ------------------------------------------------------------------

    function simulateEvent() {
        var btn = document.getElementById("btnSimulateEvent");
        if (btn) btn.disabled = true;

        postApi("/api/detection/simulate-event", function (data) {
            if (btn) btn.disabled = false;
            if (!data) return;
            showSimFeedback(data);
            // Immediately poll to refresh
            poll();
        });
    }

    function showSimFeedback(data) {
        var el = document.getElementById("simFeedback");
        if (!el || !data) return;
        var sectorName = SECTOR_NAMES[data.sector] || data.sector;
        var msg = "Synthetic event injected: " + data.mitre_technique + " (" + data.mitre_name + ") targeting " + sectorName;
        el.innerHTML = '<div class="det-feedback-banner">' + escHtml(msg) + '</div>';
        el.style.display = "block";
        // Auto-hide after 4 seconds
        setTimeout(function () { el.style.display = "none"; }, 4000);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    function escHtml(s) {
        if (!s) return "";
        var d = document.createElement("div");
        d.appendChild(document.createTextNode(s));
        return d.innerHTML;
    }

    // ------------------------------------------------------------------
    // Init
    // ------------------------------------------------------------------

    function init() {
        poll();
        setInterval(poll, POLL_MS);

        var btn = document.getElementById("btnSimulateEvent");
        if (btn) {
            btn.addEventListener("click", simulateEvent);
        }

        console.log("[DETECTION] Page initialized.");
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
