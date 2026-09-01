/**
 * Adversary Intelligence Page — live polling and rendering.
 */
(function () {
    "use strict";

    var POLL_MS = 2000;
    var pollTimer = null;

    var SECTOR_ICONS = {
        military: "\u2694\uFE0F", government: "\uD83C\uDFDB\uFE0F", telecom: "\uD83D\uDCE1",
        energy: "\u26A1", banking: "\uD83C\uDFE6", healthcare: "\uD83C\uDFE5",
        education: "\uD83C\uDF93", commercial: "\uD83C\uDFEC"
    };

    var ADAPT_LABELS = {
        "unknown": "UNKNOWN",
        "active": "ACTIVE",
        "adapted": "ADAPTED",
        "trapped_in_decoy": "TRAPPED",
        "contained": "CONTAINED"
    };

    // ------------------------------------------------------------------
    // API helpers
    // ------------------------------------------------------------------

    function api(url, cb) {
        var xhr = new XMLHttpRequest();
        xhr.open("GET", url, true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4) {
                try { cb(JSON.parse(xhr.responseText), xhr.status); }
                catch (e) { cb(null, xhr.status); }
            }
        };
        xhr.send();
    }

    // ------------------------------------------------------------------
    // Polling
    // ------------------------------------------------------------------

    function pollAdversary() {
        api("/api/adversary", function (data) {
            if (!data) return;
            renderStats(data);
            renderProgression(data.attack_progression || []);
            renderTechniques(data.observed_techniques || []);
            renderStealthAdapt(data);
            renderBehavior(data.behavior_history || []);
        });
    }

    // ------------------------------------------------------------------
    // Rendering
    // ------------------------------------------------------------------

    function renderStats(d) {
        setText("statId", d.adversary_id || "—");
        setText("statSector", d.current_sector ? d.current_sector.toUpperCase() : "—");
        setText("statStealth", Math.round((d.stealth_level || 0) * 100) + "%");
        setText("statAdapt", ADAPT_LABELS[d.adaptation_status] || d.adaptation_status.toUpperCase());
        setText("statEvidence", d.evidence_collected || 0);
        setText("statConfidence", Math.round((d.threat_confidence || 0) * 100) + "%");
    }

    function renderProgression(path) {
        var el = document.getElementById("attackProgression");
        if (!path || path.length === 0) {
            el.innerHTML = '<p class="adv-card__empty">No attack path recorded. Start the simulation to track adversary movement.</p>';
            return;
        }
        var html = '<div class="attack-path-chain">';
        for (var i = 0; i < path.length; i++) {
            var sid = path[i];
            var icon = SECTOR_ICONS[sid] || "\uD83D\uDD35";
            var name = sid.charAt(0).toUpperCase() + sid.slice(1);
            var isLast = (i === path.length - 1);
            html += '<div class="ap-node' + (isLast ? ' ap-node--compromised' : ' ap-node--warning') + '">';
            html += '<span class="ap-node__icon">' + icon + '</span>';
            html += '<span class="ap-node__name">' + name + '</span>';
            html += '</div>';
            if (i < path.length - 1) html += '<div class="ap-arrow">\u2192</div>';
        }
        html += '</div>';
        el.innerHTML = html;
    }

    function renderTechniques(techniques) {
        var el = document.getElementById("observedTechniques");
        if (!techniques || techniques.length === 0) {
            el.innerHTML = '<p class="adv-card__empty">No techniques observed yet.</p>';
            return;
        }
        var html = '<div class="adv-tech-grid">';
        for (var i = 0; i < techniques.length; i++) {
            var t = techniques[i];
            html += '<div class="adv-tech-item">';
            html += '<code class="adv-tech-item__id">' + (t.technique || "") + '</code>';
            html += '<span class="adv-tech-item__name">' + (t.name || "") + '</span>';
            html += '<span class="adv-tech-item__meta">' + (t.occurrences || 0) + ' occurrence(s)';
            if (t.sectors && t.sectors.length > 0) {
                html += ' in ' + t.sectors.join(", ");
            }
            html += '</span>';
            html += '</div>';
        }
        html += '</div>';
        el.innerHTML = html;
    }

    function renderStealthAdapt(d) {
        var stealthPct = Math.round((d.stealth_level || 0) * 100);
        var fill = document.getElementById("stealthFill");
        if (fill) fill.style.width = stealthPct + "%";
        setText("stealthValue", stealthPct + "%");

        var badge = document.getElementById("adaptBadge");
        if (badge) {
            var label = ADAPT_LABELS[d.adaptation_status] || d.adaptation_status.toUpperCase();
            badge.textContent = label;
            badge.className = "adv-adapt__badge adv-adapt__badge--" + (d.adaptation_status || "unknown");
        }

        setText("firstSeen", d.first_seen ? formatTs(d.first_seen) : "—");
        setText("lastSeen", d.last_seen ? formatTs(d.last_seen) : "—");
        setText("entryPoint", d.entry_point ? d.entry_point.toUpperCase() : "—");
    }

    function renderBehavior(history) {
        var tbody = document.getElementById("behaviorBody");
        if (!history || history.length === 0) {
            tbody.innerHTML = '<tr class="adv-table__empty"><td colspan="5">No behavior recorded yet.</td></tr>';
            return;
        }
        var html = "";
        for (var i = 0; i < history.length; i++) {
            var h = history[i];
            var ts = h.timestamp ? h.timestamp.substring(11, 19) : "";
            var actionClass = h.action.indexOf("deception") === 0 ? "adv-action--deception" : "adv-action--attack";
            html += '<tr>';
            html += '<td class="adv-table__time">' + ts + '</td>';
            html += '<td>' + (h.sector || "") + '</td>';
            html += '<td><span class="' + actionClass + '">' + (h.action || "") + '</span></td>';
            html += '<td>' + (h.technique ? '<code>' + h.technique + '</code>' : '—') + '</td>';
            html += '<td class="adv-table__detail">' + (h.detail || "") + '</td>';
            html += '</tr>';
        }
        tbody.innerHTML = html;
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    function setText(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    function formatTs(iso) {
        if (!iso) return "—";
        try {
            var d = new Date(iso);
            return d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
        } catch (e) {
            return iso;
        }
    }

    // ------------------------------------------------------------------
    // Init
    // ------------------------------------------------------------------

    function init() {
        pollAdversary();
        pollTimer = setInterval(pollAdversary, POLL_MS);
        console.log("[ADVERSARY] Page initialized.");
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
