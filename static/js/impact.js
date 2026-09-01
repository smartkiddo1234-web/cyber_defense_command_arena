/**
 * National Security Impact Page — live polling and rendering.
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

    function pollImpact() {
        api("/api/impact", function (data) {
            if (!data) return;
            renderStats(data);
            renderClassify(data.impact_level || "low");
            renderPriority(data);
            renderChains(data.propagation_chains || []);
            renderAffected(data.propagation_chains || []);
        });
    }

    // ------------------------------------------------------------------
    // Rendering
    // ------------------------------------------------------------------

    function renderStats(d) {
        var level = (d.impact_level || "low").toUpperCase();
        setText("statLevel", level);
        setText("statScore", (d.score || 0).toFixed(3));
        setText("statCompromised", d.total_compromised || 0);
        setText("statAtRisk", d.total_at_risk || 0);
        setText("statPriority", d.priority_sector ? d.priority_sector.toUpperCase() : "\u2014");

        // Color the level stat
        var el = document.getElementById("statLevel");
        if (el) {
            el.className = "imp-stat__value imp-stat__value--" + (d.impact_level || "low");
        }
    }

    function renderClassify(level) {
        var levels = document.querySelectorAll(".imp-level");
        for (var i = 0; i < levels.length; i++) {
            var el = levels[i];
            var dataLevel = el.getAttribute("data-level");
            if (dataLevel === level) {
                el.className = "imp-level imp-level--" + level + " imp-level--active";
            } else {
                el.className = "imp-level" + (dataLevel === "low" ? " imp-level--low" : "");
            }
        }
    }

    function renderPriority(d) {
        var el = document.getElementById("priorityPanel");
        if (!d.priority_sector) {
            el.innerHTML = '<p class="imp-card__empty">No defensive priority identified yet.</p>';
            return;
        }
        var sector = d.priority_sector;
        var icon = SECTOR_ICONS[sector] || "\uD83D\uDD35";
        var name = sector.charAt(0).toUpperCase() + sector.slice(1);
        var html = '<div class="imp-priority">';
        html += '<div class="imp-priority__header">';
        html += '<span class="imp-priority__icon">' + icon + '</span>';
        html += '<span class="imp-priority__name">' + name + '</span>';
        html += '<span class="imp-priority__badge">PRIORITY</span>';
        html += '</div>';
        html += '<p class="imp-priority__reason">' + escapeHtml(d.priority_reason || "") + '</p>';
        html += '</div>';
        el.innerHTML = html;
    }

    function renderChains(chains) {
        var el = document.getElementById("propagationChains");
        if (!chains || chains.length === 0) {
            el.innerHTML = '<p class="imp-card__empty">No propagation chains. Start the simulation to see cascading risk.</p>';
            return;
        }
        var html = '';
        for (var c = 0; c < chains.length; c++) {
            var chain = chains[c];
            html += '<div class="imp-chain">';
            html += '<span class="imp-chain__label">From ' + capitalize(chain.origin) + ':</span>';
            html += '<div class="attack-path-chain">';
            for (var p = 0; p < chain.path.length; p++) {
                var sid = chain.path[p];
                var icon = SECTOR_ICONS[sid] || "\uD83D\uDD35";
                var name = capitalize(sid);
                var isOrigin = (p === 0);
                html += '<div class="ap-node' + (isOrigin ? ' ap-node--compromised' : ' ap-node--warning') + '">';
                html += '<span class="ap-node__icon">' + icon + '</span>';
                html += '<span class="ap-node__name">' + name + '</span>';
                html += '</div>';
                if (p < chain.path.length - 1) html += '<div class="ap-arrow">\u2192</div>';
            }
            html += '</div></div>';
        }
        el.innerHTML = html;
    }

    function renderAffected(chains) {
        var tbody = document.getElementById("affectedBody");
        if (!chains || chains.length === 0) {
            tbody.innerHTML = '<tr class="imp-table__empty"><td colspan="5">No affected sectors yet.</td></tr>';
            return;
        }
        var html = "";
        for (var c = 0; c < chains.length; c++) {
            var assessments = chains[c].assessments || [];
            for (var a = 0; a < assessments.length; a++) {
                var r = assessments[a];
                var riskClass = r.risk_score >= 0.5 ? "imp-risk--high" : (r.risk_score >= 0.2 ? "imp-risk--moderate" : "imp-risk--low");
                html += '<tr>';
                html += '<td>' + capitalize(r.source_sector) + '</td>';
                html += '<td><strong>' + capitalize(r.affected_sector) + '</strong></td>';
                html += '<td class="imp-table__dep">' + escapeHtml(r.dependency_label) + '</td>';
                html += '<td><span class="' + riskClass + '">' + r.risk_score.toFixed(3) + '</span></td>';
                html += '<td>';
                var assets = r.critical_assets || [];
                for (var i = 0; i < assets.length; i++) {
                    html += '<span class="imp-asset-tag imp-asset-tag--' + assets[i].criticality + '">' + assets[i].name + '</span> ';
                }
                if (assets.length === 0) html += '\u2014';
                html += '</td>';
                html += '</tr>';
            }
        }
        if (!html) {
            html = '<tr class="imp-table__empty"><td colspan="5">No affected sectors yet.</td></tr>';
        }
        tbody.innerHTML = html;
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    function setText(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = String(val);
    }

    function capitalize(s) {
        if (!s) return "";
        return s.charAt(0).toUpperCase() + s.slice(1);
    }

    function escapeHtml(s) {
        var div = document.createElement("div");
        div.appendChild(document.createTextNode(s));
        return div.innerHTML;
    }

    // ------------------------------------------------------------------
    // Init
    // ------------------------------------------------------------------

    function init() {
        pollImpact();
        pollTimer = setInterval(pollImpact, POLL_MS);
        console.log("[IMPACT] Page initialized.");
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
