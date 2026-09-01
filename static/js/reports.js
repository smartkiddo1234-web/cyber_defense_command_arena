/**
 * Reports & Scenario Replay — incident report generation and
 * chronological timeline replay.
 */
(function () {
    "use strict";

    /* --- DOM refs --- */
    var btnGen    = document.getElementById("btnGenReport");
    var btnExport = document.getElementById("btnExport");
    var feedback  = document.getElementById("rptFeedback");

    var elScenario  = document.getElementById("rptScenario");
    var elThreat    = document.getElementById("rptThreat");
    var elOutcome   = document.getElementById("rptOutcome");
    var elAffected  = document.getElementById("rptAffected");
    var elMitre     = document.getElementById("rptMitre");
    var elDeception = document.getElementById("rptDeception");
    var elEvidence  = document.getElementById("rptEvidence");
    var elDecisions = document.getElementById("rptDecisions");
    var elTimeline  = document.getElementById("rptTimeline");

    /* --- Helpers --- */
    function esc(s) {
        var d = document.createElement("div");
        d.textContent = s || "";
        return d.innerHTML;
    }

    function showFeedback(msg, color) {
        feedback.textContent = msg;
        feedback.style.display = "block";
        feedback.style.borderLeftColor = color || "#38bdf8";
        clearTimeout(showFeedback._t);
        showFeedback._t = setTimeout(function () {
            feedback.style.display = "none";
        }, 6000);
    }

    var THREAT_COLORS = {
        low: "#34b872", medium: "#d49a3c", high: "#d44848", critical: "#f43f5e"
    };

    var ACTION_LABELS = {
        monitor: "Monitor", investigate: "Investigate",
        isolate_asset: "Isolate Simulated Asset",
        deploy_deception: "Deploy Deception",
        increase_monitoring: "Increase Monitoring",
        protect_connected: "Protect Connected Assets",
        escalate: "Escalate to Commander"
    };

    /* --- Render sections --- */

    function renderScenario(s) {
        if (!s) { elScenario.innerHTML = '<p class="rpt-card__empty">No scenario data.</p>'; return; }
        var h = '<div class="rpt-summary-grid">';
        h += '<div class="rpt-field"><span class="rpt-label">Status</span><span class="rpt-value">' + esc(s.status) + '</span></div>';
        h += '<div class="rpt-field"><span class="rpt-label">Steps</span><span class="rpt-value">' + s.steps_completed + ' / ' + s.total_steps + '</span></div>';
        h += '<div class="rpt-field"><span class="rpt-label">Attack Path</span><span class="rpt-value">' + esc((s.attack_path || []).join(" -> ")) + '</span></div>';
        h += '</div>';
        h += '<p class="rpt-desc">' + esc(s.scenario_description || "") + '</p>';
        elScenario.innerHTML = h;
    }

    function renderThreat(t) {
        if (!t) { elThreat.innerHTML = '<p class="rpt-card__empty">No threat data.</p>'; return; }
        var color = THREAT_COLORS[t.threat_level] || "#94a3b8";
        var h = '<div class="rpt-metric">';
        h += '<span class="rpt-metric__value" style="color:' + color + '">' + (t.confidence_pct || 0) + '%</span>';
        h += '<span class="rpt-metric__label">Confidence</span></div>';
        h += '<div class="rpt-summary-grid">';
        h += '<div class="rpt-field"><span class="rpt-label">Threat Level</span><span class="rpt-value" style="color:' + color + '">' + esc((t.threat_level || "").toUpperCase()) + '</span></div>';
        h += '<div class="rpt-field"><span class="rpt-label">Risk Level</span><span class="rpt-value">' + esc(t.risk_level || "") + '</span></div>';
        h += '<div class="rpt-field"><span class="rpt-label">Severity</span><span class="rpt-value">' + esc(t.severity || "") + '</span></div>';
        h += '<div class="rpt-field"><span class="rpt-label">Evidence</span><span class="rpt-value">' + (t.total_evidence || 0) + '</span></div>';
        h += '<div class="rpt-field"><span class="rpt-label">Alerts</span><span class="rpt-value">' + (t.active_alerts || 0) + '</span></div>';
        h += '</div>';
        elThreat.innerHTML = h;
    }

    function renderOutcome(o) {
        if (!o) { elOutcome.innerHTML = '<p class="rpt-card__empty">No outcome data.</p>'; return; }
        var color = THREAT_COLORS[o.threat_level] || "#94a3b8";
        var h = '<p class="rpt-outcome__narrative">' + esc(o.narrative) + '</p>';
        h += '<div class="rpt-summary-grid">';
        h += '<div class="rpt-field"><span class="rpt-label">Simulation</span><span class="rpt-value">' + (o.simulation_complete ? "Complete" : "In Progress") + '</span></div>';
        h += '<div class="rpt-field"><span class="rpt-label">Threat</span><span class="rpt-value" style="color:' + color + '">' + esc((o.threat_level || "").toUpperCase()) + '</span></div>';
        h += '<div class="rpt-field"><span class="rpt-label">Attacker</span><span class="rpt-value">' + esc(o.attacker_state || "") + '</span></div>';
        var d = o.commander_decisions || {};
        h += '<div class="rpt-field"><span class="rpt-label">Decisions</span><span class="rpt-value">' + (d.approve || 0) + ' approved, ' + (d.override || 0) + ' overridden, ' + (d.dismiss || 0) + ' dismissed</span></div>';
        h += '</div>';
        elOutcome.innerHTML = h;
    }

    function renderAffected(a) {
        if (!a) { elAffected.innerHTML = '<p class="rpt-card__empty">No data.</p>'; return; }
        var h = '';
        var sectors = a.sectors || {};
        var sKeys = Object.keys(sectors);
        if (sKeys.length > 0) {
            h += '<h4 class="rpt-sub">Sectors</h4><div class="rpt-affected-grid">';
            sKeys.forEach(function (s) {
                var d = sectors[s];
                h += '<div class="rpt-affected-item"><strong>' + esc(s) + '</strong>';
                h += '<span>' + (d.evidence_count || 0) + ' events</span>';
                if (d.techniques && d.techniques.length) {
                    h += '<span class="rpt-affected__tech">' + esc(d.techniques.join(", ")) + '</span>';
                }
                h += '</div>';
            });
            h += '</div>';
        }
        var assets = a.assets || {};
        var aKeys = Object.keys(assets);
        if (aKeys.length > 0) {
            h += '<h4 class="rpt-sub">Compromised Assets</h4><div class="rpt-affected-grid">';
            aKeys.forEach(function (aid) {
                var d = assets[aid];
                h += '<div class="rpt-affected-item"><strong>' + esc(d.name) + '</strong>';
                h += '<span>' + esc(d.sector) + ' &middot; ' + esc(d.status) + '</span>';
                if (d.threat_state) {
                    h += '<span class="rpt-affected__tech">' + esc(d.threat_state) + '</span>';
                }
                h += '</div>';
            });
            h += '</div>';
        }
        if (!h) { h = '<p class="rpt-card__empty">No sectors or assets affected.</p>'; }
        elAffected.innerHTML = h;
    }

    function renderMitre(m) {
        if (!m || m.length === 0) { elMitre.innerHTML = '<p class="rpt-card__empty">No MITRE techniques recorded.</p>'; return; }
        var h = '<div class="rpt-mitre-grid">';
        m.forEach(function (t) {
            h += '<div class="rpt-mitre-item">';
            h += '<span class="rpt-mitre-item__id">' + esc(t.technique) + '</span>';
            h += '<span class="rpt-mitre-item__name">' + esc(t.name) + '</span>';
            h += '<span class="rpt-mitre-item__count">' + (t.count || 0) + ' events</span>';
            h += '</div>';
        });
        h += '</div>';
        elMitre.innerHTML = h;
    }

    function renderDeception(d) {
        if (!d) { elDeception.innerHTML = '<p class="rpt-card__empty">No deception data.</p>'; return; }
        var h = '<div class="rpt-summary-grid">';
        h += '<div class="rpt-field"><span class="rpt-label">Decoys</span><span class="rpt-value">' + (d.total_decoys || 0) + '</span></div>';
        h += '<div class="rpt-field"><span class="rpt-label">Active</span><span class="rpt-value">' + (d.active || 0) + '</span></div>';
        h += '<div class="rpt-field"><span class="rpt-label">Events</span><span class="rpt-value">' + (d.total_events || 0) + '</span></div>';
        h += '<div class="rpt-field"><span class="rpt-label">Interactions</span><span class="rpt-value">' + (d.total_interactions || 0) + '</span></div>';
        h += '<div class="rpt-field"><span class="rpt-label">Diversions</span><span class="rpt-value">' + (d.total_diversions || 0) + '</span></div>';
        h += '<div class="rpt-field"><span class="rpt-label">Attacker</span><span class="rpt-value">' + esc(d.attacker_state || "") + '</span></div>';
        h += '<div class="rpt-field"><span class="rpt-label">Posture</span><span class="rpt-value">' + esc(d.posture || "") + '</span></div>';
        h += '</div>';
        elDeception.innerHTML = h;
    }

    function renderEvidence(chain) {
        if (!chain || chain.length === 0) { elEvidence.innerHTML = '<p class="rpt-card__empty">No evidence recorded.</p>'; return; }
        var h = '<div class="rpt-ev-list">';
        chain.forEach(function (ev, i) {
            var sevColor = THREAT_COLORS[ev.severity] || "#94a3b8";
            h += '<div class="rpt-ev-item">';
            h += '<span class="rpt-ev-item__num">#' + (ev.evidence_id || i + 1) + '</span>';
            h += '<span class="rpt-ev-item__mitre">' + esc(ev.mitre_technique) + '</span>';
            h += '<span class="rpt-ev-item__sector">' + esc(ev.sector) + '</span>';
            h += '<span class="rpt-ev-item__sev" style="color:' + sevColor + '">' + esc(ev.severity) + '</span>';
            h += '<span class="rpt-ev-item__conf">conf: ' + (ev.confidence || 0) + '</span>';
            h += '<span class="rpt-ev-item__contrib">contrib: ' + (ev.score_contribution || 0) + '</span>';
            h += '<p class="rpt-ev-item__desc">' + esc(ev.description) + '</p>';
            h += '</div>';
        });
        h += '</div>';
        elEvidence.innerHTML = h;
    }

    function renderDecisions(decisions) {
        if (!decisions || decisions.length === 0) { elDecisions.innerHTML = '<p class="rpt-card__empty">No decisions recorded.</p>'; return; }
        var h = '<div class="rpt-dec-list">';
        decisions.forEach(function (d) {
            var rec = d.recommendation || {};
            var decClass = "rpt-dec-item--" + (d.decision || "pending");
            h += '<div class="rpt-dec-item ' + decClass + '">';
            h += '<div class="rpt-dec-item__header">';
            h += '<span class="rpt-dec-item__id">#' + d.decision_id + '</span>';
            h += '<span class="rpt-dec-item__badge">' + esc((d.decision || "").toUpperCase()) + '</span>';
            h += '</div>';
            h += '<p class="rpt-dec-item__ai">AI: ' + esc(ACTION_LABELS[rec.recommended_action] || rec.recommended_action || "") + ' (' + esc(rec.threat_level || "") + ')</p>';
            h += '<p class="rpt-dec-item__reason">' + esc(rec.reason || "") + '</p>';
            if (d.decision === "override" && d.commander_action) {
                h += '<p class="rpt-dec-item__override">Commander chose: ' + esc(ACTION_LABELS[d.commander_action] || d.commander_action) + ' &mdash; ' + esc(d.commander_reason || "") + '</p>';
            }
            if (d.decision === "dismiss" && d.commander_reason) {
                h += '<p class="rpt-dec-item__dismiss">Reason: ' + esc(d.commander_reason) + '</p>';
            }
            h += '</div>';
        });
        h += '</div>';
        elDecisions.innerHTML = h;
    }

    function renderTimeline(timeline) {
        if (!timeline || timeline.length === 0) { elTimeline.innerHTML = '<p class="rpt-card__empty">No timeline events. Run the simulation first.</p>'; return; }
        var h = '<div class="rpt-timeline">';
        timeline.forEach(function (ev, i) {
            var phaseClass = "rpt-tl-item--" + ev.phase;
            h += '<div class="rpt-tl-item ' + phaseClass + '">';
            h += '<div class="rpt-tl-item__marker">' + (i + 1) + '</div>';
            h += '<div class="rpt-tl-item__body">';
            h += '<div class="rpt-tl-item__header">';
            h += '<span class="rpt-tl-item__phase">' + esc(ev.phase) + '</span>';
            h += '<span class="rpt-tl-item__sector">' + esc(ev.sector) + '</span>';
            h += '<span class="rpt-tl-item__time">' + esc(ev.timestamp) + '</span>';
            h += '</div>';
            h += '<p class="rpt-tl-item__desc">' + esc(ev.description) + '</p>';
            if (ev.mitre_technique) {
                h += '<span class="rpt-tl-item__mitre">' + esc(ev.mitre_technique) + '</span>';
            }
            if (ev.ai_action) {
                h += '<span class="rpt-tl-item__action">AI: ' + esc(ACTION_LABELS[ev.ai_action] || ev.ai_action) + '</span>';
            }
            if (ev.commander_decision && ev.commander_decision !== "pending") {
                h += '<span class="rpt-tl-item__decision">' + esc(ev.commander_decision) + '</span>';
            }
            // Adaptation-specific detail
            if (ev.type === "adaptation_event") {
                if (ev.previous_technique && ev.new_technique && ev.previous_technique !== ev.new_technique) {
                    h += '<span class="rpt-tl-item__adapt">Technique: ' + esc(ev.previous_technique) + ' → ' + esc(ev.new_technique) + '</span>';
                }
                if (ev.new_decoy_name) {
                    h += '<span class="rpt-tl-item__adapt">New decoy: ' + esc(ev.new_decoy_name) + '</span>';
                }
            }
            h += '</div></div>';
        });
        h += '</div>';
        elTimeline.innerHTML = h;
    }

    /* --- Generate report --- */
    function generateReport() {
        btnGen.disabled = true;
        fetch("/api/reports/generate", {method: "POST",
            headers: {"Content-Type": "application/json"}
        }).then(function (r) { return r.json(); }).then(function (data) {
            btnGen.disabled = false;
            if (data.error) { showFeedback(data.error, "#f59e0b"); return; }
            showFeedback("Report generated successfully.", "#34b872");

            var rpt = data.report;
            renderScenario(rpt.scenario_summary);
            renderThreat(rpt.threat_assessment);
            renderOutcome(rpt.final_outcome);
            renderAffected(rpt.affected_sectors_assets);
            renderMitre(rpt.mitre_techniques);
            renderDeception(rpt.deception_activity);
            renderEvidence(rpt.evidence_chain);
            renderDecisions(rpt.commander_decisions);

            renderTimeline(data.timeline);
        }).catch(function () { btnGen.disabled = false; });
    }

    /* --- Export JSON --- */
    function exportJSON() {
        fetch("/api/reports/export").then(function (r) {
            return r.text();
        }).then(function (text) {
            var blob = new Blob([text], {type: "application/json"});
            var url = URL.createObjectURL(blob);
            var a = document.createElement("a");
            a.href = url;
            a.download = "cyber_arena_report.json";
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showFeedback("Report exported as cyber_arena_report.json", "#34b872");
        }).catch(function () {
            showFeedback("No report data to export. Generate a report first.", "#f59e0b");
        });
    }

    /* --- Init --- */
    btnGen.addEventListener("click", generateReport);
    btnExport.addEventListener("click", exportJSON);
})();
