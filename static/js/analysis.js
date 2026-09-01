/**
 * analysis.js — Phase 18: Human vs AI Commander Analysis
 *
 * Polls /api/analysis every 3 seconds and renders:
 * - Decision quality metrics banner
 * - Outcome distribution panel
 * - Disagreements with evidence explanations
 * - Full comparison table
 */

(function () {
    "use strict";

    const POLL_MS = 3000;

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    function escapeHtml(str) {
        if (str === null || str === undefined) return "—";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function fmtTs(iso) {
        if (!iso) return "—";
        try { return new Date(iso).toLocaleTimeString(); } catch (_) { return iso; }
    }

    function fmtPct(val) {
        if (val === null || val === undefined) return "—";
        return (val * 100).toFixed(1) + "%";
    }

    function agreementBadge(agreement) {
        const map = {
            agree:    ["ana-badge ana-badge--agree",    "Agree"],
            override: ["ana-badge ana-badge--override", "Override"],
            dismiss:  ["ana-badge ana-badge--dismiss",  "Dismiss"],
            pending:  ["ana-badge ana-badge--pending",  "Pending"],
        };
        const [cls, label] = map[agreement] || ["ana-badge ana-badge--pending", agreement];
        return `<span class="${cls}">${label}</span>`;
    }

    function outcomeBadge(outcome) {
        const map = {
            contained:            ["ana-outcome ana-outcome--contained",   "Contained"],
            partially_mitigated:  ["ana-outcome ana-outcome--partial",     "Partial"],
            escalated:            ["ana-outcome ana-outcome--escalated",   "Escalated"],
            unknown:              ["ana-outcome ana-outcome--unknown",      "Unknown"],
        };
        const [cls, label] = map[outcome] || ["ana-outcome ana-outcome--unknown", outcome];
        return `<span class="${cls}">${label}</span>`;
    }

    function threatBadge(level) {
        const cls = "ana-threat ana-threat--" + (level || "low").toLowerCase();
        return `<span class="${cls}">${escapeHtml((level || "low").toUpperCase())}</span>`;
    }

    function fmtAction(action) {
        if (!action) return "—";
        return action.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
    }

    // -------------------------------------------------------------------------
    // Metrics banner
    // -------------------------------------------------------------------------

    function updateMetrics(m) {
        document.getElementById("metTotal").textContent      = m.total_decisions  ?? 0;
        document.getElementById("metApproved").textContent   = m.approved         ?? 0;
        document.getElementById("metOverridden").textContent = m.overridden       ?? 0;
        document.getElementById("metDismissed").textContent  = m.dismissed        ?? 0;
        document.getElementById("metAgreement").textContent  = fmtPct(m.agreement_rate);
        document.getElementById("metOverrideRate").textContent = fmtPct(m.override_rate);
        document.getElementById("metAvgConf").textContent    = fmtPct(m.avg_ai_confidence);
    }

    // -------------------------------------------------------------------------
    // Outcome distribution
    // -------------------------------------------------------------------------

    function renderOutcomes(m) {
        const el = document.getElementById("anaOutcomes");
        if (!m || m.total_decisions === 0) {
            el.innerHTML = "<p class=\"ana-empty\">No decisions recorded yet. Run the simulation and submit recommendations via Command.</p>";
            return;
        }
        const oc = m.outcome_counts || {};
        const total = m.total_decided || m.total_decisions || 1;
        const outcomes = [
            { key: "contained",           label: "Contained",           cls: "ana-bar--contained" },
            { key: "partially_mitigated", label: "Partially Mitigated", cls: "ana-bar--partial"   },
            { key: "escalated",           label: "Escalated",           cls: "ana-bar--escalated" },
            { key: "unknown",             label: "Unknown",             cls: "ana-bar--unknown"   },
        ];
        el.innerHTML = outcomes.map(function (o) {
            const count = oc[o.key] || 0;
            const pct = total > 0 ? Math.round((count / total) * 100) : 0;
            return `<div class="ana-bar-row">
                <span class="ana-bar-label">${o.label}</span>
                <div class="ana-bar-track">
                    <div class="ana-bar-fill ${o.cls}" style="width:${pct}%"></div>
                </div>
                <span class="ana-bar-count">${count}</span>
            </div>`;
        }).join("");
    }

    // -------------------------------------------------------------------------
    // Disagreements panel
    // -------------------------------------------------------------------------

    function renderDisagreements(disagreements) {
        const el = document.getElementById("anaDisagreements");
        if (!disagreements || disagreements.length === 0) {
            el.innerHTML = "<p class=\"ana-empty\">No disagreements recorded yet.</p>";
            return;
        }
        el.innerHTML = disagreements.map(function (r) {
            const evidenceHtml = (r.ai_evidence_summary || []).length > 0
                ? "<ul class=\"ana-evidence-list\">" +
                  r.ai_evidence_summary.map(e => `<li>${escapeHtml(e)}</li>`).join("") +
                  "</ul>"
                : "<p class=\"ana-empty\">No evidence summary available.</p>";

            return `<div class="ana-disagree-block">
                <div class="ana-disagree-header">
                    <span class="ana-disagree-id">Decision #${r.decision_id}</span>
                    ${agreementBadge(r.agreement)}
                    ${threatBadge(r.ai_threat_level)}
                    <span class="ana-disagree-ts">${fmtTs(r.rec_timestamp)}</span>
                </div>
                <div class="ana-disagree-body">
                    <div class="ana-disagree-col">
                        <div class="ana-disagree-col-title">AI Recommendation</div>
                        <div class="ana-disagree-action">${escapeHtml(fmtAction(r.ai_action))}</div>
                        <div class="ana-disagree-reason">${escapeHtml(r.ai_reason)}</div>
                        <div class="ana-disagree-evidence-title">Evidence available to AI:</div>
                        ${evidenceHtml}
                    </div>
                    <div class="ana-disagree-col">
                        <div class="ana-disagree-col-title">Commander Decision</div>
                        <div class="ana-disagree-action">${escapeHtml(fmtAction(r.human_action || r.human_decision))}</div>
                        <div class="ana-disagree-reason">${escapeHtml(r.human_reason || "No reason provided.")}</div>
                        <div class="ana-disagree-outcome-row">
                            Simulated outcome: ${outcomeBadge(r.simulated_outcome)}
                        </div>
                    </div>
                </div>
            </div>`;
        }).join("");
    }

    // -------------------------------------------------------------------------
    // Comparison table
    // -------------------------------------------------------------------------

    function renderTable(comparisons) {
        const tbody = document.getElementById("anaTableBody");
        if (!comparisons || comparisons.length === 0) {
            tbody.innerHTML = "<tr><td colspan=\"9\" class=\"ana-empty\">No decisions recorded yet.</td></tr>";
            return;
        }
        tbody.innerHTML = comparisons.slice().reverse().map(function (r) {
            return `<tr>
                <td>${r.decision_id}</td>
                <td>${fmtTs(r.rec_timestamp)}</td>
                <td>${escapeHtml(fmtAction(r.ai_action))}</td>
                <td>${fmtPct(r.ai_confidence)}</td>
                <td>${threatBadge(r.ai_threat_level)}</td>
                <td>${agreementBadge(r.human_decision)}</td>
                <td>${escapeHtml(fmtAction(r.human_action))}</td>
                <td>${agreementBadge(r.agreement)}</td>
                <td>${outcomeBadge(r.simulated_outcome)}</td>
            </tr>`;
        }).join("");
    }

    // -------------------------------------------------------------------------
    // Polling
    // -------------------------------------------------------------------------

    function poll() {
        fetch("/api/analysis")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                updateMetrics(data.metrics || {});
                renderOutcomes(data.metrics || {});
                renderDisagreements(data.disagreements || []);
                renderTable(data.comparisons || []);
            })
            .catch(function (err) {
                console.warn("Analysis poll failed:", err);
            });
    }

    // -------------------------------------------------------------------------
    // Init
    // -------------------------------------------------------------------------

    document.addEventListener("DOMContentLoaded", function () {
        poll();
        setInterval(poll, POLL_MS);
    });
}());
