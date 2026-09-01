/**
 * adaptation.js — Phase 17: Adaptive Adversary & Deception Evolution
 *
 * Polls /api/adaptation every 2 seconds, renders the adaptation event log,
 * and provides a manual "Trigger Adaptation" button.
 */

(function () {
    "use strict";

    const POLL_MS = 2000;

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
        try {
            return new Date(iso).toLocaleTimeString();
        } catch (_) {
            return iso;
        }
    }

    function fmtTrigger(t) {
        if (!t) return "—";
        return t.replace(/_/g, " ");
    }

    function badge(sig) {
        const cls = sig ? "adpt-badge adpt-badge--significant" : "adpt-badge adpt-badge--minor";
        const label = sig ? "Significant" : "Minor";
        return `<span class="${cls}">${label}</span>`;
    }

    function stealthDelta(prev, next) {
        if (prev === undefined || next === undefined) return "—";
        const d = next - prev;
        const sign = d >= 0 ? "+" : "";
        const cls = d >= 0.05 ? "adpt-delta adpt-delta--up"
                  : d < 0    ? "adpt-delta adpt-delta--down"
                  :              "adpt-delta adpt-delta--flat";
        return `<span class="${cls}">${sign}${(d * 100).toFixed(1)}%</span>`;
    }

    // -------------------------------------------------------------------------
    // Stats banner
    // -------------------------------------------------------------------------

    function updateStats(data) {
        document.getElementById("statCount").textContent = data.adaptation_count || 0;
        const last = data.last_adaptation;
        if (last) {
            document.getElementById("statLastTrigger").textContent =
                fmtTrigger(last.trigger) || "—";
            document.getElementById("statTechnique").textContent =
                escapeHtml(last.new_technique_name || last.new_technique || "—");
            document.getElementById("statSector").textContent =
                escapeHtml(last.new_sector || "—");
            document.getElementById("statDecoy").textContent =
                escapeHtml(last.new_decoy_name || "none");
        }
    }

    // -------------------------------------------------------------------------
    // Latest adaptation panel
    // -------------------------------------------------------------------------

    function renderLatest(evt) {
        const el = document.getElementById("adptLatest");
        if (!evt) {
            el.innerHTML = `<p class="adpt-empty">No adaptation events yet. Run the simulation and trigger an adaptation.</p>`;
            return;
        }
        el.innerHTML = `
            <div class="adpt-cycle">
                <div class="adpt-cycle__row">
                    <div class="adpt-cycle__block adpt-cycle__block--prev">
                        <div class="adpt-cycle__label">Previous Behaviour</div>
                        <div class="adpt-cycle__sector">${escapeHtml(evt.previous_sector || "—")}</div>
                        <div class="adpt-cycle__technique">${escapeHtml(evt.previous_technique || "—")} ${escapeHtml(evt.previous_technique_name ? "— " + evt.previous_technique_name : "")}</div>
                        <div class="adpt-cycle__target">Target: ${escapeHtml(evt.previous_target || "—")}</div>
                        <div class="adpt-cycle__stealth">Stealth: ${evt.previous_stealth !== undefined ? (evt.previous_stealth * 100).toFixed(1) + "%" : "—"}</div>
                    </div>
                    <div class="adpt-cycle__arrow">&#8594;</div>
                    <div class="adpt-cycle__block adpt-cycle__block--new">
                        <div class="adpt-cycle__label">Adapted Behaviour</div>
                        <div class="adpt-cycle__sector">${escapeHtml(evt.new_sector || "—")}</div>
                        <div class="adpt-cycle__technique">${escapeHtml(evt.new_technique || "—")} ${escapeHtml(evt.new_technique_name ? "— " + evt.new_technique_name : "")}</div>
                        <div class="adpt-cycle__target">Target: ${escapeHtml(evt.new_target || "—")}</div>
                        <div class="adpt-cycle__stealth">Stealth: ${evt.new_stealth !== undefined ? (evt.new_stealth * 100).toFixed(1) + "%" : "—"}</div>
                    </div>
                </div>
                <div class="adpt-cycle__reason">
                    <strong>Reason:</strong> ${escapeHtml(evt.reason || "—")}
                </div>
                <div class="adpt-cycle__meta">
                    <span>Trigger: <em>${fmtTrigger(evt.trigger)}</em></span>
                    <span>${badge(evt.significant)}</span>
                    <span>Deception Response: <strong>${escapeHtml(evt.new_decoy_name || "none")}</strong></span>
                </div>
            </div>`;
    }

    // -------------------------------------------------------------------------
    // Evidence card
    // -------------------------------------------------------------------------

    function renderEvidence(evt) {
        const el = document.getElementById("adptEvidence");
        if (!evt || !evt.detection_event_id) {
            el.innerHTML = `<p class="adpt-empty">No detection evidence generated yet.</p>`;
            return;
        }
        const signalPct = evt.new_signal_strength !== undefined
            ? (evt.new_signal_strength * 100).toFixed(1)
            : "—";
        el.innerHTML = `
            <div class="adpt-evidence-block">
                <div class="adpt-evidence-row">
                    <span class="adpt-evidence-label">Evidence ID</span>
                    <span class="adpt-evidence-value">#${escapeHtml(evt.detection_event_id)}</span>
                </div>
                <div class="adpt-evidence-row">
                    <span class="adpt-evidence-label">Sector</span>
                    <span class="adpt-evidence-value">${escapeHtml(evt.new_sector || "—")}</span>
                </div>
                <div class="adpt-evidence-row">
                    <span class="adpt-evidence-label">MITRE Technique</span>
                    <span class="adpt-evidence-value">${escapeHtml(evt.new_technique || "—")} — ${escapeHtml(evt.new_technique_name || "—")}</span>
                </div>
                <div class="adpt-evidence-row">
                    <span class="adpt-evidence-label">Signal Strength</span>
                    <span class="adpt-evidence-value">${signalPct}%</span>
                </div>
                <div class="adpt-evidence-row">
                    <span class="adpt-evidence-label">Target Asset</span>
                    <span class="adpt-evidence-value">${escapeHtml(evt.new_target || "—")}</span>
                </div>
                <div class="adpt-evidence-row">
                    <span class="adpt-evidence-label">Timestamp</span>
                    <span class="adpt-evidence-value">${fmtTs(evt.timestamp)}</span>
                </div>
            </div>`;
    }

    // -------------------------------------------------------------------------
    // History table
    // -------------------------------------------------------------------------

    function renderTable(events) {
        const tbody = document.getElementById("adptTableBody");
        if (!events || events.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="adpt-empty">No adaptation events yet.</td></tr>`;
            return;
        }
        const rows = events.slice().reverse().map(function (e) {
            return `<tr>
                <td>${e.adaptation_id}</td>
                <td>${fmtTs(e.timestamp)}</td>
                <td>${fmtTrigger(e.trigger)}</td>
                <td>${escapeHtml(e.previous_sector || "—")} → ${escapeHtml(e.new_sector || "—")}</td>
                <td>${escapeHtml(e.previous_technique || "—")} → ${escapeHtml(e.new_technique || "—")}</td>
                <td>${stealthDelta(e.previous_stealth, e.new_stealth)}</td>
                <td>${badge(e.significant)}</td>
                <td>${escapeHtml(e.new_decoy_name || "none")}</td>
            </tr>`;
        });
        tbody.innerHTML = rows.join("");
    }

    // -------------------------------------------------------------------------
    // Polling
    // -------------------------------------------------------------------------

    function poll() {
        fetch("/api/adaptation")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                updateStats(data);
                renderLatest(data.last_adaptation || null);
                renderEvidence(data.last_adaptation || null);
                renderTable(data.events || []);
            })
            .catch(function (err) {
                console.warn("Adaptation poll failed:", err);
            });
    }

    // -------------------------------------------------------------------------
    // Trigger Adaptation button
    // -------------------------------------------------------------------------

    document.addEventListener("DOMContentLoaded", function () {
        poll();
        setInterval(poll, POLL_MS);

        const btn = document.getElementById("btnAdapt");
        if (btn) {
            btn.addEventListener("click", function () {
                btn.disabled = true;
                btn.textContent = "Adapting…";
                fetch("/api/adaptation/adapt", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ trigger: "manual_trigger" }),
                })
                    .then(function (r) { return r.json(); })
                    .then(function (data) {
                        poll();
                    })
                    .catch(function (err) {
                        console.warn("Adaptation trigger failed:", err);
                    })
                    .finally(function () {
                        btn.disabled = false;
                        btn.textContent = "Trigger Adaptation";
                    });
            });
        }
    });
}());
