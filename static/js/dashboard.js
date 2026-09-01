/**
 * dashboard.js — Phase 20: Live updates for the three command-integration cards.
 *
 * Polls /api/dashboard every 4 s and updates:
 *   - Defense Units     (#defAvailable, #defEngaged, #defContained, etc.)
 *   - AI Recommendation (#aiAction, #aiThreat, #aiConf, #aiReason, etc.)
 *   - Commander Controls (#cmdTotal, #cmdPending, #cmdApproved, etc.)
 *
 * Phase 23A additions:
 *   - dashboardActivateDecoys() — calls POST /api/deception/activate
 *   - dashboardContainAttacker() — calls POST /api/deception/contain
 *   - Attacker state badge in #defAttackerBadge kept live
 *
 * Falls back silently if an element is absent (handles page reloads).
 * All data is synthetic and local.
 */
(function () {
    'use strict';

    var POLL_INTERVAL = 4000; // ms

    function setText(id, text) {
        var el = document.getElementById(id);
        if (el) el.textContent = text;
    }

    function escapeHtml(s) {
        if (!s) return '';
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    // ----------------------------------------------------------------
    // Defense Units card
    // ----------------------------------------------------------------
    function updateDefense(du) {
        setText('defAvailable', du.available);
        setText('defEngaged', du.engaged);
        setText('defContained', du.contained);
        setText('defIsolated', du.isolated_assets);
        setText('defPosture', du.posture ? du.posture.toUpperCase() : '—');
        var attackerRaw = du.attacker_state || 'free_roaming';
        setText('defAttacker', attackerRaw.replace(/_/g, ' ').toUpperCase());
        updateAttackerBadge(attackerRaw);
        updateContainButton(attackerRaw);
    }

    /** Keep the visible attacker-state badge in the action row in sync. */
    function updateAttackerBadge(state) {
        var badge = document.getElementById('defAttackerBadge');
        if (!badge) return;
        var label = state.replace(/_/g, ' ').toUpperCase();
        badge.textContent = label;
        badge.className = 'def-attacker-badge def-attacker-badge--' + state;
    }

    /** Disable Contain Attacker button when already contained. */
    function updateContainButton(state) {
        var btn = document.getElementById('btnDashContain');
        if (!btn) return;
        btn.disabled = (state === 'contained');
        btn.title = state === 'contained'
            ? 'Attacker already contained'
            : 'Contain simulated attacker — freezes all adversary activity in Cyber Arena';
    }

    // ----------------------------------------------------------------
    // AI Recommendation card
    // ----------------------------------------------------------------
    function updateAIRec(rec) {
        var body = document.getElementById('aiRecBody');
        if (!body) return;

        if (!rec.has_recommendation) {
            body.innerHTML =
                '<p class="panel__description" id="aiNoData">' +
                'No recommendation yet. Run the simulation to generate threat data.</p>' +
                '<a href="/command" class="btn btn--primary" ' +
                'style="margin-top:0.75rem;display:inline-block;">Command Module &rarr;</a>';
            return;
        }

        var conf = rec.confidence !== null ? Math.round(rec.confidence * 100) + '%' : '—';
        var action = rec.action ? rec.action.replace(/_/g, ' ').toUpperCase() : '—';
        var threat = rec.threat_level ? rec.threat_level.toUpperCase() : '—';

        body.innerHTML =
            '<div class="twin-summary-grid">' +
            '<div class="twin-stat"><span class="twin-stat__value" id="aiAction">' + escapeHtml(action) + '</span>' +
            '<span class="twin-stat__label">Action</span></div>' +
            '<div class="twin-stat"><span class="twin-stat__value" id="aiThreat">' + escapeHtml(threat) + '</span>' +
            '<span class="twin-stat__label">Threat</span></div>' +
            '<div class="twin-stat"><span class="twin-stat__value" id="aiConf">' + escapeHtml(conf) + '</span>' +
            '<span class="twin-stat__label">Confidence</span></div>' +
            '<div class="twin-stat"><span class="twin-stat__value" id="aiTotal">' + rec.total_recommendations + '</span>' +
            '<span class="twin-stat__label">Total Recs</span></div>' +
            '<div class="twin-stat"><span class="twin-stat__value" id="aiPending">' + rec.pending_decisions + '</span>' +
            '<span class="twin-stat__label">Pending</span></div>' +
            '</div>' +
            '<p class="panel__description" style="margin-top:0.6rem;" id="aiReason">' +
            escapeHtml(rec.reason || '') + '</p>' +
            '<a href="/command" class="btn btn--primary" ' +
            'style="margin-top:0.75rem;display:inline-block;">Command Module &rarr;</a>';
    }

    // ----------------------------------------------------------------
    // Commander Controls card
    // ----------------------------------------------------------------
    function updateCommander(cc) {
        setText('cmdTotal', cc.total_decisions);
        setText('cmdPending', cc.pending_decisions);
        setText('cmdApproved', cc.approved);
        setText('cmdOverridden', cc.overridden);
        setText('cmdDismissed', cc.dismissed);

        var lastEl = document.getElementById('cmdLastDecision');
        if (lastEl) {
            if (cc.last_decision) {
                var parts = 'Last decision: <strong>' + escapeHtml(cc.last_decision.toUpperCase()) + '</strong>';
                if (cc.last_action) {
                    parts += ' — action: <code>' + escapeHtml(cc.last_action) + '</code>';
                }
                if (cc.last_reason) {
                    parts += ' &mdash; ' + escapeHtml(cc.last_reason);
                }
                lastEl.innerHTML = parts;
            } else {
                lastEl.textContent =
                    'No decisions yet. Generate an AI recommendation via the Command module, then approve or override.';
            }
        }

        // Update badge
        var hdr = document.querySelector('#panelCommander .panel__header');
        if (hdr) {
            var badgeEl = hdr.querySelector('.badge');
            if (badgeEl) {
                if (cc.pending_decisions > 0) {
                    badgeEl.className = 'badge badge--warning';
                    badgeEl.textContent = cc.pending_decisions + ' Pending';
                } else {
                    badgeEl.className = 'badge badge--active';
                    badgeEl.textContent = 'Up to Date';
                }
            }
        }
    }

    // ----------------------------------------------------------------
    // Action feedback banner (inside panelDefense)
    // ----------------------------------------------------------------
    function showActionFeedback(msg, ok) {
        var el = document.getElementById('defenseActionFeedback');
        if (!el) return;
        var color = ok ? '#22c55e' : '#ef4444';
        el.style.display = 'block';
        el.style.borderLeftColor = color;
        el.style.color = color;
        el.textContent = msg;
        setTimeout(function () { el.style.display = 'none'; }, 6000);
    }

    // ----------------------------------------------------------------
    // Activate Decoys — operator command (called from inline onclick)
    // ----------------------------------------------------------------
    window.dashboardActivateDecoys = function () {
        var btn = document.getElementById('btnActivateDecoys');
        if (btn) { btn.disabled = true; }

        fetch('/api/deception/activate', { method: 'POST' })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var msg = data.message || 'Deception grid activated.';
                showActionFeedback(msg, true);
                poll(); // immediate data refresh
            })
            .catch(function (err) {
                showActionFeedback('Activate Decoys failed: ' + err.message, false);
            })
            .finally(function () {
                if (btn) { btn.disabled = false; }
            });
    };

    // ----------------------------------------------------------------
    // Contain Attacker — operator command (called from inline onclick)
    // ----------------------------------------------------------------
    window.dashboardContainAttacker = function () {
        var btn = document.getElementById('btnDashContain');
        if (btn) { btn.disabled = true; }

        fetch('/api/deception/contain', { method: 'POST' })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var msg = data.message || 'Simulated attacker contained.';
                showActionFeedback(msg, true);
                // Update badge immediately without waiting for next poll
                updateAttackerBadge('contained');
                updateContainButton('contained');
                poll(); // full data refresh
            })
            .catch(function (err) {
                showActionFeedback('Contain failed: ' + err.message, false);
                if (btn) { btn.disabled = false; }
            });
    };

    // ----------------------------------------------------------------
    // Poll
    // ----------------------------------------------------------------
    function poll() {
        fetch('/api/dashboard')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.defense_units)    updateDefense(data.defense_units);
                if (data.ai_recommendation) updateAIRec(data.ai_recommendation);
                if (data.commander_controls) updateCommander(data.commander_controls);
            })
            .catch(function () { /* silent — page may be reloading */ });
    }

    // Start polling only when the three panel IDs exist on the page
    if (document.getElementById('panelDefense') ||
        document.getElementById('panelAIRec') ||
        document.getElementById('panelCommander')) {
        setInterval(poll, POLL_INTERVAL);
        poll(); // immediate initial load to populate attacker badge
    }
}());
