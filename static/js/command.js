/**
 * Command & Response Page — AI recommendations, human-in-the-loop decisions,
 * decision log, override form.
 */
(function () {
    "use strict";

    var POLL_MS = 3000;

    /* --- DOM refs --- */
    var btnGenerate   = document.getElementById("btnGenerate");
    var feedbackEl    = document.getElementById("cmdFeedback");
    var recCard       = document.getElementById("recCard");
    var pendingList   = document.getElementById("pendingList");
    var decisionLog   = document.getElementById("decisionLog");
    var overrideCard  = document.getElementById("overrideCard");

    var statRecs      = document.getElementById("statRecs");
    var statPending   = document.getElementById("statPending");
    var statApproved  = document.getElementById("statApproved");
    var statOverridden = document.getElementById("statOverridden");
    var statDismissed = document.getElementById("statDismissed");

    var overrideDecId      = document.getElementById("overrideDecId");
    var overrideAction     = document.getElementById("overrideAction");
    var overrideReason     = document.getElementById("overrideReason");
    var btnConfirmOverride = document.getElementById("btnConfirmOverride");
    var btnCancelOverride  = document.getElementById("btnCancelOverride");

    /* --- Action label map --- */
    var ACTION_LABELS = {
        monitor: "Monitor",
        investigate: "Investigate",
        isolate_asset: "Isolate Simulated Asset",
        deploy_deception: "Deploy Deception",
        increase_monitoring: "Increase Monitoring",
        protect_connected: "Protect Connected Assets",
        escalate: "Escalate to Commander"
    };

    var THREAT_COLORS = {
        low: "#34b872", medium: "#d49a3c", high: "#d44848", critical: "#f43f5e"
    };

    /* --- Helpers --- */
    function esc(s) {
        var d = document.createElement("div");
        d.textContent = s || "";
        return d.innerHTML;
    }

    function postJSON(url, body) {
        return fetch(url, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(body || {})
        }).then(function (r) { return r.json(); });
    }

    function showFeedback(msg, color) {
        feedbackEl.textContent = msg;
        feedbackEl.style.display = "block";
        feedbackEl.style.borderLeftColor = color || "#38bdf8";
        clearTimeout(showFeedback._t);
        showFeedback._t = setTimeout(function () {
            feedbackEl.style.display = "none";
        }, 6000);
    }

    /* --- Render functions --- */
    function renderRec(rec) {
        if (!rec) { recCard.style.display = "none"; return; }
        recCard.style.display = "";
        document.getElementById("recAssessment").textContent = rec.threat_assessment;
        var tl = document.getElementById("recThreatLevel");
        tl.textContent = rec.threat_level.toUpperCase();
        tl.style.color = THREAT_COLORS[rec.threat_level] || "#94a3b8";
        document.getElementById("recConfidence").textContent = (rec.confidence * 100).toFixed(1) + "%";
        document.getElementById("recSectors").textContent = rec.affected_sectors.join(", ") || "None";
        document.getElementById("recMitre").textContent = rec.mitre_techniques.join(", ") || "None";
        document.getElementById("recActivity").textContent = rec.suspected_activity;
        document.getElementById("recAction").textContent = ACTION_LABELS[rec.recommended_action] || rec.recommended_action;
        document.getElementById("recActionDesc").textContent = rec.action_description || "";
        document.getElementById("recReason").textContent = rec.reason;

        var evList = document.getElementById("recEvidence");
        evList.innerHTML = "";
        (rec.evidence_summary || []).forEach(function (e) {
            var li = document.createElement("li");
            li.textContent = e;
            evList.appendChild(li);
        });
    }

    function renderPending(pending) {
        if (!pending || pending.length === 0) {
            pendingList.innerHTML = '<p class="cmd-card__empty">No pending decisions.</p>';
            return;
        }
        var html = "";
        pending.forEach(function (d) {
            var rec = d.recommendation;
            html += '<div class="cmd-pending">';
            html += '<div class="cmd-pending__header">';
            html += '<span class="cmd-pending__id">Decision #' + d.decision_id + '</span>';
            html += '<span class="cmd-pending__level" style="color:' + (THREAT_COLORS[rec.threat_level] || "#94a3b8") + '">'
                  + esc(rec.threat_level.toUpperCase()) + '</span>';
            html += '</div>';
            html += '<p class="cmd-pending__action">AI recommends: <strong>'
                  + esc(ACTION_LABELS[rec.recommended_action] || rec.recommended_action) + '</strong></p>';
            html += '<p class="cmd-pending__reason">' + esc(rec.reason) + '</p>';
            html += '<div class="cmd-pending__btns">';
            html += '<button class="btn btn--primary cmd-btn-approve" data-id="' + d.decision_id + '">Approve</button>';
            html += '<button class="btn btn--warning cmd-btn-override" data-id="' + d.decision_id + '">Override</button>';
            html += '<button class="btn btn--outline cmd-btn-dismiss" data-id="' + d.decision_id + '">Dismiss</button>';
            html += '</div>';
            html += '</div>';
        });
        pendingList.innerHTML = html;

        /* Attach event listeners */
        pendingList.querySelectorAll(".cmd-btn-approve").forEach(function (btn) {
            btn.addEventListener("click", function () { approveDecision(parseInt(btn.dataset.id)); });
        });
        pendingList.querySelectorAll(".cmd-btn-override").forEach(function (btn) {
            btn.addEventListener("click", function () { showOverrideForm(parseInt(btn.dataset.id)); });
        });
        pendingList.querySelectorAll(".cmd-btn-dismiss").forEach(function (btn) {
            btn.addEventListener("click", function () { dismissDecision(parseInt(btn.dataset.id)); });
        });
    }

    function renderLog(log) {
        if (!log || log.length === 0) {
            decisionLog.innerHTML = '<p class="cmd-card__empty">No decisions recorded yet.</p>';
            return;
        }
        var html = "";
        log.forEach(function (d) {
            var rec = d.recommendation;
            var decClass = "cmd-log--" + d.decision;
            html += '<div class="cmd-log ' + decClass + '">';
            html += '<div class="cmd-log__header">';
            html += '<span class="cmd-log__id">#' + d.decision_id + '</span>';
            html += '<span class="cmd-log__decision">' + esc(d.decision.toUpperCase()) + '</span>';
            html += '<span class="cmd-log__time">' + esc(d.decided_at || "pending") + '</span>';
            html += '</div>';
            html += '<p class="cmd-log__ai">AI: ' + esc(ACTION_LABELS[rec.recommended_action] || rec.recommended_action)
                  + ' (' + esc(rec.threat_level) + ')</p>';
            if (d.decision === "override") {
                html += '<p class="cmd-log__override">Commander chose: '
                      + esc(ACTION_LABELS[d.commander_action] || d.commander_action)
                      + ' — ' + esc(d.commander_reason || "") + '</p>';
            }
            if (d.decision === "dismiss" && d.commander_reason) {
                html += '<p class="cmd-log__reason">Reason: ' + esc(d.commander_reason) + '</p>';
            }
            html += '</div>';
        });
        decisionLog.innerHTML = html;
    }

    function updateStats(data) {
        statRecs.textContent = data.total_recommendations || 0;
        statPending.textContent = data.pending_decisions || 0;
        var log = data.decision_log || [];
        var approved = 0, overridden = 0, dismissed = 0;
        log.forEach(function (d) {
            if (d.decision === "approve") approved++;
            else if (d.decision === "override") overridden++;
            else if (d.decision === "dismiss") dismissed++;
        });
        statApproved.textContent = approved;
        statOverridden.textContent = overridden;
        statDismissed.textContent = dismissed;
    }

    /* --- Actions --- */
    function generateRecommendation() {
        btnGenerate.disabled = true;
        postJSON("/api/command/recommend").then(function (data) {
            btnGenerate.disabled = false;
            if (data.error) {
                showFeedback(data.error, "#f59e0b");
                return;
            }
            showFeedback("AI recommendation generated — awaiting commander decision.", "#34b872");
            renderRec(data.recommendation);
            refreshStatus();
        }).catch(function () { btnGenerate.disabled = false; });
    }

    function approveDecision(id) {
        postJSON("/api/command/decide", {
            decision_id: id, decision: "approve"
        }).then(function (data) {
            if (data.error) { showFeedback(data.error, "#f59e0b"); return; }
            showFeedback("Decision #" + id + " APPROVED by commander.", "#34b872");
            refreshStatus();
        });
    }

    function dismissDecision(id) {
        postJSON("/api/command/decide", {
            decision_id: id, decision: "dismiss", reason: "Dismissed by commander."
        }).then(function (data) {
            if (data.error) { showFeedback(data.error, "#f59e0b"); return; }
            showFeedback("Decision #" + id + " DISMISSED by commander.", "#64748b");
            refreshStatus();
        });
    }

    var _overrideId = null;
    function showOverrideForm(id) {
        _overrideId = id;
        overrideDecId.textContent = id;
        overrideAction.value = "investigate";
        overrideReason.value = "";
        overrideCard.style.display = "";
        overrideCard.scrollIntoView({behavior: "smooth", block: "center"});
    }

    function confirmOverride() {
        var action = overrideAction.value;
        var reason = overrideReason.value.trim() || "No reason provided.";
        postJSON("/api/command/decide", {
            decision_id: _overrideId, decision: "override",
            action: action, reason: reason
        }).then(function (data) {
            if (data.error) { showFeedback(data.error, "#f59e0b"); return; }
            showFeedback("Decision #" + _overrideId + " OVERRIDDEN — commander chose "
                + (ACTION_LABELS[action] || action) + ".", "#d49a3c");
            overrideCard.style.display = "none";
            refreshStatus();
        });
    }

    /* --- Refresh loop --- */
    function refreshStatus() {
        fetch("/api/command").then(function (r) { return r.json(); }).then(function (data) {
            updateStats(data);
            renderPending(data.pending || []);
            renderLog(data.decision_log || []);
            if (data.latest_recommendation) {
                renderRec(data.latest_recommendation);
            }
        }).catch(function () {});
    }

    /* --- Init --- */
    btnGenerate.addEventListener("click", generateRecommendation);
    btnConfirmOverride.addEventListener("click", confirmOverride);
    btnCancelOverride.addEventListener("click", function () {
        overrideCard.style.display = "none";
    });

    refreshStatus();
    setInterval(refreshStatus, POLL_MS);
})();
