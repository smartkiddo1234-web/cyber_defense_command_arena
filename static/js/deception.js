/**
 * Deception Page — live decoy status, adaptive response, attacker state,
 * diversion tracking, simulate-decoy, and contain controls.
 */
(function () {
    "use strict";

    var POLL_MS = 2000;

    var TYPE_ICONS = {
        server: "\u{1F5A5}",
        credential: "\u{1F511}",
        service: "\u{1F50C}",
        network_path: "\u{1F6E4}",
        honey_resource: "\u{1F36F}",
        document: "\u{1F4C4}"
    };

    var STATUS_COLORS = {
        armed: "#64748b",
        triggered: "#f59e0b",
        exhausted: "#ef4444",
        bypassed: "#38bdf8"
    };

    var EVENT_COLORS = {
        triggered: "#f59e0b",
        activity: "#38bdf8",
        bypassed: "#a78bfa",
        contained: "#ef4444",
        redirected: "#10b981"
    };

    var POSTURE_COLORS = {
        monitor: "#64748b",
        activate: "#f59e0b",
        redirect: "#f97316",
        contain: "#ef4444"
    };

    var POSTURE_LABELS = {
        monitor: "MONITOR",
        activate: "ACTIVATE DECOYS",
        redirect: "REDIRECT ATTACKER",
        contain: "RECOMMEND CONTAINMENT"
    };

    var ATTACKER_STATE_COLORS = {
        free_roaming: "#ef4444",
        trapped: "#f59e0b",
        contained: "#10b981"
    };

    var ATTACKER_STATE_LABELS = {
        free_roaming: "FREE ROAMING",
        trapped: "TRAPPED IN DECOY",
        contained: "CONTAINED"
    };

    var SECTOR_NAMES = {
        military: "Military", government: "Government", telecom: "Telecom",
        energy: "Energy", banking: "Banking & Finance", healthcare: "Healthcare",
        education: "Education", commercial: "Commercial"
    };

    // ------------------------------------------------------------------
    // API
    // ------------------------------------------------------------------

    function apiGet(url, cb) {
        var xhr = new XMLHttpRequest();
        xhr.open("GET", url, true);
        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4) {
                try { cb(JSON.parse(xhr.responseText)); }
                catch (e) { cb(null); }
            }
        };
        xhr.send();
    }

    function apiPost(url, cb) {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", url, true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4) {
                try { cb(JSON.parse(xhr.responseText)); }
                catch (e) { cb(null); }
            }
        };
        xhr.send();
    }

    // ------------------------------------------------------------------
    // Polling
    // ------------------------------------------------------------------

    function poll() {
        apiGet("/api/deception", function (data) {
            if (!data) return;
            renderStats(data);
            renderAdaptive(data.adaptive || {});
            renderAttackerState(data.adaptive || {});
            renderDecoyGrid(data.decoys || []);
            renderEvents(data.events || []);
            renderActivity(data.decoys || []);
            updateButtons(data.adaptive || {});
        });
    }

    // ------------------------------------------------------------------
    // Stats
    // ------------------------------------------------------------------

    function renderStats(data) {
        setText("statTotal", data.total_decoys || 0);
        setText("statArmed", data.armed || 0);
        setText("statActive", data.active || 0);
        setText("statBypassed", data.bypassed || 0);
        setText("statEvents", data.total_events || 0);
        setText("statDiverted", data.total_diversions || 0);
    }

    function setText(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    // ------------------------------------------------------------------
    // Adaptive Response
    // ------------------------------------------------------------------

    function renderAdaptive(adapt) {
        var posture = adapt.posture || "monitor";
        var color = POSTURE_COLORS[posture] || "#64748b";
        var label = POSTURE_LABELS[posture] || "MONITOR";

        var postureEl = document.getElementById("postureDisplay");
        if (postureEl) {
            postureEl.innerHTML =
                '<span class="dec-adaptive__posture-level" style="background:' + color + '22;color:' + color + ';border:1px solid ' + color + '">' + label + '</span>';
        }

        var descEl = document.getElementById("postureDesc");
        if (descEl) {
            descEl.textContent = adapt.description || "";
        }
    }

    // ------------------------------------------------------------------
    // Attacker State
    // ------------------------------------------------------------------

    function renderAttackerState(adapt) {
        var state = adapt.attacker_state || "free_roaming";
        var color = ATTACKER_STATE_COLORS[state] || "#64748b";
        var label = ATTACKER_STATE_LABELS[state] || "FREE ROAMING";

        var badge = document.getElementById("stateBadge");
        if (badge) {
            badge.textContent = label;
            badge.style.background = color + "22";
            badge.style.color = color;
            badge.style.borderColor = color;
        }

        setText("currentDecoy", adapt.current_decoy_name || "\u2014");
        setText("deceptionStatus",
            state === "trapped" ? "Active \u2014 attacker in decoy" :
            state === "contained" ? "Contained \u2014 all activity frozen" :
            "No active deception"
        );

        // Count total evidence from events
        var evidenceEl = document.getElementById("evidenceCollected");
        if (evidenceEl) {
            // We don't have direct access here, use a placeholder approach
            // The API response has events array but we get adaptive only
            // Use the stat from parent scope
        }
    }

    // ------------------------------------------------------------------
    // Update buttons
    // ------------------------------------------------------------------

    function updateButtons(adapt) {
        var containBtn  = document.getElementById("btnContain");
        var activateBtn = document.getElementById("btnActivateDecoys");
        var state   = adapt.attacker_state || "free_roaming";
        var posture = adapt.posture || "monitor";

        // ---- Freeze / Contain ----
        if (containBtn) {
            var alreadyContained = (state === "contained");
            containBtn.disabled = alreadyContained;
            if (alreadyContained) {
                containBtn.textContent = "Attacker Contained";
                containBtn.classList.remove("btn--danger");
                containBtn.classList.add("btn--disabled");
            } else {
                containBtn.textContent = "Freeze / Contain";
                containBtn.classList.add("btn--danger");
                containBtn.classList.remove("btn--disabled");
            }
        }

        // ---- Activate Decoys ----
        // Disable once posture has been elevated above monitor,
        // or when attacker is already contained (no point activating).
        if (activateBtn) {
            var alreadyActive = (posture !== "monitor");
            activateBtn.disabled = alreadyActive || (state === "contained");
            if (alreadyActive) {
                activateBtn.title = "Deception grid already activated (posture: " + posture + ")";
            } else if (state === "contained") {
                activateBtn.title = "Attacker already contained";
            } else {
                activateBtn.title = "Elevate deception posture and arm all decoys against the simulated attacker";
            }
        }
    }

    // ------------------------------------------------------------------
    // Decoy Grid
    // ------------------------------------------------------------------

    function renderDecoyGrid(decoys) {
        var grid = document.getElementById("decoyGrid");
        if (!decoys || decoys.length === 0) {
            grid.innerHTML = '<p class="dec-card__empty">No decoys deployed.</p>';
            return;
        }
        var html = "";
        decoys.forEach(function (d) {
            var icon = TYPE_ICONS[d.type] || "\u{1F535}";
            var statusColor = STATUS_COLORS[d.status] || "#64748b";
            var typeName = d.type.replace("_", " ");
            typeName = typeName.charAt(0).toUpperCase() + typeName.slice(1);

            html += '<div class="decoy-tile decoy-tile--' + d.status + '">';
            html += '  <div class="decoy-tile__header">';
            html += '    <span class="decoy-tile__icon">' + icon + '</span>';
            html += '    <div>';
            html += '      <div class="decoy-tile__name">' + escHtml(d.name) + '</div>';
            html += '      <div class="decoy-tile__type">' + typeName + ' &middot; ' + (SECTOR_NAMES[d.sector] || d.sector) + '</div>';
            html += '    </div>';
            html += '  </div>';
            html += '  <div class="decoy-tile__body">';
            html += '    <span class="decoy-tile__status" style="color:' + statusColor + '">' + d.status.toUpperCase() + '</span>';
            html += '    <p class="decoy-tile__desc">' + escHtml(d.description) + '</p>';
            if (d.triggered_at) {
                var ts = d.triggered_at.substring(11, 19);
                html += '    <div class="decoy-tile__meta">Triggered: ' + ts + ' &middot; Activity: ' + d.attacker_activity.length + ' entries</div>';
            }
            if (d.diverted_from && d.diverted_from.length > 0) {
                html += '    <div class="decoy-tile__diverted">\u2713 Diverted from: ' + escHtml(d.diverted_from.join(", ")) + '</div>';
            }
            html += '  </div>';
            html += '</div>';
        });
        grid.innerHTML = html;
    }

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------

    function renderEvents(events) {
        var el = document.getElementById("eventList");
        if (!events || events.length === 0) {
            el.innerHTML = '<p class="dec-card__empty">No deception events yet. Run the simulation or use the Simulate Attacker &rarr; Decoy control.</p>';
            return;
        }

        // Also update evidence collected stat
        setText("evidenceCollected", events.length);

        var html = "";
        // Show newest first
        for (var i = events.length - 1; i >= 0; i--) {
            var ev = events[i];
            var color = EVENT_COLORS[ev.event_type] || "#64748b";
            var ts = ev.timestamp ? ev.timestamp.substring(11, 19) : "";
            html += '<div class="dec-event" style="border-left-color:' + color + '">';
            html += '  <div class="dec-event__header">';
            html += '    <span class="dec-event__badge" style="background:' + color + '22;color:' + color + '">' + ev.event_type.toUpperCase() + '</span>';
            html += '    <span class="dec-event__time">' + ts + '</span>';
            html += '    <span class="dec-event__decoy">' + escHtml(ev.decoy_name) + '</span>';
            html += '  </div>';
            html += '  <p class="dec-event__desc">' + escHtml(ev.description) + '</p>';
            if (ev.diverted_from && ev.diverted_from.length > 0) {
                html += '  <div class="dec-event__diverted">\u2713 Diverted attacker from: ' + escHtml(ev.diverted_from.join(", ")) + '</div>';
            }
            if (ev.evidence_boost > 0) {
                html += '  <div class="dec-event__meta">Evidence boost: +' + Math.round(ev.evidence_boost * 100) + '%</div>';
            }
            html += '</div>';
        }
        el.innerHTML = html;
    }

    // ------------------------------------------------------------------
    // Attacker Activity
    // ------------------------------------------------------------------

    function renderActivity(decoys) {
        var el = document.getElementById("activityLog");
        var hasActivity = false;
        var html = "";
        decoys.forEach(function (d) {
            if (!d.attacker_activity || d.attacker_activity.length === 0) return;
            hasActivity = true;
            html += '<div class="dec-activity-block">';
            html += '  <div class="dec-activity-block__header">';
            html += '    <strong>' + escHtml(d.name) + '</strong>';
            html += '    <span class="dec-activity-block__status">' + d.status.toUpperCase() + '</span>';
            html += '  </div>';
            html += '  <ul class="dec-activity-list">';
            d.attacker_activity.forEach(function (act, idx) {
                html += '<li><span class="dec-activity-list__num">' + (idx + 1) + '.</span> ' + escHtml(act) + '</li>';
            });
            html += '  </ul>';
            if (d.diverted_from && d.diverted_from.length > 0) {
                html += '  <div class="dec-activity-block__divert">\u2713 Successfully diverted from: ' + escHtml(d.diverted_from.join(", ")) + '</div>';
            }
            if (d.adapted) {
                html += '  <div class="dec-activity-block__adapt">Attacker recognised deception and adapted.</div>';
            }
            html += '</div>';
        });
        if (!hasActivity) {
            el.innerHTML = '<p class="dec-card__empty">No attacker activity recorded yet.</p>';
        } else {
            el.innerHTML = html;
        }
    }

    // ------------------------------------------------------------------
    // Activate Decoys — elevate posture and arm grid
    // ------------------------------------------------------------------

    window.activateDecoys = function () {
        var btn = document.getElementById("btnActivateDecoys");
        if (btn) btn.disabled = true;

        apiPost("/api/deception/activate", function (data) {
            if (!data) {
                showFeedback("Activate Decoys request failed.", "#ef4444");
                if (btn) btn.disabled = false;
                return;
            }

            if (data.error) {
                showFeedback(data.error, "#ef4444");
                if (btn) btn.disabled = false;
                return;
            }

            var count = data.armed_count || 0;
            var msg = "Deception grid activated \u2014 " + count + " decoy(s) armed and monitoring.";
            showFeedback(msg, "#f59e0b");
            poll(); // immediate refresh of posture, events, stats
        });
    };

    // ------------------------------------------------------------------
    // Simulate Attacker → Decoy
    // ------------------------------------------------------------------

    window.simulateDecoy = function () {
        var btn = document.getElementById("btnSimulateDecoy");
        if (btn) btn.disabled = true;

        apiPost("/api/deception/simulate-decoy", function (data) {
            if (btn) btn.disabled = false;
            if (!data) return;

            if (data.error) {
                showFeedback(data.error, "#ef4444");
                return;
            }

            var msg = "Simulated attacker redirected into decoy \"" + data.decoy_name + "\"";
            if (data.protected_assets && data.protected_assets.length > 0) {
                msg += " \u2014 diverted from " + data.protected_assets.join(", ");
            }
            showFeedback(msg, "#10b981");
            poll(); // immediate refresh
        });
    };

    // ------------------------------------------------------------------
    // Freeze / Contain
    // ------------------------------------------------------------------

    window.containAttacker = function () {
        var btn = document.getElementById("btnContain");
        if (btn) btn.disabled = true;

        apiPost("/api/deception/contain", function (data) {
            if (!data) return;

            var msg = data.message || "Simulated attacker contained.";
            showFeedback(msg, "#10b981");
            poll(); // immediate refresh
        });
    };

    // ------------------------------------------------------------------
    // Feedback banner
    // ------------------------------------------------------------------

    function showFeedback(msg, color) {
        var el = document.getElementById("feedbackBanner");
        if (!el) return;
        el.style.display = "block";
        el.style.borderColor = color;
        el.style.background = color + "11";
        el.innerHTML = '<span style="color:' + color + '">\u2713</span> ' + escHtml(msg);
        setTimeout(function () { el.style.display = "none"; }, 6000);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    function escHtml(s) {
        var d = document.createElement("div");
        d.appendChild(document.createTextNode(s || ""));
        return d.innerHTML;
    }

    // ------------------------------------------------------------------
    // Init
    // ------------------------------------------------------------------

    function init() {
        poll();
        setInterval(poll, POLL_MS);
        console.log("[DECEPTION] Phase 6 page initialized.");
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
