/**
 * Simulation Page — controls, path builder, and live polling.
 *
 * Supports two modes:
 *   1. Default (fixed SCENARIO: Military → Telecom → Energy → Healthcare)
 *   2. Custom (user-configured path via Path Builder)
 *
 * Demo Scenario is always the fixed default path.
 */
(function () {
    "use strict";

    var POLL_MS = 1500;
    var pollTimer = null;

    // Path builder state
    var pathSteps = [];       // [{sector, technique, threat_level, name, icon}]
    var allSectors = [];      // loaded from /api/simulation/sectors
    var allTechniques = [];   // loaded from /api/simulation/techniques
    var validTargets = {};    // cache: sector_id → [{sector_id, name, icon, direction, label}]

    // ------------------------------------------------------------------
    // API helpers
    // ------------------------------------------------------------------

    function api(method, url, body, cb) {
        var xhr = new XMLHttpRequest();
        xhr.open(method, url, true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4) {
                try { cb(JSON.parse(xhr.responseText), xhr.status); }
                catch (e) { cb(null, xhr.status); }
            }
        };
        xhr.send(body ? JSON.stringify(body) : null);
    }

    function apiGet(url, cb) { api("GET", url, null, cb); }
    function apiPost(url, body, cb) { api("POST", url, body, cb); }

    // ------------------------------------------------------------------
    // Control actions (default mode)
    // ------------------------------------------------------------------

    window.startSim = function () {
        apiPost("/api/simulation/start", null, function () { pollStatus(); });
    };
    window.stopSim = function () {
        apiPost("/api/simulation/stop", null, function () { pollStatus(); });
    };
    window.resetSim = function () {
        apiPost("/api/simulation/reset", null, function () {
            pathSteps = [];
            validTargets = {};
            renderPathBuilder();
            pollStatus();
        });
    };
    window.stepSim = function () {
        apiPost("/api/simulation/step", null, function () { pollStatus(); });
    };

    window.runDemo = function () {
        var btn = document.getElementById("btnDemo");
        var fb  = document.getElementById("demoFeedback");
        btn.disabled = true;
        btn.textContent = "Running\u2026";
        fb.style.display = "block";
        fb.textContent = "Executing demo scenario\u2026";
        apiPost("/api/demo/run", null, function (data, status) {
            btn.disabled = false;
            btn.textContent = "Run Demo Scenario";
            if (status === 200 && data && data.status === "complete") {
                fb.textContent = "Demo complete: " + data.steps_executed + " steps | "
                    + "Attack path: " + (data.attack_path || []).join(" \u2192 ")
                    + " | Decoy: " + (data.decoy_used || "none")
                    + " | Contained: " + (data.contained ? "yes" : "no")
                    + " | Recovered: " + (data.recovered_sectors || []).join(", ");
                pollStatus();
            } else {
                fb.textContent = "Demo failed. Please reset and try again.";
                fb.style.borderColor = "rgba(212,72,72,0.3)";
                fb.style.color = "#d44848";
            }
        });
    };

    // ------------------------------------------------------------------
    // Path Builder actions
    // ------------------------------------------------------------------

    window.addPathStep = function () {
        var selSector = document.getElementById("selStartSector");
        var selTech   = document.getElementById("selTechnique");
        var selThreat = document.getElementById("selThreatLevel");

        var sectorId = selSector.value;
        if (!sectorId) {
            showFeedback("Please select a sector.", "warning");
            return;
        }

        // Validate reachability (skip for first step)
        if (pathSteps.length > 0) {
            var lastSector = pathSteps[pathSteps.length - 1].sector;
            var targets = validTargets[lastSector] || [];
            var found = targets.some(function (t) { return t.sector_id === sectorId; });
            if (!found) {
                var validNames = targets.map(function (t) { return t.name; }).join(", ");
                showFeedback(
                    "Invalid: '" + sectorId + "' is not reachable from '"
                    + lastSector + "'. Valid targets: " + (validNames || "none"),
                    "error"
                );
                return;
            }
        }

        // Find sector metadata
        var sectorMeta = allSectors.find(function (s) { return s.id === sectorId; });
        var techId = selTech.value;
        var techName = allTechniques.find(function (t) { return t.id === techId; });

        pathSteps.push({
            sector: sectorId,
            name: sectorMeta ? sectorMeta.name : sectorId,
            icon: sectorMeta ? sectorMeta.icon : "\uD83D\uDD35",
            technique: techId,
            technique_name: techName ? techName.name : techId,
            threat_level: selThreat.value,
        });

        // Pre-fetch valid targets for the new last sector
        loadValidTargets(sectorId);

        renderPathBuilder();
        hideFeedback();
    };

    window.removePathStep = function (index) {
        pathSteps.splice(index, 1);
        renderPathBuilder();
        hideFeedback();
    };

    window.clearPath = function () {
        pathSteps = [];
        validTargets = {};
        renderPathBuilder();
        hideFeedback();
    };

    window.configureAndStart = function () {
        if (pathSteps.length === 0) {
            showFeedback("Add at least one step to the path.", "warning");
            return;
        }

        var payload = {
            path: pathSteps.map(function (s) {
                return {
                    sector: s.sector,
                    technique: s.technique,
                    threat_level: s.threat_level,
                };
            })
        };

        var btn = document.getElementById("btnCustomStart");
        btn.disabled = true;
        btn.textContent = "Configuring\u2026";

        apiPost("/api/simulation/configure", payload, function (data, status) {
            btn.disabled = false;
            btn.textContent = "Configure & Start Custom";

            if (status === 200 && data && data.ok) {
                showFeedback(data.message, "success");
                pollStatus();
            } else {
                var errMsg = (data && data.error) ? data.error : "Configuration failed.";
                if (data && data.errors && data.errors.length > 0) {
                    errMsg += "\n" + data.errors.join("\n");
                }
                showFeedback(errMsg, "error");
            }
        });
    };

    // ------------------------------------------------------------------
    // Path Builder rendering
    // ------------------------------------------------------------------

    function renderPathBuilder() {
        renderPathSteps();
        renderPathPreview();
        updateSectorDropdown();
        updateCustomButton();
    }

    function renderPathSteps() {
        var el = document.getElementById("pathSteps");
        if (!el) return;

        if (pathSteps.length === 0) {
            el.innerHTML = "";
            return;
        }

        var html = "";
        pathSteps.forEach(function (step, i) {
            html += '<div class="sim-path-step">';
            html += '<span class="sim-path-step__index">' + (i + 1) + '</span>';
            html += '<span class="sim-path-step__icon">' + step.icon + '</span>';
            html += '<span class="sim-path-step__name">' + escapeHtml(step.name) + '</span>';
            html += '<code class="sim-path-step__tech">' + step.technique + '</code>';
            html += '<span class="sim-path-step__threat sim-path-step__threat--' + step.threat_level + '">' + step.threat_level + '</span>';
            html += '<button class="sim-path-step__remove" onclick="removePathStep(' + i + ')" title="Remove">&times;</button>';
            if (i < pathSteps.length - 1) {
                html += '<span class="sim-path-step__arrow">\u2192</span>';
            }
            html += '</div>';
        });
        el.innerHTML = html;
    }

    function renderPathPreview() {
        var el = document.getElementById("pathPreview");
        if (!el) return;

        if (pathSteps.length === 0) {
            el.innerHTML = '<span class="sim-path-builder__empty">No steps added yet.</span>';
            return;
        }

        var html = '<div class="sim-path-preview">';
        pathSteps.forEach(function (step, i) {
            html += '<span class="sim-path-preview__node">' + step.icon + ' ' + escapeHtml(step.name) + '</span>';
            if (i < pathSteps.length - 1) {
                html += '<span class="sim-path-preview__arrow">\u2192</span>';
            }
        });
        html += '</div>';
        el.innerHTML = html;
    }

    function updateSectorDropdown() {
        var sel = document.getElementById("selStartSector");
        if (!sel) return;

        var currentVal = sel.value;
        sel.innerHTML = '<option value="">Select sector\u2026</option>';

        // If we have steps, only show valid targets from the last sector
        if (pathSteps.length > 0) {
            var lastSector = pathSteps[pathSteps.length - 1].sector;
            var targets = validTargets[lastSector] || [];

            if (targets.length === 0) {
                // Fallback: show all sectors (validation will catch invalid ones)
                allSectors.forEach(function (s) {
                    sel.innerHTML += '<option value="' + s.id + '">' + s.icon + ' ' + escapeHtml(s.name) + '</option>';
                });
            } else {
                targets.forEach(function (t) {
                    var dirLabel = t.direction === "incoming" ? " \u2190" : " \u2192";
                    sel.innerHTML += '<option value="' + t.sector_id + '">'
                        + t.icon + ' ' + escapeHtml(t.name) + dirLabel
                        + ' (' + escapeHtml(t.label) + ')</option>';
                });
            }
        } else {
            // First step: show all sectors
            allSectors.forEach(function (s) {
                sel.innerHTML += '<option value="' + s.id + '">' + s.icon + ' ' + escapeHtml(s.name) + '</option>';
            });
        }

        // Restore previous selection if still valid
        if (currentVal) sel.value = currentVal;
    }

    function updateCustomButton() {
        var btn = document.getElementById("btnCustomStart");
        if (btn) btn.disabled = pathSteps.length === 0;
    }

    function showFeedback(msg, type) {
        var el = document.getElementById("pathFeedback");
        if (!el) return;
        el.style.display = "block";
        el.className = "sim-path-builder__feedback sim-path-builder__feedback--" + (type || "info");
        el.textContent = msg;
    }

    function hideFeedback() {
        var el = document.getElementById("pathFeedback");
        if (el) el.style.display = "none";
    }

    // ------------------------------------------------------------------
    // Polling
    // ------------------------------------------------------------------

    function pollStatus() {
        apiGet("/api/simulation", function (data) {
            if (!data) return;
            renderControls(data);
            renderProgress(data);
            renderAttackPath(data.attack_path || []);
            renderCurrentActivity(data);
            renderEventLog(data.events || []);
        });
    }

    // ------------------------------------------------------------------
    // Rendering
    // ------------------------------------------------------------------

    function renderControls(d) {
        var btnStart = document.getElementById("btnStart");
        var btnStop  = document.getElementById("btnStop");
        var btnStep  = document.getElementById("btnStep");
        var btnDemo  = document.getElementById("btnDemo");
        btnStart.disabled = d.running || d.complete;
        btnStop.disabled  = !d.running;
        btnStep.disabled  = d.running || d.complete;
        if (btnDemo) btnDemo.disabled = d.running;
    }

    function renderProgress(d) {
        var pct = d.total_steps > 0 ? (d.current_step / d.total_steps) * 100 : 0;
        var bar   = document.getElementById("progressBar");
        var label = document.getElementById("progressLabel");
        bar.style.width = pct + "%";
        var mode = d.mode === "custom" ? "Custom" : "Default";
        var state = d.complete ? "Complete" : (d.running ? "Running" : "Idle");
        label.textContent = "Step " + d.current_step + " / " + d.total_steps
            + " \u2014 " + state + " (" + mode + ")";
    }

    function renderAttackPath(path) {
        var el = document.getElementById("attackPathView");
        if (!path || path.length === 0) {
            el.innerHTML = '<p class="sim-panel__empty">No attack path yet. Start the simulation.</p>';
            return;
        }
        var html = '<div class="attack-path-chain">';
        var SECTOR_ICONS = {
            military: "\u2694\uFE0F", government: "\uD83C\uDFDB\uFE0F", telecom: "\uD83D\uDCE1",
            energy: "\u26A1", banking: "\uD83C\uDFE6", healthcare: "\uD83C\uDFE5",
            education: "\uD83C\uDF93", commercial: "\uD83C\uDFEC"
        };
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
    }

    function renderCurrentActivity(d) {
        var el = document.getElementById("currentActivity");
        if (!d.current_sector) {
            el.innerHTML = '<p class="sim-panel__empty">Waiting for simulation to begin\u2026</p>';
            return;
        }
        var html = '<div class="sim-current">';
        html += '<div class="sim-current__row"><span class="sim-current__label">Sector:</span> <strong>' + d.current_sector.toUpperCase() + '</strong></div>';
        if (d.current_technique) {
            html += '<div class="sim-current__row"><span class="sim-current__label">MITRE:</span> <code>' + d.current_technique + '</code> ' + (d.current_technique_name || '') + '</div>';
        }
        if (d.mode) {
            html += '<div class="sim-current__row"><span class="sim-current__label">Mode:</span> <strong>' + d.mode.toUpperCase() + '</strong></div>';
        }
        html += '</div>';
        el.innerHTML = html;
    }

    function renderEventLog(events) {
        var tbody = document.getElementById("eventTableBody");
        if (!events || events.length === 0) {
            tbody.innerHTML = '<tr class="sim-table__empty"><td colspan="6">No events yet.</td></tr>';
            return;
        }
        var html = "";
        events.forEach(function (ev) {
            var ts = ev.timestamp ? ev.timestamp.substring(11, 19) : "";
            html += '<tr>';
            html += '<td>' + ev.step + '</td>';
            html += '<td class="sim-table__time">' + ts + '</td>';
            html += '<td>' + ev.sector_name + '</td>';
            html += '<td><code>' + ev.mitre_technique + '</code></td>';
            html += '<td><span class="badge badge--' + ev.target_status + '">' + ev.target_status + '</span></td>';
            html += '<td class="sim-table__desc">' + ev.description + '</td>';
            html += '</tr>';
        });
        tbody.innerHTML = html;
    }

    // ------------------------------------------------------------------
    // Utility
    // ------------------------------------------------------------------

    function escapeHtml(s) {
        if (!s) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
                        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function loadValidTargets(sectorId) {
        if (validTargets[sectorId]) return;
        apiGet("/api/simulation/valid-targets/" + sectorId, function (data) {
            if (data && data.ok) {
                validTargets[sectorId] = data.targets || [];
                renderPathBuilder();
            }
        });
    }

    // ------------------------------------------------------------------
    // Init
    // ------------------------------------------------------------------

    function init() {
        // Load sectors for path builder
        apiGet("/api/simulation/sectors", function (data) {
            if (data && Array.isArray(data)) {
                allSectors = data;
                renderPathBuilder();
            }
        });

        // Load MITRE techniques
        apiGet("/api/simulation/techniques", function (data) {
            if (data && Array.isArray(data)) {
                allTechniques = data;
                var sel = document.getElementById("selTechnique");
                if (sel) {
                    sel.innerHTML = "";
                    data.forEach(function (t) {
                        sel.innerHTML += '<option value="' + t.id + '">'
                            + escapeHtml(t.name) + ' (' + t.id + ')</option>';
                    });
                }
            }
        });

        pollStatus();
        pollTimer = setInterval(pollStatus, POLL_MS);
        console.log("[SIMULATION] Page initialized with path builder.");
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
