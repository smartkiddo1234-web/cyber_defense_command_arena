/**
 * AI Tactical Command And Deployment Simulator — Client-Side Application
 *
 * Provides:
 *  - Status-badge polling (/api/status every 30 s)
 *  - Clickable System-Standby badge that toggles application standby state
 *    via /api/standby/enter and /api/standby/exit
 */

(function () {
    "use strict";

    // ------------------------------------------------------------------
    // Constants
    // ------------------------------------------------------------------

    const STATUS_ENDPOINT   = "/api/status";
    const STANDBY_STATUS    = "/api/standby";
    const STANDBY_ENTER     = "/api/standby/enter";
    const STANDBY_EXIT      = "/api/standby/exit";
    const POLL_INTERVAL_MS  = 10000; // 10 seconds

    // ------------------------------------------------------------------
    // Status badge UI
    // ------------------------------------------------------------------

    /**
     * Update the header status badge to reflect current application state.
     * @param {boolean} isStandby  - true when standby is active
     * @param {string}  simulation - "active" | "idle" | "complete"
     */
    function updateStatusBadge(isStandby, simulation) {
        var badge = document.getElementById("systemBadge");
        if (!badge) return;

        if (isStandby) {
            badge.textContent  = "SYSTEM STANDBY — Click to Resume";
            badge.className    = "status-badge status-badge--standby status-badge--clickable";
            badge.title        = "System is on standby. Click to return to operational state.";
        } else if (simulation === "active") {
            badge.textContent  = "SIMULATION ACTIVE — Click for Standby";
            badge.className    = "status-badge status-badge--active status-badge--clickable";
            badge.title        = "Simulation is running. Click to enter standby mode.";
        } else {
            badge.textContent  = "SYSTEM OPERATIONAL — Click for Standby";
            badge.className    = "status-badge status-badge--operational status-badge--clickable";
            badge.title        = "System is operational. Click to enter standby mode.";
        }
    }

    // ------------------------------------------------------------------
    // Standby toggle
    // ------------------------------------------------------------------

    function toggleStandby() {
        var badge = document.getElementById("systemBadge");
        if (!badge) return;

        // Disable badge while the request is in-flight
        badge.classList.add("status-badge--busy");
        badge.style.pointerEvents = "none";

        // Decide which endpoint to call
        fetch(STANDBY_STATUS)
            .then(function (r) { return r.json(); })
            .then(function (info) {
                var endpoint = info.standby ? STANDBY_EXIT : STANDBY_ENTER;
                return fetch(endpoint, { method: "POST" });
            })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                updateStatusBadge(data.standby, data.simulation_running ? "active" : "idle");
            })
            .catch(function (err) {
                console.warn("[CYBER ARENA] Standby toggle failed:", err.message);
            })
            .finally(function () {
                badge.classList.remove("status-badge--busy");
                badge.style.pointerEvents = "";
            });
    }

    // ------------------------------------------------------------------
    // Periodic status polling
    // ------------------------------------------------------------------

    function fetchStatus() {
        fetch(STATUS_ENDPOINT)
            .then(function (response) {
                if (!response.ok) {
                    throw new Error("Status request failed: " + response.status);
                }
                return response.json();
            })
            .then(function (data) {
                updateStatusBadge(!!data.standby, data.simulation);
            })
            .catch(function (err) {
                console.warn("[CYBER ARENA] Status check failed:", err.message);
            });
    }

    // ------------------------------------------------------------------
    // Initialization
    // ------------------------------------------------------------------

    function init() {
        var badge = document.getElementById("systemBadge");
        if (badge) {
            badge.addEventListener("click", toggleStandby);
            badge.style.cursor = "pointer";
        }

        fetchStatus();
        setInterval(fetchStatus, POLL_INTERVAL_MS);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
