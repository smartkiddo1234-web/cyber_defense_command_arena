"""
AI Tactical Command And Deployment Simulator — Flask Application

Main entry point for the CYBER ARENA command-center platform.
This is a synthetic cybersecurity simulation for academic competition.

SAFETY: This application does NOT interact with real systems, networks,
or infrastructure. All data is fictional and generated locally.
"""

import os
import logging

from flask import Flask, render_template, jsonify, request

from config import config_map
from database import DatabaseManager
from simulation import get_twin, get_simulator
from simulation.models import AssetStatus
from simulation.simulator import SCENARIO
from detection import get_detection_engine
from deception import get_deception_engine
from command import get_command_engine
from reports import get_report_engine
from intelligence import get_adversary_engine
from impact import get_impact_engine
from adaptation import get_adaptation_engine
from analysis import get_analysis_engine

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app(config_name=None):
    """
    Create and configure the Flask application.

    Args:
        config_name: One of 'development', 'testing', 'production'.
                     Defaults to FLASK_ENV or 'development'.
    """
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    app = Flask(__name__)
    app.config.from_object(config_map.get(config_name, config_map["default"]))

    # ------------------------------------------------------------------
    # Database initialization
    # ------------------------------------------------------------------
    db_manager = DatabaseManager(app.config["DATABASE_PATH"])
    db_manager.initialize()
    app.db = db_manager

    logger.info(
        "Database initialized at %s (schema %s)",
        app.config["DATABASE_PATH"],
        db_manager.get_schema_version(),
    )

    # ------------------------------------------------------------------
    # Context processor — inject app metadata into all templates
    # ------------------------------------------------------------------
    @app.context_processor
    def inject_app_metadata():
        return {
            "app_name": app.config["APP_NAME"],
            "app_short_name": app.config["APP_SHORT_NAME"],
            "app_version": app.config["APP_VERSION"],
            "app_phase": app.config["APP_PHASE"],
        }

    # ------------------------------------------------------------------
    # Wire simulator → detection engine + deception engine
    # ------------------------------------------------------------------
    twin = get_twin()
    det_engine = get_detection_engine()
    dec_engine = get_deception_engine()
    cmd_engine = get_command_engine()
    rpt_engine = get_report_engine()
    adv_engine = get_adversary_engine()
    imp_engine = get_impact_engine()
    adp_engine = get_adaptation_engine()
    ana_engine = get_analysis_engine()

    # Phase 6: wire detection engine into deception engine for evidence integration
    dec_engine.set_detection_engine(det_engine)

    # Phase 11: wire command engine to detection and deception
    cmd_engine.set_engines(det_engine, dec_engine)

    # Phase 12: wire report engine to all engines
    rpt_engine.set_engines(det_engine, dec_engine, cmd_engine, None, twin)

    # Phase 15: wire adversary intelligence engine
    adv_engine.set_engines(simulator=None, detection_engine=det_engine, deception_engine=dec_engine)

    def _on_sim_step(step_index, step_data, event_dict):
        """Callback: each simulator step feeds detection, deception, and adversary intel."""
        det_engine.ingest_event(event_dict)
        dec_engine.evaluate_step(step_index, step_data)

    simulator = get_simulator(twin, on_step=_on_sim_step)

    # Phase 15: wire simulator reference to adversary engine (must be after simulator creation)
    adv_engine.set_engines(simulator=simulator, detection_engine=det_engine, deception_engine=dec_engine)

    # Phase 16: wire impact engine to twin and detection
    imp_engine.set_engines(twin=twin, detection_engine=det_engine)

    # Phase 17: wire adaptation engine to all components
    adp_engine.set_engines(
        simulator=simulator,
        detection_engine=det_engine,
        deception_engine=dec_engine,
        adversary_engine=adv_engine,
        command_engine=cmd_engine,
        twin=twin,
    )

    # Phase 18: wire analysis engine to command engine (read-only)
    ana_engine.set_engines(command_engine=cmd_engine)

    # Phase 12: give report engine the simulator reference
    rpt_engine._simulator = simulator

    # Phase 19: wire optional adaptation + analysis engines into report engine
    rpt_engine.set_optional_engines(adaptation_engine=adp_engine, analysis_engine=ana_engine)

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    def _dashboard_command_data() -> dict:
        """
        Collect the live command-engine data shown in the three Phase-20
        dashboard cards (Defense Units, AI Recommendation, Commander Controls).

        Defense Units: derived from deception containment + commander decisions
        (no separate defense engine exists — use existing data).
        """
        cmd_status = cmd_engine.status()
        dec_status = dec_engine.status()

        # --- Defense Units ---
        # "Units" are the deception decoys + isolation actions (containment).
        # We map existing concepts:
        #   available  = total decoys not yet triggered (armed)
        #   engaged    = decoys actively interacting with the attacker (active)
        #   contained  = 1 if attacker state is CONTAINED or TRAPPED else 0
        #   isolated   = number of isolated assets across all sectors
        isolated_assets = sum(
            1 for sector in twin.sectors.values()
            for asset in sector.assets
            if asset.status.value == "isolated"
        )
        defense_units = {
            "available": dec_status["armed"],
            "engaged": dec_status["active"],
            "contained": 1 if dec_status["attacker_state"] in ("contained", "trapped") else 0,
            "isolated_assets": isolated_assets,
            "attacker_state": dec_status["attacker_state"],
            "posture": dec_status["posture"],
        }

        # --- AI Recommendation ---
        latest_rec = cmd_status["latest_recommendation"]
        ai_rec = {
            "has_recommendation": latest_rec is not None,
            "action": latest_rec["recommended_action"] if latest_rec else None,
            "threat_level": latest_rec["threat_level"] if latest_rec else None,
            "confidence": latest_rec["confidence"] if latest_rec else None,
            "reason": latest_rec["reason"] if latest_rec else None,
            "pending_decisions": cmd_status["pending_decisions"],
            "total_recommendations": cmd_status["total_recommendations"],
        }

        # --- Commander Controls ---
        log = cmd_status["decision_log"]
        last_decided = next((d for d in log if d["decision"] != "pending"), None)
        approved = sum(1 for d in log if d["decision"] == "approve")
        overridden = sum(1 for d in log if d["decision"] == "override")
        dismissed = sum(1 for d in log if d["decision"] == "dismiss")
        commander = {
            "total_decisions": cmd_status["total_decisions"],
            "pending_decisions": cmd_status["pending_decisions"],
            "approved": approved,
            "overridden": overridden,
            "dismissed": dismissed,
            "last_decision": last_decided["decision"] if last_decided else None,
            "last_action": last_decided["commander_action"] if last_decided else None,
            "last_reason": last_decided["commander_reason"] if last_decided else None,
        }

        return {
            "defense_units": defense_units,
            "ai_recommendation": ai_rec,
            "commander_controls": commander,
        }

    @app.route("/")
    def index():
        """Root route — the command-center dashboard."""
        cmd_data = _dashboard_command_data()
        viz_data = _dashboard_viz_data()
        return render_template("dashboard.html",
                               twin_summary=twin.summary(),
                               sim_status=simulator.status(),
                               detection=det_engine.status(),
                               deception=dec_engine.status(),
                               defense_units=cmd_data["defense_units"],
                               ai_recommendation=cmd_data["ai_recommendation"],
                               commander_controls=cmd_data["commander_controls"],
                               viz_data=viz_data)

    @app.route("/api/dashboard")
    def api_dashboard():
        """Live JSON payload for the three Phase-20 dashboard cards."""
        return jsonify(_dashboard_command_data())

    def _dashboard_viz_data() -> dict:
        """
        Collect enriched chart data for the Phase-21 visual dashboard.
        Aggregates detection, twin, deception data for all dashboard chart components.
        """
        det_status = det_engine.status()
        dec_status = dec_engine.status()
        twin_data  = twin.to_dict()

        # 1. Threat Activity (bar chart) — sector heatmap
        sector_heatmap = det_status.get("sector_heatmap", [])

        # 2. Threat Distribution (donut) — from twin sector statuses
        sector_statuses = {}
        for sid, sec in twin_data.get("sectors", {}).items():
            st = sec.get("status", "healthy")
            sector_statuses[st] = sector_statuses.get(st, 0) + 1

        # 3. Confidence Trend (line chart) — evidence timestamps + confidence
        evidence = det_status.get("evidence_chain", [])
        confidence_points = []
        for ev in evidence:
            confidence_points.append({
                "timestamp": ev.get("timestamp", ""),
                "confidence": ev.get("confidence", 0),
                "sector": ev.get("sector", ""),
            })

        # 4. Attack/Dependency Flow — twin attack paths + dependencies
        attack_paths = twin_data.get("attack_paths", [])
        dependencies = twin_data.get("dependencies", [])

        # 5. Sector Risk — combine heatmap signals with twin status
        sector_risk = []
        heatmap_lookup = {h["sector"]: h for h in sector_heatmap}
        for sid, sec in twin_data.get("sectors", {}).items():
            hm = heatmap_lookup.get(sid, {})
            risk_score = hm.get("max_signal", 0) * 0.6
            if sec.get("status") == "compromised":
                risk_score += 0.4
            elif sec.get("status") == "warning":
                risk_score += 0.2
            elif sec.get("status") == "under_attack":
                risk_score += 0.35
            sector_risk.append({
                "sector_id": sid,
                "name": sec.get("name", sid),
                "icon": sec.get("icon", ""),
                "status": sec.get("status", "healthy"),
                "threat_level": sec.get("threat_level", "none"),
                "risk_score": round(min(risk_score, 1.0), 3),
                "evidence_count": hm.get("evidence_count", 0),
                "latest_technique": hm.get("latest_technique", ""),
            })
        sector_risk.sort(key=lambda x: x["risk_score"], reverse=True)

        # 6. Critical Alert — most important current threat
        critical_alert = None
        if sector_heatmap:
            top = max(sector_heatmap, key=lambda h: h.get("max_signal", 0))
            critical_alert = {
                "sector": top.get("sector", ""),
                "signal": top.get("max_signal", 0),
                "technique": top.get("latest_technique_name", ""),
                "technique_id": top.get("latest_technique", ""),
                "evidence_count": top.get("evidence_count", 0),
            }

        # 7. Deception status summary
        dec_summary = {
            "total": dec_status.get("total_decoys", 0),
            "armed": dec_status.get("armed", 0),
            "active": dec_status.get("active", 0),
            "bypassed": dec_status.get("bypassed", 0),
            "attacker_state": dec_status.get("attacker_state", "unknown"),
            "posture": dec_status.get("posture", "unknown"),
            "interactions": dec_status.get("total_interactions", 0),
            "diversions": dec_status.get("total_diversions", 0),
        }

        # 8. Overall status
        overall = {
            "confidence_pct": det_status.get("confidence_pct", 0),
            "risk_level": det_status.get("risk_level", "normal"),
            "threat_level": det_status.get("threat_level", "low"),
            "threat_score": det_status.get("threat_score", 0),
            "active_alerts": det_status.get("active_alerts", 0),
            "total_evidence": det_status.get("total_evidence", 0),
            "sim_status": simulator.status(),
        }

        return {
            "sector_heatmap": sector_heatmap,
            "threat_distribution": sector_statuses,
            "confidence_trend": confidence_points,
            "attack_paths": attack_paths,
            "dependencies": dependencies,
            "sector_risk": sector_risk,
            "critical_alert": critical_alert,
            "deception": dec_summary,
            "overall": overall,
            "twin_summary": twin_data.get("summary", {}),
        }

    @app.route("/api/dashboard/v2")
    def api_dashboard_v2():
        """Phase 21: Enriched chart data for all dashboard visualizations."""
        return jsonify(_dashboard_viz_data())

    @app.route("/digital-twin")
    def digital_twin():
        """Full Digital Twin topology view."""
        return render_template("digital_twin.html", twin_data=twin.to_dict())

    @app.route("/simulation")
    def simulation():
        """Attack simulation control page."""
        return render_template("simulation.html", total_steps=len(SCENARIO))

    @app.route("/detection")
    def detection():
        """Detection and analysis page."""
        return render_template("detection.html")

    @app.route("/deception")
    def deception():
        """Deception grid page."""
        return render_template("deception.html")

    @app.route("/command")
    def command():
        """AI Command & Human-in-the-Loop Response page."""
        return render_template("command.html")

    @app.route("/reports")
    def reports():
        """Reports & Scenario Replay page."""
        return render_template("reports.html")

    @app.route("/adversary")
    def adversary():
        """Adversary Intelligence page (Phase 15)."""
        return render_template("adversary.html")

    @app.route("/impact")
    def impact():
        """National Security Impact page (Phase 16)."""
        return render_template("impact.html")

    @app.route("/adaptation")
    def adaptation():
        """Adaptive Adversary & Deception Evolution page (Phase 17)."""
        return render_template("adaptation.html")

    @app.route("/analysis")
    def analysis():
        """Human vs AI Commander Analysis page (Phase 18)."""
        return render_template("analysis.html")

    # ------------------------------------------------------------------
    # Simulation API
    # ------------------------------------------------------------------

    @app.route("/api/simulation")
    def api_simulation():
        return jsonify(simulator.status())

    @app.route("/api/simulation/start", methods=["POST"])
    def api_sim_start():
        if simulator.is_standby:
            return jsonify({"ok": False, "message": "System is on standby. Exit standby first."}), 409
        if simulator.is_complete:
            return jsonify({"ok": False, "message": "Scenario already complete. Reset first."})
        simulator.start()
        return jsonify({"ok": True, "message": "Simulation started"})

    @app.route("/api/simulation/stop", methods=["POST"])
    def api_sim_stop():
        simulator.stop()
        return jsonify({"ok": True, "message": "Simulation paused"})

    @app.route("/api/simulation/reset", methods=["POST"])
    def api_sim_reset():
        simulator.reset()
        simulator.clear_custom_scenario()
        det_engine.reset()
        dec_engine.reset()
        cmd_engine.reset()
        adv_engine.reset()
        adp_engine.reset()
        return jsonify({"ok": True, "message": "All engines reset"})

    # ------------------------------------------------------------------
    # Standby mode endpoint
    # ------------------------------------------------------------------

    @app.route("/api/standby", methods=["GET"])
    def api_standby_status():
        """Return current standby state."""
        return jsonify(simulator.standby_info())

    @app.route("/api/standby/enter", methods=["POST"])
    def api_standby_enter():
        """Enter application-level standby. Pauses simulation progress; preserves all data."""
        info = simulator.enter_standby()
        return jsonify({"ok": True, "message": "System entered standby.", **info})

    @app.route("/api/standby/exit", methods=["POST"])
    def api_standby_exit():
        """Exit standby and return to normal operational state."""
        info = simulator.exit_standby()
        return jsonify({"ok": True, "message": "System returned to operational state.", **info})

    @app.route("/api/simulation/step", methods=["POST"])
    def api_sim_step():
        if simulator.is_complete:
            return jsonify({"ok": False, "message": "Scenario already complete."})
        simulator.step_once()
        return jsonify({"ok": True, "message": "Advanced one step"})

    # ------------------------------------------------------------------
    # User-Controlled Simulation API (Phase 22)
    # ------------------------------------------------------------------

    @app.route("/api/simulation/sectors")
    def api_sim_sectors():
        """List all sectors with their assets for the path builder."""
        sectors = []
        for sid, sec in twin.sectors.items():
            sectors.append({
                "id": sid,
                "name": sec.name,
                "icon": sec.icon,
                "assets": [{"id": a.asset_id, "name": a.name} for a in sec.assets],
            })
        return jsonify(sectors)

    @app.route("/api/simulation/valid-targets/<sector_id>")
    def api_sim_valid_targets(sector_id):
        """Return valid next-target sectors from a given sector."""
        if sector_id not in twin.sectors:
            return jsonify({"ok": False, "error": f"Unknown sector: {sector_id}"}), 404
        targets = simulator.valid_targets_for(sector_id)
        return jsonify({"ok": True, "sector": sector_id, "targets": targets})

    @app.route("/api/simulation/techniques")
    def api_sim_techniques():
        """List available MITRE ATT&CK techniques for path building."""
        from simulation.simulator import TECHNIQUE_POOL
        techniques = [
            {"id": tid, "name": name}
            for tid, name in sorted(TECHNIQUE_POOL.items())
        ]
        return jsonify(techniques)

    @app.route("/api/simulation/configure", methods=["POST"])
    def api_sim_configure():
        """
        Configure and start a custom user-controlled simulation.

        JSON body: {
            "path": [
                {"sector": "telecom", "technique": "T1021", "threat_level": "high"},
                {"sector": "banking", "technique": "T1486", "threat_level": "severe"}
            ]
        }
        """
        data = request.get_json() or {}
        path = data.get("path", [])

        if not path:
            return jsonify({"ok": False, "error": "Path is empty. Select at least one sector."}), 400

        # Reset all engines before custom run
        simulator.reset()
        det_engine.reset()
        dec_engine.reset()
        cmd_engine.reset()
        adv_engine.reset()
        adp_engine.reset()

        # Convert path entries to configure format
        steps = []
        for entry in path:
            steps.append({
                "sector": entry.get("sector", ""),
                "mitre_technique": entry.get("technique", "T1595"),
                "threat_level": entry.get("threat_level", "moderate"),
            })

        result = simulator.configure(steps)

        if not result.get("ok"):
            return jsonify({
                "ok": False,
                "error": "Path validation failed",
                "errors": result.get("errors", []),
            }), 400

        # Start the custom simulation
        simulator.start()
        return jsonify({
            "ok": True,
            "message": f"Custom simulation started ({result['steps']} steps)",
            "total_steps": result["steps"],
            "warnings": result.get("errors", []),
        })

    @app.route("/api/simulation/mode")
    def api_sim_mode():
        """Return the current simulation mode (default or custom)."""
        return jsonify({
            "mode": "custom" if simulator.is_custom else "default",
            "total_steps": simulator.total_steps,
            "is_complete": simulator.is_complete,
        })

    # ------------------------------------------------------------------
    # Detection API
    # ------------------------------------------------------------------

    @app.route("/api/detection")
    def api_detection():
        return jsonify(det_engine.status())

    @app.route("/api/detection/simulate-event", methods=["POST"])
    def api_simulate_event():
        """
        Inject a random synthetic attack event.
        Updates the detection engine AND mutates the Digital Twin asset status.
        """
        event = det_engine.simulate_event()
        # Also update the Digital Twin so the event is visible there
        for asset_id in event.get("targets", []):
            twin.set_asset_status(asset_id, AssetStatus.UNDER_ATTACK)
            asset = twin.get_asset(asset_id)
            if asset:
                asset.threat_state = event["mitre_technique"]
                activity_msg = (
                    f"[{event['mitre_technique']}] {event['mitre_name']} — "
                    f"{event['description']}"
                )
                asset.activity.append(activity_msg)
        return jsonify(event)

    # ------------------------------------------------------------------
    # Deception API
    # ------------------------------------------------------------------

    @app.route("/api/deception")
    def api_deception():
        """Return deception status with adaptive posture driven by detection risk."""
        # Update posture based on current detection risk level
        risk = det_engine.risk_level().value
        dec_engine.update_posture(risk)
        return jsonify(dec_engine.status())

    @app.route("/api/deception/simulate-decoy", methods=["POST"])
    def api_simulate_decoy():
        """
        Phase 6: Manually inject the simulated attacker into a random decoy.
        Updates deception grid, detection evidence, and Digital Twin.
        """
        result = dec_engine.simulate_attacker_decoy()
        if "error" in result:
            return jsonify(result), 400

        # Update Digital Twin — mark diverted assets as under attack
        for asset_id in result.get("protected_assets", []):
            asset = twin.get_asset(asset_id)
            if asset:
                activity_msg = (
                    f"[DECEPTION] Attacker diverted by decoy '{result['decoy_name']}' "
                    f"— real asset protected."
                )
                asset.activity.append(activity_msg)

        # Update detection risk for the adaptive posture
        risk = det_engine.risk_level().value
        dec_engine.update_posture(risk)

        return jsonify(result)

    @app.route("/api/deception/activate", methods=["POST"])
    def api_activate_decoys():
        """
        Operator command: activate the deception grid.

        Elevates deception posture to ACTIVATE, records a synthetic evidence
        event for every armed decoy, and updates the adversary intelligence
        and dashboard state.  Does NOT interact with real systems.
        """
        result = dec_engine.activate_decoys()

        # Refresh adversary intelligence profile from updated deception state
        adv_engine.update()

        # Update detection risk for the adaptive posture
        risk = det_engine.risk_level().value
        dec_engine.update_posture(risk)

        return jsonify(result)

    @app.route("/api/deception/contain", methods=["POST"])
    def api_contain():
        """
        Phase 6: Freeze/Contain the simulated attacker.
        Changes only the simulated attacker's state inside Cyber Arena.
        Does NOT interact with any real system.
        """
        result = dec_engine.contain_attacker()

        # Also mark any trapped decoy asset in the twin
        if result.get("current_decoy"):
            decoy = dec_engine.decoys.get(result["current_decoy"])
            if decoy:
                for asset_id in decoy.linked_asset_ids:
                    asset = twin.get_asset(asset_id)
                    if asset:
                        asset.activity.append(
                            "[CONTAINMENT] Simulated attacker contained — "
                            "no further activity."
                        )

        # Update command engine so posture reflects containment
        # (no explicit method needed — cmd_engine reads live from det/dec on demand)

        # Refresh adversary intelligence profile from updated deception state
        adv_engine.update()

        return jsonify(result)

    # ------------------------------------------------------------------
    # Command API (Phase 11)
    # ------------------------------------------------------------------

    @app.route("/api/command")
    def api_command():
        """Return the full command engine status and decision log."""
        return jsonify(cmd_engine.status())

    @app.route("/api/command/recommend", methods=["POST"])
    def api_command_recommend():
        """
        Generate an AI recommendation from current threat data.
        Creates a pending decision record awaiting commander input.
        """
        rec = cmd_engine.generate_recommendation()
        if rec is None:
            return jsonify({"error": "No detection evidence available. Run the simulation first."}), 400
        dr = cmd_engine.submit_recommendation(rec)
        return jsonify({
            "recommendation": rec.to_dict(),
            "decision_id": dr.decision_id,
            "message": "AI recommendation generated. Awaiting commander decision.",
        })

    @app.route("/api/command/decide", methods=["POST"])
    def api_command_decide():
        """
        Process a commander's decision on a pending recommendation.

        Expects JSON body with:
        - decision_id: int
        - decision: "approve" | "override" | "dismiss"
        - action: str (required for override)
        - reason: str (required for override, optional for dismiss)
        """
        from flask import request
        try:
            data = request.get_json(force=True)
        except Exception:
            return jsonify({"error": "Invalid JSON body."}), 400
        if data is None:
            data = {}
        decision_id = data.get("decision_id")
        decision = (data.get("decision") or "").lower()

        if decision_id is None:
            return jsonify({"error": "decision_id is required."}), 400

        if decision == "approve":
            dr = cmd_engine.approve_decision(decision_id)
            if dr is None:
                return jsonify({"error": "Decision not found or already decided."}), 400
            return jsonify(dr.to_dict())

        elif decision == "override":
            action = data.get("action", "")
            reason = data.get("reason", "No reason provided.")
            if not action:
                return jsonify({"error": "Override action is required."}), 400
            dr = cmd_engine.override_decision(decision_id, action, reason)
            if dr is None:
                return jsonify({"error": "Decision not found or already decided."}), 400
            return jsonify(dr.to_dict())

        elif decision == "dismiss":
            reason = data.get("reason", "")
            dr = cmd_engine.dismiss_decision(decision_id, reason)
            if dr is None:
                return jsonify({"error": "Decision not found or already decided."}), 400
            return jsonify(dr.to_dict())

        else:
            return jsonify({"error": "Invalid decision. Use approve, override, or dismiss."}), 400

    # ------------------------------------------------------------------
    # Reports API (Phase 12)
    # ------------------------------------------------------------------

    @app.route("/api/reports/generate", methods=["POST"])
    def api_report_generate():
        """Generate a full incident report from all engines."""
        report = rpt_engine.generate_report()
        timeline = rpt_engine.replay_timeline()
        return jsonify({"report": report, "timeline": timeline})

    @app.route("/api/reports/export")
    def api_report_export():
        """Export the report as downloadable JSON."""
        from flask import Response
        data = rpt_engine.export_json()
        return Response(
            data,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=cyber_arena_report.json"},
        )

    @app.route("/api/reports/replay")
    def api_report_replay():
        """Return the chronological replay timeline."""
        timeline = rpt_engine.replay_timeline()
        return jsonify({"timeline": timeline})

    # ------------------------------------------------------------------
    # Adversary Intelligence API (Phase 15)
    # ------------------------------------------------------------------

    @app.route("/api/adversary")
    def api_adversary():
        """Return the current adversary intelligence profile."""
        return jsonify(adv_engine.profile())

    # ------------------------------------------------------------------
    # National Security Impact API (Phase 16)
    # ------------------------------------------------------------------

    @app.route("/api/impact")
    def api_impact():
        """Return the current national security impact assessment."""
        return jsonify(imp_engine.to_dict())

    # ------------------------------------------------------------------
    # Adaptive Adversary API (Phase 17)
    # ------------------------------------------------------------------

    @app.route("/api/adaptation")
    def api_adaptation():
        """Return the current adaptation state and event log."""
        return jsonify(adp_engine.status())

    @app.route("/api/adaptation/adapt", methods=["POST"])
    def api_adaptation_adapt():
        """
        Trigger a manual adversary adaptation cycle.
        The adversary shifts sector, technique, stealth, and target.
        A new detection event is generated and fed into the evidence chain.
        A new deception decoy is recommended.
        """
        from flask import request as _req
        data = {}
        try:
            data = _req.get_json(force=True) or {}
        except Exception:
            pass
        trigger = data.get("trigger", "manual_trigger")

        evt = adp_engine.adapt(trigger_event=trigger)
        if evt is None:
            return jsonify({
                "ok": False,
                "message": "Adaptation not possible (attacker contained or no simulation data).",
            }), 400

        return jsonify({"ok": True, "event": evt.to_dict()})

    # ------------------------------------------------------------------
    # Human vs AI Analysis API (Phase 18)
    # ------------------------------------------------------------------

    @app.route("/api/analysis")
    def api_analysis():
        """Return Human vs AI comparison records and quality metrics."""
        return jsonify(ana_engine.status())

    # ------------------------------------------------------------------
    # Demo Scenario (Phase 13)
    # ------------------------------------------------------------------

    @app.route("/api/demo/run", methods=["POST"])
    def api_demo_run():
        """
        Execute the complete synthetic demo scenario in one call.

        Pipeline:
        1.  Reset all engines + twin
        2.  Seed random for deterministic results
        3.  Run all 8 scenario steps (Military -> Telecom -> Energy -> Healthcare)
        4.  Trigger deception interaction (attacker trapped in decoy)
        5.  Contain the attacker
        6.  Simulate recovery — restore critical assets to healthy
        7.  Generate AI recommendation + commander approval
        8.  Generate final report

        Returns the full report, timeline and summary of actions taken.
        All data is fictional and local.
        """
        import random as _random
        _random.seed(42)  # deterministic demo run

        # 1. Reset everything
        simulator.reset()
        det_engine.reset()
        dec_engine.reset()
        cmd_engine.reset()
        adv_engine.reset()
        adp_engine.reset()

        # 2. Run all 8 scenario steps synchronously
        for _ in range(len(SCENARIO)):
            simulator.step_once()

        # 3. Trigger deception interaction (attacker enters decoy)
        dec_result = dec_engine.simulate_attacker_decoy()
        decoy_used = dec_result.get("decoy_name", "none")

        # 4. Contain the attacker
        contain_result = dec_engine.contain_attacker()
        contained = contain_result.get("attacker_state") == "contained"

        # 4b. Adversary adapts — breaks out and shifts behaviour
        #     (attacker is NOT permanently trapped: state returns to FREE_ROAMING)
        dec_engine._attacker_state_before_adapt = dec_engine.attacker_state
        # Temporarily set to FREE_ROAMING so adaptation can run
        from deception.models import AttackerState as _AttackerState
        dec_engine._attacker_state = _AttackerState.FREE_ROAMING
        adapt_evt = adp_engine.adapt(trigger_event="deception_triggered")
        # Restore contained for the next demo stage
        dec_engine._attacker_state = _AttackerState.CONTAINED
        adaptation_summary = adapt_evt.to_dict() if adapt_evt else None

        # 5. Simulate recovery — restore energy + healthcare assets
        recovered_sectors = []
        for sector_id in ("energy", "healthcare"):
            sector = twin.get_sector(sector_id)
            if sector:
                for asset in sector.assets:
                    if asset.status.value in ("compromised", "under_attack"):
                        asset.status = AssetStatus.HEALTHY
                        asset.threat_state = None
                        asset.activity.append(
                            "[RECOVERY] Asset restored to operational status."
                        )
                sector.recompute_status()
                recovered_sectors.append(sector_id)

        # 6. Generate AI recommendation
        rec = cmd_engine.generate_recommendation()
        decision_id = None
        commander_decision = None
        if rec is not None:
            dr = cmd_engine.submit_recommendation(rec)
            decision_id = dr.decision_id
            # 7. Commander approves
            decided = cmd_engine.approve_decision(decision_id)
            if decided:
                commander_decision = decided.to_dict()

        # 8. Generate final report
        report = rpt_engine.generate_report()
        timeline = rpt_engine.replay_timeline()

        return jsonify({
            "status": "complete",
            "steps_executed": len(SCENARIO),
            "attack_path": report["scenario_summary"].get("attack_path", []),
            "decoy_used": decoy_used,
            "contained": contained,
            "adaptation": adaptation_summary,
            "recovered_sectors": recovered_sectors,
            "decision_id": decision_id,
            "commander_decision": commander_decision,
            "report": report,
            "timeline": timeline,
        })

    @app.route("/api/status")
    def api_status():
        """Health-check endpoint returning basic application state."""
        return jsonify({
            "status": "operational",
            "app": app.config["APP_SHORT_NAME"],
            "version": app.config["APP_VERSION"],
            "phase": app.config["APP_PHASE"],
            "simulation": "active" if simulator.is_running else ("complete" if simulator.is_complete else "idle"),
            "standby": simulator.is_standby,
            "twin_summary": twin.summary(),
            "threat_score": round(det_engine.threat_score(), 3),
            "severity": det_engine.current_severity().value,
            "risk_level": det_engine.risk_level().value,
            "threat_level": det_engine.threat_level().value,
            "deception_active": len(dec_engine.active_decoys) > 0,
            "deception_events": len(dec_engine.events),
            "deception_posture": dec_engine.posture.value,
            "attacker_state": dec_engine.attacker_state.value,
        })

    @app.route("/api/twin")
    def api_twin():
        """Return the full Digital Twin state as JSON."""
        return jsonify(get_twin().to_dict())

    @app.route("/api/twin/sector/<sector_id>")
    def api_sector(sector_id):
        """Return detail for a single sector."""
        twin = get_twin()
        sector = twin.get_sector(sector_id)
        if sector is None:
            return jsonify({"error": "Sector not found"}), 404
        outgoing = [d.to_dict() for d in twin.outgoing_dependencies(sector_id)]
        incoming = [d.to_dict() for d in twin.incoming_dependencies(sector_id)]
        data = sector.to_dict()
        data["outgoing"] = outgoing
        data["incoming"] = incoming
        return jsonify(data)

    @app.route("/api/twin/asset/<asset_id>")
    def api_asset(asset_id):
        """Return detail for a single asset."""
        twin = get_twin()
        asset = twin.get_asset(asset_id)
        if asset is None:
            return jsonify({"error": "Asset not found"}), 404
        data = asset.to_dict()
        data["dependencies"] = twin.asset_dependencies(asset)
        return jsonify(data)

    # ------------------------------------------------------------------
    # Error handlers
    # ------------------------------------------------------------------

    @app.errorhandler(404)
    def not_found(error):
        return render_template("base.html", error="404 — Page not found"), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.exception("Internal server error: %s", error)
        return render_template("base.html", error="500 — Internal server error"), 500

    logger.info(
        "%s v%s (%s) — configuration: %s",
        app.config["APP_NAME"],
        app.config["APP_VERSION"],
        app.config["APP_PHASE"],
        config_name,
    )

    return app


# ---------------------------------------------------------------------------
# Top-level application instance
#
# Exposes the Flask app as a module-level variable named "app" so that WSGI
# servers and Vercel's Flask preset can auto-detect it. The factory
# (create_app) remains available and unchanged for tests and custom configs.
# ---------------------------------------------------------------------------

app = create_app()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Use a non-debug host/port suitable for local development
    app.run(host="127.0.0.1", port=5000, debug=False)
