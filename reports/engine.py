"""
Reports Engine

Generates structured incident reports and scenario replay timelines by
aggregating data from all Cyber Arena modules:

    Digital Twin  ->  Detection  ->  Evidence Chain
    ->  Deception  ->  AI Recommendation  ->  Commander Decisions  ->  Report

All data is fictional and local.
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional


class ReportEngine:
    """
    Collects snapshots from every engine and produces:
    - generate_report()  — structured incident report (JSON)
    - replay_timeline()  — chronological event sequence for replay
    - export_json()      — plain-text JSON export of the report
    """

    def __init__(self):
        self._det_engine = None
        self._dec_engine = None
        self._cmd_engine = None
        self._simulator = None
        self._twin = None
        self._adp_engine = None   # Phase 19: adaptation events in timeline
        self._ana_engine = None   # Phase 19: analysis summary in report

    def set_engines(self, det_engine, dec_engine, cmd_engine,
                    simulator, twin):
        """Wire all engines for data collection."""
        self._det_engine = det_engine
        self._dec_engine = dec_engine
        self._cmd_engine = cmd_engine
        self._simulator = simulator
        self._twin = twin

    def set_optional_engines(self, adaptation_engine=None, analysis_engine=None):
        """Wire optional Phase 17/18 engines (called after they are created)."""
        if adaptation_engine is not None:
            self._adp_engine = adaptation_engine
        if analysis_engine is not None:
            self._ana_engine = analysis_engine

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report(self) -> dict:
        """
        Build a structured incident report from the current state of
        all engines.

        Returns a dict containing every section required by Phase 12.
        """
        report: Dict = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scenario_summary": self._scenario_summary(),
            "threat_assessment": self._threat_assessment(),
            "affected_sectors_assets": self._affected_sectors_assets(),
            "mitre_techniques": self._mitre_techniques(),
            "evidence_chain": self._evidence_chain(),
            "deception_activity": self._deception_activity(),
            "adaptation_summary": self._adaptation_summary(),
            "ai_recommendations": self._ai_recommendations(),
            "commander_decisions": self._commander_decisions(),
            "analysis_summary": self._analysis_summary(),
            "final_outcome": self._final_outcome(),
        }
        return report

    def replay_timeline(self) -> List[dict]:
        """
        Build a chronological replay of the simulated attack scenario.

        Each entry is a timeline event with: timestamp, phase (step number),
        sector, type, description, and associated data.
        """
        timeline: List[dict] = []

        # 1. Detection evidence (simulator steps + manual events)
        if self._det_engine:
            for ev in self._det_engine.evidence:
                entry = {
                    "timestamp": ev.timestamp.isoformat(),
                    "phase": "detection",
                    "sector": ev.sector,
                    "type": "detection_event",
                    "description": ev.description,
                    "mitre_technique": ev.mitre_technique,
                    "mitre_name": ev.mitre_name,
                    "signal_strength": round(ev.signal_strength, 3),
                    "signal_type": ev.signal_type.value if ev.signal_type else None,
                    "confidence": round(ev.current_confidence(), 3),
                    "score_contribution": round(ev.score_contribution, 4),
                    "targets": list(ev.targets),
                }
                timeline.append(entry)

        # 2. Deception events
        if self._dec_engine:
            for evt in self._dec_engine.events:
                entry = {
                    "timestamp": evt.timestamp.isoformat(),
                    "phase": "deception",
                    "sector": evt.sector,
                    "type": "deception_event",
                    "description": evt.description,
                    "decoy_id": evt.decoy_id,
                    "decoy_name": evt.decoy_name,
                    "event_type": evt.event_type,
                    "attacker_state": evt.attacker_state,
                    "diverted_from": list(evt.diverted_from),
                    "mitre_technique": evt.mitre_technique,
                    "action_type": evt.action_type.value if evt.action_type else None,
                }
                timeline.append(entry)

        # 3. Commander decisions
        if self._cmd_engine:
            for dr in self._cmd_engine.decisions:
                rec = dr.recommendation
                entry = {
                    "timestamp": (
                        dr.decided_at.isoformat() if dr.decided_at
                        else rec.timestamp.isoformat()
                    ),
                    "phase": "command",
                    "sector": rec.affected_sectors[0] if rec.affected_sectors else "unknown",
                    "type": "commander_decision",
                    "description": (
                        f"AI recommended '{rec.recommended_action.value}'. "
                        f"Commander decided: {dr.decision.value}."
                    ),
                    "ai_action": rec.recommended_action.value,
                    "commander_decision": dr.decision.value,
                    "commander_action": dr.commander_action,
                    "commander_reason": dr.commander_reason,
                    "threat_level": rec.threat_level,
                }
                timeline.append(entry)

        # 4. Adaptation events (Phase 17)
        if self._adp_engine:
            for evt in self._adp_engine.events:
                entry = {
                    "timestamp": evt.timestamp.isoformat(),
                    "phase": "adaptation",
                    "sector": evt.new_sector or "unknown",
                    "type": "adaptation_event",
                    "description": evt.reason,
                    "mitre_technique": evt.new_technique,
                    "trigger": evt.trigger,
                    "previous_sector": evt.previous_sector,
                    "new_sector": evt.new_sector,
                    "previous_technique": evt.previous_technique,
                    "new_technique": evt.new_technique,
                    "stealth_delta": round(
                        (evt.new_stealth or 0) - (evt.previous_stealth or 0), 3
                    ),
                    "significant": evt.significant,
                    "new_decoy_name": evt.new_decoy_name,
                    "detection_event_id": evt.detection_event_id,
                }
                timeline.append(entry)

        # Sort chronologically
        timeline.sort(key=lambda e: e["timestamp"])
        return timeline

    def export_json(self) -> str:
        """Return the full report as a formatted JSON string."""
        report = self.generate_report()
        return json.dumps(report, indent=2, default=str)

    # ------------------------------------------------------------------
    # Internal section builders
    # ------------------------------------------------------------------

    def _scenario_summary(self) -> dict:
        """Summary of the scripted attack scenario."""
        if self._simulator is None:
            return {"status": "no simulator", "steps_completed": 0}
        status = self._simulator.status()
        return {
            "status": "complete" if status["complete"] else (
                "running" if status["running"] else "idle"
            ),
            "steps_completed": status["current_step"],
            "total_steps": status["total_steps"],
            "attack_path": status["attack_path"],
            "scenario_description": (
                "Scripted adversary attack progressing through "
                "Military -> Telecom -> Energy -> Healthcare sectors."
            ),
        }

    def _threat_assessment(self) -> dict:
        """Current threat level, score, and severity."""
        if self._det_engine is None:
            return {"threat_score": 0, "threat_level": "low"}
        return {
            "threat_score": round(self._det_engine.threat_score(), 3),
            "threat_level": self._det_engine.threat_level().value,
            "risk_level": self._det_engine.risk_level().value,
            "severity": self._det_engine.current_severity().value,
            "confidence_pct": round(self._det_engine.threat_score() * 100, 1),
            "total_evidence": len(self._det_engine.evidence),
            "active_alerts": len(self._det_engine.active_alerts),
        }

    def _affected_sectors_assets(self) -> dict:
        """Sectors and assets affected during the simulation."""
        sectors = {}
        if self._det_engine:
            for hm in self._det_engine.sector_heatmap():
                sectors[hm["sector"]] = {
                    "evidence_count": hm["evidence_count"],
                    "techniques": hm.get("techniques", []),
                }

        assets = {}
        if self._twin:
            for sector in self._twin.sectors.values():
                for asset in sector.assets:
                    if asset.status.value != "healthy":
                        assets[asset.asset_id] = {
                            "name": asset.name,
                            "sector": sector.sector_id,
                            "status": asset.status.value,
                            "threat_state": asset.threat_state or "",
                        }

        return {"sectors": sectors, "assets": assets}

    def _mitre_techniques(self) -> list:
        """MITRE ATT&CK techniques observed."""
        if self._det_engine is None:
            return []
        return self._det_engine.mitre_summary()

    def _evidence_chain(self) -> list:
        """Full evidence chain with score contributions."""
        if self._det_engine is None:
            return []
        return self._det_engine.evidence_chain()

    def _deception_activity(self) -> dict:
        """Deception engine activity summary."""
        if self._dec_engine is None:
            return {"total_decoys": 0, "active": 0, "events": 0}
        dec_status = self._dec_engine.status()
        return {
            "total_decoys": dec_status["total_decoys"],
            "armed": dec_status["armed"],
            "active": dec_status["active"],
            "bypassed": dec_status["bypassed"],
            "total_events": dec_status["total_events"],
            "total_interactions": dec_status.get("total_interactions", 0),
            "total_diversions": dec_status.get("total_diversions", 0),
            "attacker_state": dec_status["attacker_state"],
            "posture": dec_status["posture"],
            "decoys": [
                {
                    "decoy_id": d["decoy_id"],
                    "name": d["name"],
                    "type": d["type"],
                    "sector": d["sector"],
                    "status": d["status"],
                    "trigger_count": d["trigger_count"],
                    "interactions": len(d.get("interactions", [])),
                }
                for d in dec_status["decoys"]
            ],
        }

    def _ai_recommendations(self) -> list:
        """All AI recommendations generated during the session."""
        if self._cmd_engine is None:
            return []
        return [rec.to_dict() for rec in self._cmd_engine.recommendations]

    def _commander_decisions(self) -> list:
        """Full decision log with overrides and reasons."""
        if self._cmd_engine is None:
            return []
        return self._cmd_engine.decision_log()

    def _adaptation_summary(self) -> dict:
        """Summary of adversary adaptation events (Phase 17)."""
        if self._adp_engine is None or self._adp_engine.adaptation_count == 0:
            return {"adaptation_count": 0, "events": []}
        return {
            "adaptation_count": self._adp_engine.adaptation_count,
            "events": [e.to_dict() for e in self._adp_engine.events],
        }

    def _analysis_summary(self) -> dict:
        """Human vs AI decision quality summary (Phase 18)."""
        if self._ana_engine is None:
            return {"total_decisions": 0}
        m = self._ana_engine.metrics()
        return m.to_dict()

    def _final_outcome(self) -> dict:
        """
        Synthesised final outcome based on simulation state,
        threat level, and commander decisions.
        """
        sim_complete = (
            self._simulator.is_complete if self._simulator else False
        )
        threat_level = (
            self._det_engine.threat_level().value
            if self._det_engine else "low"
        )
        attacker_state = (
            self._dec_engine.attacker_state.value
            if self._dec_engine else "unknown"
        )

        # Count commander decisions by type
        decisions = {"approve": 0, "override": 0, "dismiss": 0, "pending": 0}
        if self._cmd_engine:
            for dr in self._cmd_engine.decisions:
                decisions[dr.decision.value] += 1

        # Determine how many sectors have been recovered
        recovered_sectors = 0
        if self._twin:
            for sector in self._twin.sectors.values():
                sector.recompute_status()
                if sector.status.value == "healthy":
                    recovered_sectors += 1

        # Determine outcome narrative
        if attacker_state == "contained":
            narrative = (
                "Simulated attacker was contained by the commander. "
                "The deception grid successfully diverted and trapped the threat."
            )
        elif attacker_state == "trapped":
            narrative = (
                "Simulated attacker is currently trapped in a decoy. "
                "The deception system has contained the threat within "
                "the simulated environment."
            )
        elif sim_complete and threat_level in ("high", "critical"):
            narrative = (
                "The full attack scenario completed with elevated threat levels. "
                "Multiple sectors were compromised in the simulation. "
                "Commander review of AI recommendations is recommended."
            )
        elif sim_complete:
            narrative = (
                "The full attack scenario completed. Detection and deception "
                "systems tracked the adversary across all target sectors."
            )
        else:
            narrative = (
                "Simulation is in progress. Threat assessment will be "
                "finalised upon scenario completion."
            )

        return {
            "simulation_complete": sim_complete,
            "threat_level": threat_level,
            "attacker_state": attacker_state,
            "commander_decisions": decisions,
            "recovered_sectors": recovered_sectors,
            "narrative": narrative,
        }

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

    def reset(self):
        """No persistent state to clear — report is generated on demand."""
        pass


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[ReportEngine] = None


def get_report_engine() -> ReportEngine:
    """Return the global ReportEngine instance (create on first call)."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = ReportEngine()
    return _engine_instance
