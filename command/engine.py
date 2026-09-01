"""
Command Engine

Analyses the current threat picture from the Detection and Deception
engines, generates AI defensive recommendations, and processes the human
commander's decisions.

The AI NEVER automatically executes an action — every recommendation
requires explicit commander confirmation (APPROVE / OVERRIDE / DISMISS).

All processing is entirely fictional and local.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from command.models import (
    ACTION_DESCRIPTIONS,
    AIRecommendation,
    CommandDecision,
    DecisionRecord,
    DefensiveAction,
)


# ---------------------------------------------------------------------------
# Critical infrastructure priority (for national-security scenario)
# Sectors are ordered by criticality — military first, then civilian infra.
# ---------------------------------------------------------------------------

CRITICAL_SECTORS = ["military", "energy", "healthcare", "telecom", "banking",
                    "government", "commercial", "education"]

# Sectors considered "civilian critical" (downstream from military)
CIVILIAN_CRITICAL = {"energy", "healthcare", "telecom", "banking"}


class CommandEngine:
    """
    Generates AI recommendations and records commander decisions.

    Depends on:
    - DetectionEngine  (threat_score, threat_level, evidence, sector_heatmap)
    - DeceptionEngine  (attacker_state, events, decoys, posture)
    """

    def __init__(self):
        self.recommendations: List[AIRecommendation] = []
        self.decisions: List[DecisionRecord] = []
        self._next_rec_id = 1
        self._next_dec_id = 1
        self._det_engine = None
        self._dec_engine = None

    def set_engines(self, det_engine, dec_engine):
        """Wire the detection and deception engines."""
        self._det_engine = det_engine
        self._dec_engine = dec_engine

    # ------------------------------------------------------------------
    # Recommendation generation
    # ------------------------------------------------------------------

    def generate_recommendation(self) -> Optional[AIRecommendation]:
        """
        Analyse the current threat picture and produce a recommendation.

        Returns None if there is no detection evidence (nothing to analyse).
        """
        if self._det_engine is None:
            return None
        if len(self._det_engine.evidence) == 0:
            return None

        score = self._det_engine.threat_score()
        threat_level = self._det_engine.threat_level().value
        risk = self._det_engine.risk_level()
        heatmap = self._det_engine.sector_heatmap()
        mitre = self._det_engine.mitre_summary()

        # Affected sectors (ordered by evidence count desc)
        affected_sectors = sorted(
            [h["sector"] for h in heatmap],
            key=lambda s: next(
                (h["evidence_count"] for h in heatmap if h["sector"] == s), 0
            ),
            reverse=True,
        )

        # Active MITRE techniques
        active_techniques = [m["technique"] for m in mitre]

        # Build evidence summary (top 5 evidence items by confidence)
        chain = self._det_engine.evidence_chain()
        evidence_summary = []
        for ev in sorted(chain, key=lambda e: e["confidence"], reverse=True)[:5]:
            evidence_summary.append(
                f"[{ev['mitre_technique']}] {ev['mitre_name']} in {ev['sector']} "
                f"(confidence {ev['confidence']:.2f})"
            )

        # Deception state
        attacker_state = "unknown"
        deception_active = False
        if self._dec_engine is not None:
            attacker_state = self._dec_engine.attacker_state.value
            deception_active = len(self._dec_engine.active_decoys) > 0

        # --- Determine suspected activity ---
        suspected_activity = self._describe_activity(
            active_techniques, affected_sectors, attacker_state
        )

        # --- Detect national-security scenario ---
        is_national_security = self._check_national_security(
            affected_sectors, active_techniques
        )

        # --- Choose recommended action ---
        action = self._choose_action(
            score, threat_level, risk.value, attacker_state,
            is_national_security, deception_active, affected_sectors,
        )

        # --- Build threat assessment text ---
        assessment = self._build_assessment(
            score, threat_level, affected_sectors, is_national_security,
            attacker_state,
        )

        # --- Build reason text ---
        reason = self._build_reason(
            action, score, threat_level, affected_sectors,
            is_national_security, deception_active, attacker_state,
        )

        rec = AIRecommendation(
            rec_id=self._next_rec_id,
            timestamp=datetime.now(timezone.utc),
            threat_assessment=assessment,
            affected_sectors=affected_sectors,
            suspected_activity=suspected_activity,
            recommended_action=action,
            reason=reason,
            confidence=score,
            evidence_summary=evidence_summary,
            mitre_techniques=active_techniques,
            threat_score=score,
            threat_level=threat_level,
        )
        self._next_rec_id += 1
        self.recommendations.append(rec)
        return rec

    # ------------------------------------------------------------------
    # Decision processing
    # ------------------------------------------------------------------

    def get_pending(self) -> List[DecisionRecord]:
        """Return all pending (undecided) decision records."""
        return [d for d in self.decisions if d.is_pending]

    def submit_recommendation(self, rec: AIRecommendation) -> DecisionRecord:
        """Wrap a recommendation in a DecisionRecord awaiting commander input."""
        dr = DecisionRecord(
            decision_id=self._next_dec_id,
            recommendation=rec,
        )
        self._next_dec_id += 1
        self.decisions.append(dr)
        return dr

    def approve_decision(self, decision_id: int) -> Optional[DecisionRecord]:
        """Commander approves the AI recommendation."""
        dr = self._find_decision(decision_id)
        if dr is None or not dr.is_pending:
            return None
        dr.approve()
        return dr

    def override_decision(self, decision_id: int, action: str,
                         reason: str) -> Optional[DecisionRecord]:
        """Commander overrides with a different action."""
        dr = self._find_decision(decision_id)
        if dr is None or not dr.is_pending:
            return None
        dr.override(chosen_action=action, reason=reason)
        return dr

    def dismiss_decision(self, decision_id: int,
                         reason: str = "") -> Optional[DecisionRecord]:
        """Commander dismisses the recommendation."""
        dr = self._find_decision(decision_id)
        if dr is None or not dr.is_pending:
            return None
        dr.dismiss(reason=reason)
        return dr

    def _find_decision(self, decision_id: int) -> Optional[DecisionRecord]:
        for dr in self.decisions:
            if dr.decision_id == decision_id:
                return dr
        return None

    # ------------------------------------------------------------------
    # Decision log
    # ------------------------------------------------------------------

    def decision_log(self) -> List[dict]:
        """Return the full decision history (newest first)."""
        return [dr.to_dict() for dr in reversed(self.decisions)]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _describe_activity(techniques: List[str], sectors: List[str],
                           attacker_state: str) -> str:
        """Build a human-readable suspected-activity string."""
        parts = []
        if techniques:
            parts.append(f"MITRE techniques observed: {', '.join(techniques)}")
        if sectors:
            parts.append(f"Affected sectors: {', '.join(sectors)}")
        if attacker_state == "trapped":
            parts.append("Attacker currently trapped in decoy.")
        elif attacker_state == "contained":
            parts.append("Attacker contained by operator command.")
        return " ".join(parts) if parts else "No significant activity detected."

    @staticmethod
    def _check_national_security(sectors: List[str],
                                 techniques: List[str]) -> bool:
        """
        Detect national-security scenario: attacker progressing from
        military toward civilian critical sectors.
        """
        has_military = "military" in sectors
        has_civilian = bool(set(sectors) & CIVILIAN_CRITICAL)
        return has_military and has_civilian

    @staticmethod
    def _choose_action(score: float, threat_level: str, risk: str,
                       attacker_state: str, is_national_security: bool,
                       deception_active: bool,
                       sectors: List[str]) -> DefensiveAction:
        """Select the most appropriate defensive action."""
        # Critical threat → escalate
        if threat_level == "critical" or risk == "critical":
            return DefensiveAction.ESCALATE

        # National security scenario → protect connected assets
        if is_national_security:
            return DefensiveAction.PROTECT_CONNECTED

        # High threat with no deception yet → deploy deception
        if score >= 0.40 and not deception_active:
            return DefensiveAction.DEPLOY_DECEPTION

        # High threat with active deception → increase monitoring
        if score >= 0.40 and deception_active:
            return DefensiveAction.INCREASE_MONITORING

        # Attacker trapped → investigate
        if attacker_state == "trapped":
            return DefensiveAction.INVESTIGATE

        # Medium threat → investigate
        if score >= 0.15:
            return DefensiveAction.INVESTIGATE

        # Low threat → monitor
        return DefensiveAction.MONITOR

    @staticmethod
    def _build_assessment(score: float, threat_level: str,
                          sectors: List[str], is_national_security: bool,
                          attacker_state: str) -> str:
        """Build the threat assessment summary text."""
        parts = [f"Threat level: {threat_level.upper()} ({score:.1%} confidence)."]
        if sectors:
            parts.append(f"Sectors affected: {', '.join(sectors)}.")
        if is_national_security:
            parts.append(
                "NATIONAL SECURITY SCENARIO: attacker progression detected "
                "from military toward civilian critical infrastructure."
            )
        if attacker_state == "trapped":
            parts.append("Simulated attacker is currently trapped in a decoy.")
        elif attacker_state == "contained":
            parts.append("Simulated attacker has been contained.")
        return " ".join(parts)

    @staticmethod
    def _build_reason(action: DefensiveAction, score: float,
                      threat_level: str, sectors: List[str],
                      is_national_security: bool, deception_active: bool,
                      attacker_state: str) -> str:
        """Build the recommendation rationale."""
        reasons = []
        if action == DefensiveAction.ESCALATE:
            reasons.append(
                "Threat level is CRITICAL — immediate commander review required."
            )
        elif action == DefensiveAction.PROTECT_CONNECTED:
            reasons.append(
                "Military-to-civilian progression detected. Downstream "
                "critical infrastructure must be hardened."
            )
        elif action == DefensiveAction.DEPLOY_DECEPTION:
            reasons.append(
                f"Threat score {score:.1%} warrants deception deployment "
                f"to divert the attacker and gather evidence."
            )
        elif action == DefensiveAction.INCREASE_MONITORING:
            reasons.append(
                "Active deception is in place. Increasing monitoring to "
                "capture additional evidence from decoy interactions."
            )
        elif action == DefensiveAction.INVESTIGATE:
            reasons.append(
                "Moderate threat activity detected. Further investigation "
                "is needed to confirm attacker intent and scope."
            )
        elif action == DefensiveAction.ISOLATE_ASSET:
            reasons.append(
                "Affected asset shows signs of compromise. Simulated "
                "isolation will prevent lateral movement."
            )
        else:
            reasons.append(
                "Threat level is low. Continue monitoring for changes."
            )

        if is_national_security:
            reasons.append(
                "Investigation of the original military breach is "
                "recommended to identify the initial access vector."
            )
        return " ".join(reasons)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> dict:
        pending = self.get_pending()
        return {
            "total_recommendations": len(self.recommendations),
            "total_decisions": len(self.decisions),
            "pending_decisions": len(pending),
            "latest_recommendation": (
                self.recommendations[-1].to_dict()
                if self.recommendations else None
            ),
            "pending": [d.to_dict() for d in pending],
            "decision_log": self.decision_log(),
        }

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

    def reset(self):
        """Clear all recommendations and decisions."""
        self.recommendations.clear()
        self.decisions.clear()
        self._next_rec_id = 1
        self._next_dec_id = 1


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[CommandEngine] = None


def get_command_engine() -> CommandEngine:
    """Return the global CommandEngine instance (create on first call)."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = CommandEngine()
    return _engine_instance
