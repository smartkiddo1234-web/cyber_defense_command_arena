"""
Analysis Models — Phase 18: Human vs AI Commander Analysis

Defines data structures for comparing AI recommendations with human
commander decisions, and for calculating decision-quality metrics.

Data is derived entirely from the existing Command engine decision log.
No duplicate command systems are created. All processing is fictional/local.
"""

from datetime import datetime, timezone
from typing import List, Optional


class Agreement:
    """
    Enum-like constants for agreement classification between AI and human.
    Using string constants so they serialize cleanly to JSON.
    """
    AGREE = "agree"          # Human approved the AI recommendation
    OVERRIDE = "override"    # Human chose a different action
    DISMISS = "dismiss"      # Human dismissed the recommendation
    PENDING = "pending"      # No human decision yet


class SimulatedOutcome:
    """
    Simulated outcome categories for a defensive decision.
    Based on the threat level and action taken — entirely fictional.
    """
    CONTAINED = "contained"              # Threat neutralised
    PARTIALLY_MITIGATED = "partially_mitigated"  # Threat reduced
    ESCALATED = "escalated"              # Threat grew
    UNKNOWN = "unknown"                  # Not enough data yet


class ComparisonRecord:
    """
    Pairs an AI recommendation with the human commander's decision and
    derives the comparison, explanation, and simulated outcome.

    Wraps a DecisionRecord without replacing or duplicating any command data.
    """

    def __init__(
        self,
        decision_id: int,
        rec_id: int,
        rec_timestamp: datetime,
        ai_action: str,
        ai_confidence: float,
        ai_threat_level: str,
        ai_threat_score: float,
        ai_affected_sectors: List[str],
        ai_mitre_techniques: List[str],
        ai_evidence_summary: List[str],
        ai_reason: str,
        human_decision: str,        # approve / override / dismiss / pending
        human_action: Optional[str],
        human_reason: Optional[str],
        decided_at: Optional[datetime],
    ):
        self.decision_id = decision_id
        self.rec_id = rec_id
        self.rec_timestamp = rec_timestamp

        # AI side
        self.ai_action = ai_action
        self.ai_confidence = ai_confidence
        self.ai_threat_level = ai_threat_level
        self.ai_threat_score = ai_threat_score
        self.ai_affected_sectors = ai_affected_sectors
        self.ai_mitre_techniques = ai_mitre_techniques
        self.ai_evidence_summary = ai_evidence_summary
        self.ai_reason = ai_reason

        # Human side
        self.human_decision = human_decision
        self.human_action = human_action
        self.human_reason = human_reason
        self.decided_at = decided_at

        # Derived
        self.agreement = self._derive_agreement()
        self.simulated_outcome = self._derive_outcome()

    # ------------------------------------------------------------------
    # Derivation helpers
    # ------------------------------------------------------------------

    def _derive_agreement(self) -> str:
        if self.human_decision == "approve":
            return Agreement.AGREE
        if self.human_decision == "override":
            return Agreement.OVERRIDE
        if self.human_decision == "dismiss":
            return Agreement.DISMISS
        return Agreement.PENDING

    def _derive_outcome(self) -> str:
        """
        Simulate a plausible outcome based on the action taken and threat level.
        Entirely fictional — used only for illustration.
        No claim is made that AI or human is objectively "better".
        """
        # Action actually executed (human overrides take effect)
        action = self.human_action if self.human_action else self.ai_action
        threat = self.ai_threat_level

        if self.human_decision == "pending":
            return SimulatedOutcome.UNKNOWN

        if action in ("escalate", "protect_connected", "isolate_asset"):
            return SimulatedOutcome.CONTAINED
        if action in ("deploy_deception", "increase_monitoring", "investigate"):
            if threat in ("critical", "high"):
                return SimulatedOutcome.PARTIALLY_MITIGATED
            return SimulatedOutcome.CONTAINED
        if action == "monitor":
            if threat in ("critical", "high"):
                return SimulatedOutcome.ESCALATED
            return SimulatedOutcome.PARTIALLY_MITIGATED
        if self.human_decision == "dismiss":
            if threat in ("critical", "high"):
                return SimulatedOutcome.ESCALATED
            return SimulatedOutcome.UNKNOWN
        return SimulatedOutcome.UNKNOWN

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "rec_id": self.rec_id,
            "rec_timestamp": self.rec_timestamp.isoformat(),

            # AI recommendation
            "ai_action": self.ai_action,
            "ai_confidence": round(self.ai_confidence, 3),
            "ai_threat_level": self.ai_threat_level,
            "ai_threat_score": round(self.ai_threat_score, 3),
            "ai_affected_sectors": list(self.ai_affected_sectors),
            "ai_mitre_techniques": list(self.ai_mitre_techniques),
            "ai_evidence_summary": list(self.ai_evidence_summary),
            "ai_reason": self.ai_reason,

            # Human decision
            "human_decision": self.human_decision,
            "human_action": self.human_action,
            "human_reason": self.human_reason,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,

            # Comparison
            "agreement": self.agreement,
            "simulated_outcome": self.simulated_outcome,
        }


class QualityMetrics:
    """
    Simple, explainable decision-quality metrics derived from the full
    comparison record set.

    No claim is made that AI or human is objectively "better" — the
    metrics describe what happened and leave interpretation to the user.
    """

    def __init__(self, records: List[ComparisonRecord]):
        self._records = records

    @property
    def total_decisions(self) -> int:
        return len(self._records)

    @property
    def decided_records(self) -> List[ComparisonRecord]:
        return [r for r in self._records if r.human_decision != "pending"]

    @property
    def total_decided(self) -> int:
        return len(self.decided_records)

    @property
    def approved(self) -> int:
        return sum(1 for r in self._records if r.human_decision == "approve")

    @property
    def overridden(self) -> int:
        return sum(1 for r in self._records if r.human_decision == "override")

    @property
    def dismissed(self) -> int:
        return sum(1 for r in self._records if r.human_decision == "dismiss")

    @property
    def pending(self) -> int:
        return sum(1 for r in self._records if r.human_decision == "pending")

    @property
    def agreement_rate(self) -> float:
        """Fraction of decided records where human agreed with AI."""
        if self.total_decided == 0:
            return 0.0
        return round(self.approved / self.total_decided, 3)

    @property
    def override_rate(self) -> float:
        """Fraction of decided records where human overrode AI."""
        if self.total_decided == 0:
            return 0.0
        return round(self.overridden / self.total_decided, 3)

    @property
    def dismiss_rate(self) -> float:
        """Fraction of decided records where human dismissed AI."""
        if self.total_decided == 0:
            return 0.0
        return round(self.dismissed / self.total_decided, 3)

    @property
    def avg_ai_confidence(self) -> float:
        """Mean AI confidence across all records."""
        if not self._records:
            return 0.0
        return round(sum(r.ai_confidence for r in self._records) / len(self._records), 3)

    @property
    def outcome_counts(self) -> dict:
        counts = {
            SimulatedOutcome.CONTAINED: 0,
            SimulatedOutcome.PARTIALLY_MITIGATED: 0,
            SimulatedOutcome.ESCALATED: 0,
            SimulatedOutcome.UNKNOWN: 0,
        }
        for r in self._records:
            counts[r.simulated_outcome] = counts.get(r.simulated_outcome, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "total_decisions": self.total_decisions,
            "total_decided": self.total_decided,
            "approved": self.approved,
            "overridden": self.overridden,
            "dismissed": self.dismissed,
            "pending": self.pending,
            "agreement_rate": self.agreement_rate,
            "override_rate": self.override_rate,
            "dismiss_rate": self.dismiss_rate,
            "avg_ai_confidence": self.avg_ai_confidence,
            "outcome_counts": self.outcome_counts,
        }
