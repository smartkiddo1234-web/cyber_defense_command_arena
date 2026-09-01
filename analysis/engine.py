"""
Analysis Engine — Phase 18: Human vs AI Commander Analysis

Derives a full comparison view from the existing CommandEngine decision log.
Does NOT create a duplicate command system — reads only from cmd_engine.decisions.

All processing is fictional and local.
"""

from typing import List, Optional

from analysis.models import ComparisonRecord, QualityMetrics


class AnalysisEngine:
    """
    Builds Human vs AI comparison records and quality metrics
    from the existing CommandEngine decision log.

    Integration:
    - CommandEngine.decisions  → source of all comparison data
    - No writes to the CommandEngine — read-only integration
    """

    def __init__(self):
        self._cmd_engine = None

    # ------------------------------------------------------------------
    # Engine reference
    # ------------------------------------------------------------------

    def set_engines(self, command_engine):
        """Bind the command engine for live data access."""
        self._cmd_engine = command_engine

    # ------------------------------------------------------------------
    # Core derivation
    # ------------------------------------------------------------------

    def comparisons(self) -> List[ComparisonRecord]:
        """
        Build a ComparisonRecord for every DecisionRecord in the
        command engine's decision log.  Always fresh — no caching.
        """
        if self._cmd_engine is None:
            return []

        records: List[ComparisonRecord] = []
        for dr in self._cmd_engine.decisions:
            rec = dr.recommendation
            record = ComparisonRecord(
                decision_id=dr.decision_id,
                rec_id=rec.rec_id,
                rec_timestamp=rec.timestamp,
                ai_action=rec.recommended_action.value,
                ai_confidence=rec.confidence,
                ai_threat_level=rec.threat_level,
                ai_threat_score=rec.threat_score,
                ai_affected_sectors=list(rec.affected_sectors),
                ai_mitre_techniques=list(rec.mitre_techniques),
                ai_evidence_summary=list(rec.evidence_summary),
                ai_reason=rec.reason,
                human_decision=dr.decision.value,
                human_action=dr.commander_action,
                human_reason=dr.commander_reason,
                decided_at=dr.decided_at,
            )
            records.append(record)
        return records

    def metrics(self) -> QualityMetrics:
        """Return quality metrics computed over all comparison records."""
        return QualityMetrics(self.comparisons())

    # ------------------------------------------------------------------
    # Disagreements with explanation
    # ------------------------------------------------------------------

    def disagreements(self) -> List[ComparisonRecord]:
        """
        Return only the records where the human did NOT agree with the AI
        (override or dismiss decisions).
        """
        return [r for r in self.comparisons()
                if r.human_decision in ("override", "dismiss")]

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def status(self) -> dict:
        """Return the full analysis state as a serializable dict."""
        recs = self.comparisons()
        m = QualityMetrics(recs)
        return {
            "comparisons": [r.to_dict() for r in recs],
            "metrics": m.to_dict(),
            "disagreements": [r.to_dict() for r in self.disagreements()],
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[AnalysisEngine] = None


def get_analysis_engine() -> AnalysisEngine:
    """Return the global AnalysisEngine instance (create on first call)."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = AnalysisEngine()
    return _engine_instance
