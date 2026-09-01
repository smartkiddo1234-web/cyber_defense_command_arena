"""
Command Data Models

AI recommendations, commander decisions, and the decision log for the
human-in-the-loop command system. All data is fictional and simulated.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional


class DefensiveAction(Enum):
    """
    Safe simulated defensive actions the AI can recommend.

    None of these actions interact with real systems.
    """
    MONITOR = "monitor"
    INVESTIGATE = "investigate"
    ISOLATE_ASSET = "isolate_asset"
    DEPLOY_DECEPTION = "deploy_deception"
    INCREASE_MONITORING = "increase_monitoring"
    PROTECT_CONNECTED = "protect_connected"
    ESCALATE = "escalate"


# Human-readable descriptions for each action
ACTION_DESCRIPTIONS: Dict[DefensiveAction, str] = {
    DefensiveAction.MONITOR: (
        "Continue passive observation of the affected sector. "
        "No active response at this time."
    ),
    DefensiveAction.INVESTIGATE: (
        "Deepen analysis of the affected sector — gather additional evidence "
        "and correlate with cross-sector activity."
    ),
    DefensiveAction.ISOLATE_ASSET: (
        "Simulated isolation of the affected asset within Cyber Arena. "
        "The asset is quarantined from the Digital Twin network. "
        "No real systems are affected."
    ),
    DefensiveAction.DEPLOY_DECEPTION: (
        "Activate additional decoys in the affected sector to divert "
        "the simulated attacker and collect evidence."
    ),
    DefensiveAction.INCREASE_MONITORING: (
        "Raise monitoring intensity across affected and connected sectors. "
        "Lower detection thresholds for early warning."
    ),
    DefensiveAction.PROTECT_CONNECTED: (
        "Harden simulated defences on downstream and connected critical "
        "assets identified in the Digital Twin dependency graph."
    ),
    DefensiveAction.ESCALATE: (
        "Escalate to the human commander for immediate review. "
        "Threat profile exceeds automated response parameters."
    ),
}


class CommandDecision(Enum):
    """
    Commander's response to an AI recommendation.

    PENDING  — awaiting commander decision.
    APPROVE  — commander approves the recommended action.
    OVERRIDE — commander chooses a different action.
    DISMISS  — commander dismisses the recommendation.
    """
    PENDING = "pending"
    APPROVE = "approve"
    OVERRIDE = "override"
    DISMISS = "dismiss"


class AIRecommendation:
    """
    A single AI-generated defensive recommendation based on the current
    threat picture, detection signals, and deception state.
    """

    def __init__(
        self,
        rec_id: int,
        timestamp: datetime,
        threat_assessment: str,
        affected_sectors: List[str],
        suspected_activity: str,
        recommended_action: DefensiveAction,
        reason: str,
        confidence: float,
        evidence_summary: List[str],
        mitre_techniques: List[str],
        threat_score: float,
        threat_level: str,
    ):
        self.rec_id = rec_id
        self.timestamp = timestamp
        self.threat_assessment = threat_assessment
        self.affected_sectors = affected_sectors
        self.suspected_activity = suspected_activity
        self.recommended_action = recommended_action
        self.reason = reason
        self.confidence = confidence  # 0.0 – 1.0
        self.evidence_summary = evidence_summary
        self.mitre_techniques = mitre_techniques
        self.threat_score = threat_score
        self.threat_level = threat_level

    def to_dict(self) -> dict:
        return {
            "rec_id": self.rec_id,
            "timestamp": self.timestamp.isoformat(),
            "threat_assessment": self.threat_assessment,
            "affected_sectors": list(self.affected_sectors),
            "suspected_activity": self.suspected_activity,
            "recommended_action": self.recommended_action.value,
            "action_description": ACTION_DESCRIPTIONS[self.recommended_action],
            "reason": self.reason,
            "confidence": round(self.confidence, 3),
            "evidence_summary": list(self.evidence_summary),
            "mitre_techniques": list(self.mitre_techniques),
            "threat_score": round(self.threat_score, 3),
            "threat_level": self.threat_level,
        }


class DecisionRecord:
    """
    A logged command decision pairing an AI recommendation with the
    human commander's response.
    """

    def __init__(
        self,
        decision_id: int,
        recommendation: AIRecommendation,
    ):
        self.decision_id = decision_id
        self.recommendation = recommendation
        self.decision: CommandDecision = CommandDecision.PENDING
        self.commander_action: Optional[str] = None  # override action name
        self.commander_reason: Optional[str] = None
        self.decided_at: Optional[datetime] = None

    @property
    def is_pending(self) -> bool:
        return self.decision == CommandDecision.PENDING

    def approve(self):
        """Commander approves the AI recommendation."""
        self.decision = CommandDecision.APPROVE
        self.decided_at = datetime.now(timezone.utc)

    def override(self, chosen_action: str, reason: str):
        """Commander overrides with a different action."""
        self.decision = CommandDecision.OVERRIDE
        self.commander_action = chosen_action
        self.commander_reason = reason
        self.decided_at = datetime.now(timezone.utc)

    def dismiss(self, reason: str = ""):
        """Commander dismisses the recommendation."""
        self.decision = CommandDecision.DISMISS
        self.commander_reason = reason if reason else "No reason provided."
        self.decided_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "recommendation": self.recommendation.to_dict(),
            "decision": self.decision.value,
            "commander_action": self.commander_action,
            "commander_reason": self.commander_reason,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "is_pending": self.is_pending,
        }
