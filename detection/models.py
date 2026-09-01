"""
Detection Data Models

Evidence records, threat scores, and alert structures for the
simulated detection engine. All data is fictional.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    """Threat severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SignalType(Enum):
    """
    Detection signal classification.

    Each simulated event is categorised into one of these signal types,
    describing the *kind* of adversarial activity observed.
    """
    UNUSUAL_LOGIN = "unusual_login"
    REPEATED_FAILED_AUTH = "repeated_failed_auth"
    SUSPICIOUS_NETWORK = "suspicious_network_connection"
    ABNORMAL_DATA_ACCESS = "abnormal_data_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUSPICIOUS_FILE_ACTIVITY = "suspicious_file_activity"
    LATERAL_MOVEMENT = "lateral_movement"


class ThreatLevel(Enum):
    """
    Overall threat level derived from the aggregate threat score.

    Distinct from Severity (per-event) and RiskLevel (operational posture).
    ThreatLevel classifies the combined detection picture into four bands
    suitable for display and automated response decisions.
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(Enum):
    """
    Operational risk state derived from the overall threat score.

    Distinct from Severity (which classifies individual events/alerts).
    RiskLevel represents the *system-wide* operational posture:
      NORMAL     — no significant threat detected
      SUSPICIOUS — anomalous activity observed, monitor closely
      HIGH_RISK  — confirmed adversarial activity, prepare response
      CRITICAL   — widespread compromise, immediate action required
    """
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"
    CRITICAL = "critical"


class Evidence:
    """
    A single piece of detection evidence with temporal confidence.

    Confidence decays over time if not reinforced by new evidence.
    """

    def __init__(
        self,
        evidence_id: int,
        timestamp: datetime,
        sector: str,
        targets: List[str],
        mitre_technique: str,
        mitre_name: str,
        description: str,
        signal_strength: float,
        severity: Severity,
        signal_type: Optional[SignalType] = None,
    ):
        self.evidence_id = evidence_id
        self.timestamp = timestamp
        self.sector = sector
        self.targets = targets
        self.mitre_technique = mitre_technique
        self.mitre_name = mitre_name
        self.description = description
        self.signal_strength = signal_strength  # 0.0 – 1.0
        self.severity = severity
        self.signal_type = signal_type
        self.score_contribution = 0.0  # set by DetectionEngine after scoring

    # Minimum floor: old evidence retains at least 15 % of its original signal
    MIN_FLOOR = 0.15

    def current_confidence(self, decay_rate: float = 0.95) -> float:
        """
        Calculate time-decayed confidence.

        Each 3-second interval multiplies the original signal by decay_rate.
        This simulates temporal confidence: older unreinforced evidence
        gradually loses weight, but never drops below MIN_FLOOR of its
        original signal strength.
        """
        elapsed = (datetime.now(timezone.utc) - self.timestamp).total_seconds()
        intervals = max(0, elapsed / 3.0)
        decayed = self.signal_strength * (decay_rate ** intervals)
        floor = self.signal_strength * self.MIN_FLOOR
        return max(decayed, floor)

    def exp_confidence(self, decay_lambda: float = 0.0171) -> float:
        """
        Continuous exponential-decay confidence.

        confidence(t) = strength * e^(-lambda * delta_t)

        where delta_t is elapsed seconds since the evidence was recorded.
        Lambda defaults to -ln(0.95)/3 ≈ 0.0171, which matches the
        discrete 3-second interval model (DECAY_RATE = 0.95).
        """
        import math
        elapsed = (datetime.now(timezone.utc) - self.timestamp).total_seconds()
        elapsed = max(0.0, elapsed)
        decayed = self.signal_strength * math.exp(-decay_lambda * elapsed)
        floor = self.signal_strength * self.MIN_FLOOR
        return max(decayed, floor)

    def to_dict(self, decay_rate: float = 0.95) -> dict:
        conf = self.current_confidence(decay_rate)
        return {
            "evidence_id": self.evidence_id,
            "timestamp": self.timestamp.isoformat(),
            "sector": self.sector,
            "targets": list(self.targets),
            "mitre_technique": self.mitre_technique,
            "mitre_name": self.mitre_name,
            "description": self.description,
            "signal_strength": round(self.signal_strength, 3),
            "confidence": round(conf, 3),
            "severity": self.severity.value,
            "signal_type": self.signal_type.value if self.signal_type else None,
            "score_contribution": round(self.score_contribution, 4),
        }


class Alert:
    """An active alert generated when threat score crosses a threshold."""

    def __init__(
        self,
        alert_id: int,
        timestamp: datetime,
        severity: Severity,
        title: str,
        description: str,
        sector: str,
        evidence_ids: List[int],
    ):
        self.alert_id = alert_id
        self.timestamp = timestamp
        self.severity = severity
        self.title = title
        self.description = description
        self.sector = sector
        self.evidence_ids = evidence_ids
        self.acknowledged = False

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "sector": self.sector,
            "evidence_ids": list(self.evidence_ids),
            "acknowledged": self.acknowledged,
        }
