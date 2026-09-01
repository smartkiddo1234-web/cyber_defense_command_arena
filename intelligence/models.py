"""
Adversary Intelligence Models

Defines the AdversaryProfile and related data structures for the
simulated adversary tracking layer.

All data is fictional and derived from existing synthetic simulation events.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional


class AdversaryActivity:
    """A single timestamped adversary activity record."""

    def __init__(
        self,
        timestamp: datetime,
        sector: str,
        action: str,
        technique: Optional[str] = None,
        technique_name: Optional[str] = None,
        detail: str = "",
    ):
        self.timestamp = timestamp
        self.sector = sector
        self.action = action
        self.technique = technique
        self.technique_name = technique_name
        self.detail = detail

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "sector": self.sector,
            "action": self.action,
            "technique": self.technique,
            "technique_name": self.technique_name,
            "detail": self.detail,
        }


class AdversaryProfile:
    """
    Simulated adversary intelligence profile derived from existing
    simulation, detection, and deception data.
    """

    def __init__(self):
        self.adversary_id: str = "ADV-SYNTH-001"
        self.entry_point: Optional[str] = None
        self.current_sector: Optional[str] = None
        self.attack_progression: List[str] = []
        self.observed_techniques: List[Dict] = []
        self.behavior_history: List[AdversaryActivity] = []
        self.stealth_level: float = 0.0
        self.adaptation_status: str = "unknown"
        self.evidence_collected: int = 0
        self.threat_confidence: float = 0.0
        self.first_seen: Optional[datetime] = None
        self.last_seen: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "adversary_id": self.adversary_id,
            "entry_point": self.entry_point,
            "current_sector": self.current_sector,
            "attack_progression": list(self.attack_progression),
            "observed_techniques": list(self.observed_techniques),
            "behavior_history": [a.to_dict() for a in self.behavior_history],
            "stealth_level": round(self.stealth_level, 3),
            "adaptation_status": self.adaptation_status,
            "evidence_collected": self.evidence_collected,
            "threat_confidence": round(self.threat_confidence, 3),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }
