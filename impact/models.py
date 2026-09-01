"""
National Security Impact Models

Defines data structures for dependency propagation analysis,
risk assessment, and national security impact scoring.

All data is fictional and derived from existing synthetic simulation data.
"""

from enum import Enum
from typing import Dict, List, Optional


class ImpactLevel(Enum):
    """National security impact classification."""
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class RiskAssessment:
    """Assessment of a single sector's cascading risk from a compromised source."""

    def __init__(
        self,
        source_sector: str,
        affected_sector: str,
        dependency_label: str,
        risk_score: float = 0.0,
        critical_assets: Optional[List[dict]] = None,
    ):
        self.source_sector = source_sector
        self.affected_sector = affected_sector
        self.dependency_label = dependency_label
        self.risk_score = round(risk_score, 3)
        self.critical_assets = critical_assets or []

    def to_dict(self) -> dict:
        return {
            "source_sector": self.source_sector,
            "affected_sector": self.affected_sector,
            "dependency_label": self.dependency_label,
            "risk_score": self.risk_score,
            "critical_assets": list(self.critical_assets),
        }


class PropagationChain:
    """A chain of cascading risk propagation from a compromised sector."""

    def __init__(self, origin: str, path: Optional[List[str]] = None):
        self.origin = origin
        self.path = path or [origin]
        self.assessments: List[RiskAssessment] = []

    def to_dict(self) -> dict:
        return {
            "origin": self.origin,
            "path": list(self.path),
            "assessments": [a.to_dict() for a in self.assessments],
        }


class NationalImpactSummary:
    """Aggregate national security impact assessment."""

    def __init__(self):
        self.impact_level: ImpactLevel = ImpactLevel.LOW
        self.affected_sectors: List[str] = []
        self.total_compromised: int = 0
        self.total_at_risk: int = 0
        self.propagation_chains: List[PropagationChain] = []
        self.priority_sector: Optional[str] = None
        self.priority_reason: str = ""
        self.score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "impact_level": self.impact_level.value,
            "affected_sectors": list(self.affected_sectors),
            "total_compromised": self.total_compromised,
            "total_at_risk": self.total_at_risk,
            "propagation_chains": [c.to_dict() for c in self.propagation_chains],
            "priority_sector": self.priority_sector,
            "priority_reason": self.priority_reason,
            "score": round(self.score, 3),
        }
