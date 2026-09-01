"""
Simulation Data Models

Structured data classes for the Digital Twin and future simulation modules.
All data is entirely fictional — no real infrastructure is represented.
"""

from enum import Enum
from typing import List, Optional


class AssetStatus(Enum):
    """Possible operational states for a simulated asset."""
    HEALTHY = "healthy"
    WARNING = "warning"
    COMPROMISED = "compromised"
    ISOLATED = "isolated"
    UNDER_ATTACK = "under_attack"


class AssetCriticality(Enum):
    """How critical a simulated asset is to its sector."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatLevel(Enum):
    """Aggregate threat level for a sector."""
    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    SEVERE = "severe"


class Asset:
    """A single simulated infrastructure asset."""

    def __init__(
        self,
        asset_id: str,
        name: str,
        sector_id: str,
        criticality: AssetCriticality = AssetCriticality.MEDIUM,
        status: AssetStatus = AssetStatus.HEALTHY,
    ):
        self.asset_id = asset_id
        self.name = name
        self.sector_id = sector_id
        self.criticality = criticality
        self.status = status
        # Simulated activity log (populated by future phases)
        self.activity: List[str] = []
        # Threat annotations (populated by future phases)
        self.threat_state: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "sector_id": self.sector_id,
            "criticality": self.criticality.value,
            "status": self.status.value,
            "activity": list(self.activity),
            "threat_state": self.threat_state,
        }


class Sector:
    """A simulated national infrastructure sector."""

    def __init__(
        self,
        sector_id: str,
        name: str,
        icon: str = "",
        description: str = "",
    ):
        self.sector_id = sector_id
        self.name = name
        self.icon = icon
        self.description = description
        self.assets: List[Asset] = []
        self.status = AssetStatus.HEALTHY
        self.threat_level = ThreatLevel.NONE

    # ------------------------------------------------------------------
    # Derived metrics
    # ------------------------------------------------------------------

    @property
    def asset_count(self) -> int:
        return len(self.assets)

    @property
    def healthy_count(self) -> int:
        return sum(1 for a in self.assets if a.status == AssetStatus.HEALTHY)

    @property
    def warning_count(self) -> int:
        return sum(1 for a in self.assets if a.status == AssetStatus.WARNING)

    @property
    def compromised_count(self) -> int:
        return sum(
            1 for a in self.assets
            if a.status in (AssetStatus.COMPROMISED, AssetStatus.UNDER_ATTACK)
        )

    def recompute_status(self):
        """Recalculate the sector-level status from its assets."""
        if any(a.status == AssetStatus.UNDER_ATTACK for a in self.assets):
            self.status = AssetStatus.UNDER_ATTACK
            self.threat_level = ThreatLevel.SEVERE
        elif any(a.status == AssetStatus.COMPROMISED for a in self.assets):
            self.status = AssetStatus.COMPROMISED
            self.threat_level = ThreatLevel.HIGH
        elif any(a.status == AssetStatus.WARNING for a in self.assets):
            self.status = AssetStatus.WARNING
            self.threat_level = ThreatLevel.MODERATE
        elif any(a.status == AssetStatus.ISOLATED for a in self.assets):
            self.status = AssetStatus.ISOLATED
            self.threat_level = ThreatLevel.LOW
        else:
            self.status = AssetStatus.HEALTHY
            self.threat_level = ThreatLevel.NONE

    def to_dict(self) -> dict:
        self.recompute_status()
        return {
            "sector_id": self.sector_id,
            "name": self.name,
            "icon": self.icon,
            "description": self.description,
            "status": self.status.value,
            "threat_level": self.threat_level.value,
            "asset_count": self.asset_count,
            "healthy": self.healthy_count,
            "warning": self.warning_count,
            "compromised": self.compromised_count,
            "assets": [a.to_dict() for a in self.assets],
        }


class Dependency:
    """A directed dependency link between two sectors."""

    def __init__(self, source_id: str, target_id: str, label: str = ""):
        self.source_id = source_id
        self.target_id = target_id
        self.label = label
        self.active = True  # can be severed in later phases

    def to_dict(self) -> dict:
        return {
            "source": self.source_id,
            "target": self.target_id,
            "label": self.label,
            "active": self.active,
        }
