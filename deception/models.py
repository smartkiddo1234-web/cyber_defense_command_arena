"""
Deception Data Models

Structured data classes for the adaptive deception grid.
All data is entirely fictional — no real systems are represented.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional


class DecoyType(Enum):
    """Types of deception mechanisms."""
    SERVER = "server"
    CREDENTIAL = "credential"
    SERVICE = "service"
    NETWORK_PATH = "network_path"
    HONEY_RESOURCE = "honey_resource"
    DOCUMENT = "document"


class DecoyStatus(Enum):
    """Operational state of a decoy."""
    ARMED = "armed"
    TRIGGERED = "triggered"
    EXHAUSTED = "exhausted"
    BYPASSED = "bypassed"


class AttackerState(Enum):
    """
    Simulated attacker operational state within the deception grid.

    FREE_ROAMING — attacker is active, not yet caught in any decoy.
    TRAPPED      — attacker is currently interacting with a decoy.
    CONTAINED    — operator issued containment; attacker isolated in simulation.
    """
    FREE_ROAMING = "free_roaming"
    TRAPPED = "trapped"
    CONTAINED = "contained"


class DeceptionPosture(Enum):
    """
    Adaptive deception response level driven by the detection risk level.

    MONITOR   — low suspicion; decoys remain armed, passive observation only.
    ACTIVATE  — suspicious activity; arm and prioritise nearby decoys.
    REDIRECT  — high risk; actively steer attacker toward additional decoys.
    CONTAIN   — critical; recommend simulated containment of the attacker.
    """
    MONITOR = "monitor"
    ACTIVATE = "activate"
    REDIRECT = "redirect"
    CONTAIN = "contain"


class DeceptionActionType(Enum):
    """
    Classification of simulated attacker interactions with decoys.

    Each interaction between the attacker and a decoy is categorised into
    one of these types, mapping to a specific MITRE ATT&CK technique.
    """
    RECONNAISSANCE = "reconnaissance"
    SUSPICIOUS_LOGIN = "suspicious_login"
    CANARY_CREDENTIAL_USE = "canary_credential_use"
    SERVICE_PROBING = "service_probing"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUSPICIOUS_FILE_ACCESS = "suspicious_file_access"


# Human-readable descriptions for each posture level
POSTURE_DESCRIPTIONS: Dict[DeceptionPosture, str] = {
    DeceptionPosture.MONITOR: (
        "Low suspicion — decoys remain armed. Passive observation only."
    ),
    DeceptionPosture.ACTIVATE: (
        "Suspicious activity detected — decoys activated and prioritised "
        "for the targeted sectors."
    ),
    DeceptionPosture.REDIRECT: (
        "High risk — actively redirecting the simulated attacker toward "
        "additional decoys to waste time and collect evidence."
    ),
    DeceptionPosture.CONTAIN: (
        "Critical threat — recommending containment of the simulated "
        "attacker. Use the Freeze/Contain control to isolate."
    ),
}


class AssetCategory(Enum):
    """Visual classification for assets shown on the deception grid."""
    REAL = "real"
    DECOY = "decoy"
    ISOLATED = "isolated"
    CONTAINED_ATTACKER = "contained_attacker"


ASSET_CATEGORY_LABELS: Dict[AssetCategory, str] = {
    AssetCategory.REAL: "Real Asset",
    AssetCategory.DECOY: "Decoy Asset",
    AssetCategory.ISOLATED: "Isolated Asset",
    AssetCategory.CONTAINED_ATTACKER: "Contained Attacker",
}

ASSET_CATEGORY_DESCRIPTIONS: Dict[AssetCategory, str] = {
    AssetCategory.REAL: "Production infrastructure within the Digital Twin.",
    AssetCategory.DECOY: "Fictional decoy designed to attract and delay the attacker.",
    AssetCategory.ISOLATED: "Asset that has been quarantined from the network.",
    AssetCategory.CONTAINED_ATTACKER: "Simulated attacker whose activity has been frozen.",
}


class Decoy:
    """A single deception mechanism deployed in the simulation."""

    def __init__(
        self,
        decoy_id: str,
        name: str,
        decoy_type: DecoyType,
        sector: str,
        description: str,
        trigger_sector: str,
        trigger_step_min: int = 0,
    ):
        self.decoy_id = decoy_id
        self.name = name
        self.decoy_type = decoy_type
        self.sector = sector
        self.description = description
        self.status = DecoyStatus.ARMED
        # Which sector must be attacked before this decoy can trigger
        self.trigger_sector = trigger_sector
        # Minimum simulator step before this decoy is eligible
        self.trigger_step_min = trigger_step_min
        self.triggered_at: Optional[datetime] = None
        self.trigger_count = 0
        # Simulated attacker activity inside the decoy
        self.attacker_activity: List[str] = []
        # How many steps the attacker stays in the decoy before adapting
        self.retention_steps = 2
        self.steps_in_decoy = 0
        self.adapted = False
        # Phase 6: real assets this decoy protects in its trigger sector
        self.linked_asset_ids: List[str] = []
        # Phase 6: assets diverted away from when this decoy triggered
        self.diverted_from: List[str] = []
        # Phase 10: structured interaction records
        self.interactions: List[dict] = []

    def trigger(self) -> bool:
        """Attempt to trigger this decoy. Returns True if newly triggered."""
        if self.status != DecoyStatus.ARMED:
            return False
        self.status = DecoyStatus.TRIGGERED
        self.triggered_at = datetime.now(timezone.utc)
        self.trigger_count += 1
        return True

    def record_activity(self, description: str):
        """Log simulated attacker activity inside the decoy."""
        self.attacker_activity.append(description)
        self.steps_in_decoy += 1

    def check_adaptation(self) -> bool:
        """Check if the attacker has recognized the deception."""
        if self.steps_in_decoy >= self.retention_steps and not self.adapted:
            self.adapted = True
            self.status = DecoyStatus.BYPASSED
            return True
        return False

    def to_dict(self) -> dict:
        return {
            "decoy_id": self.decoy_id,
            "name": self.name,
            "type": self.decoy_type.value,
            "sector": self.sector,
            "description": self.description,
            "status": self.status.value,
            "trigger_sector": self.trigger_sector,
            "triggered_at": self.triggered_at.isoformat() if self.triggered_at else None,
            "trigger_count": self.trigger_count,
            "attacker_activity": list(self.attacker_activity),
            "retention_steps": self.retention_steps,
            "steps_in_decoy": self.steps_in_decoy,
            "adapted": self.adapted,
            "linked_asset_ids": list(self.linked_asset_ids),
            "diverted_from": list(self.diverted_from),
            "interactions": list(self.interactions),
        }


class DeceptionEvent:
    """A recorded deception interaction event."""

    def __init__(
        self,
        event_id: int,
        timestamp: datetime,
        decoy_id: str,
        decoy_name: str,
        decoy_type: DecoyType,
        sector: str,
        event_type: str,
        description: str,
        evidence_boost: float = 0.0,
    ):
        self.event_id = event_id
        self.timestamp = timestamp
        self.decoy_id = decoy_id
        self.decoy_name = decoy_name
        self.decoy_type = decoy_type
        self.sector = sector
        self.event_type = event_type  # "triggered", "activity", "bypassed", "contained", "redirected"
        self.description = description
        self.evidence_boost = evidence_boost
        # Phase 6: attacker state and diversion tracking
        self.attacker_state: Optional[str] = None
        self.diverted_from: List[str] = []
        # Phase 10: MITRE technique, signal, and action classification
        self.mitre_technique: Optional[str] = None
        self.mitre_name: Optional[str] = None
        self.signal_strength: float = 0.0
        self.action_type: Optional[DeceptionActionType] = None
        self.confidence_contribution: float = 0.0

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "decoy_id": self.decoy_id,
            "decoy_name": self.decoy_name,
            "decoy_type": self.decoy_type.value,
            "sector": self.sector,
            "event_type": self.event_type,
            "description": self.description,
            "evidence_boost": round(self.evidence_boost, 3),
            "attacker_state": self.attacker_state,
            "diverted_from": list(self.diverted_from),
            "mitre_technique": self.mitre_technique,
            "mitre_name": self.mitre_name,
            "signal_strength": round(self.signal_strength, 3),
            "action_type": self.action_type.value if self.action_type else None,
            "confidence_contribution": round(self.confidence_contribution, 4),
        }
