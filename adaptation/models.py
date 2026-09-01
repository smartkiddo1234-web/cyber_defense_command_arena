"""
Adaptation Models

Defines data structures for adversary behavioral adaptation events
and deception response events within the CYBER ARENA simulation.

All data is fictional and local.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional


class AdaptationEvent:
    """
    Records one adversary adaptation cycle:
    - trigger (what caused the adaptation)
    - previous behaviour (sector, technique, stealth)
    - new behaviour (sector, technique, stealth)
    - deception response (recommended new decoy)
    - whether the adaptation was significant enough to update command
    """

    def __init__(
        self,
        adaptation_id: int,
        timestamp: datetime,
        trigger: str,
        previous_sector: Optional[str],
        new_sector: Optional[str],
        previous_technique: Optional[str],
        new_technique: Optional[str],
        previous_technique_name: Optional[str] = None,
        new_technique_name: Optional[str] = None,
        previous_stealth: float = 0.0,
        new_stealth: float = 0.0,
        previous_signal_strength: float = 0.0,
        new_signal_strength: float = 0.0,
        previous_target: Optional[str] = None,
        new_target: Optional[str] = None,
        reason: str = "",
        significant: bool = False,
        new_decoy_id: Optional[str] = None,
        new_decoy_name: Optional[str] = None,
        detection_event_id: Optional[int] = None,
    ):
        self.adaptation_id = adaptation_id
        self.timestamp = timestamp
        self.trigger = trigger
        self.previous_sector = previous_sector
        self.new_sector = new_sector
        self.previous_technique = previous_technique
        self.new_technique = new_technique
        self.previous_technique_name = previous_technique_name
        self.new_technique_name = new_technique_name
        self.previous_stealth = previous_stealth
        self.new_stealth = new_stealth
        self.previous_signal_strength = previous_signal_strength
        self.new_signal_strength = new_signal_strength
        self.previous_target = previous_target
        self.new_target = new_target
        self.reason = reason
        self.significant = significant
        self.new_decoy_id = new_decoy_id
        self.new_decoy_name = new_decoy_name
        self.detection_event_id = detection_event_id

    def to_dict(self) -> dict:
        return {
            "adaptation_id": self.adaptation_id,
            "timestamp": self.timestamp.isoformat(),
            "trigger": self.trigger,
            "previous_sector": self.previous_sector,
            "new_sector": self.new_sector,
            "previous_technique": self.previous_technique,
            "new_technique": self.new_technique,
            "previous_technique_name": self.previous_technique_name,
            "new_technique_name": self.new_technique_name,
            "previous_stealth": round(self.previous_stealth, 3),
            "new_stealth": round(self.new_stealth, 3),
            "previous_signal_strength": round(self.previous_signal_strength, 3),
            "new_signal_strength": round(self.new_signal_strength, 3),
            "previous_target": self.previous_target,
            "new_target": self.new_target,
            "reason": self.reason,
            "significant": self.significant,
            "new_decoy_id": self.new_decoy_id,
            "new_decoy_name": self.new_decoy_name,
            "detection_event_id": self.detection_event_id,
        }
