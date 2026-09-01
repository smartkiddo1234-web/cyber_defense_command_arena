"""
Adversary Intelligence Engine

Builds and maintains a simulated adversary profile by analysing existing
Simulation, Detection, and Deception events.  Does NOT create a separate
attack system — all data is derived from the existing synthetic pipeline.

All processing is entirely fictional and local.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from intelligence.models import AdversaryActivity, AdversaryProfile


class AdversaryIntelligence:
    """
    Constructs and maintains an adversary profile from existing engine data.

    Integration points:
    - Simulator events  → position, progression, behavior history
    - Detection evidence → techniques, stealth, threat confidence
    - Deception events  → adaptation status, containment awareness
    """

    def __init__(self, simulator=None, detection_engine=None, deception_engine=None):
        self._simulator = simulator
        self._detection = detection_engine
        self._deception = deception_engine
        self._profile = AdversaryProfile()

    # ------------------------------------------------------------------
    # Engine references (set after construction for loose coupling)
    # ------------------------------------------------------------------

    def set_engines(self, simulator, detection_engine, deception_engine):
        """Bind the engine references for live data queries."""
        self._simulator = simulator
        self._detection = detection_engine
        self._deception = deception_engine

    # ------------------------------------------------------------------
    # Profile building
    # ------------------------------------------------------------------

    def update(self) -> AdversaryProfile:
        """
        Rebuild the adversary profile from current engine state.
        Called on every API query and after each simulation step.
        """
        profile = AdversaryProfile()
        history: List[AdversaryActivity] = []

        # --- Simulator events → position, progression, behavior ---
        sim_events = []
        if self._simulator:
            sim_events = self._simulator.events
            profile.attack_progression = list(self._simulator.attack_path)

            if sim_events:
                profile.entry_point = sim_events[0]["sector"]
                profile.current_sector = sim_events[-1]["sector"]
                try:
                    profile.first_seen = datetime.fromisoformat(sim_events[0]["timestamp"])
                except (ValueError, KeyError):
                    pass
                try:
                    profile.last_seen = datetime.fromisoformat(sim_events[-1]["timestamp"])
                except (ValueError, KeyError):
                    pass

                for ev in sim_events:
                    ts = _parse_ts(ev.get("timestamp"))
                    history.append(AdversaryActivity(
                        timestamp=ts,
                        sector=ev.get("sector", "unknown"),
                        action="attack",
                        technique=ev.get("mitre_technique"),
                        technique_name=ev.get("mitre_name"),
                        detail=ev.get("description", ""),
                    ))

        # --- Detection evidence → techniques, stealth, confidence ---
        techniques_map: Dict[str, dict] = {}
        if self._detection and hasattr(self._detection, "evidence"):
            evidence_list = self._detection.evidence
            profile.evidence_collected = len(evidence_list)
            profile.threat_confidence = round(self._detection.threat_score(), 3)

            # Collect observed techniques
            for ev in evidence_list:
                tech_id = ev.mitre_technique
                if tech_id and tech_id not in techniques_map:
                    techniques_map[tech_id] = {
                        "technique": tech_id,
                        "name": ev.mitre_name,
                        "first_seen": ev.timestamp.isoformat(),
                        "last_seen": ev.timestamp.isoformat(),
                        "occurrences": 0,
                        "sectors": set(),
                    }
                if tech_id and tech_id in techniques_map:
                    techniques_map[tech_id]["occurrences"] += 1
                    techniques_map[tech_id]["last_seen"] = ev.timestamp.isoformat()
                    if hasattr(ev, "sector"):
                        techniques_map[tech_id]["sectors"].add(ev.sector)

            # Stealth level: average signal strength (lower = more stealthy)
            strengths = [ev.signal_strength for ev in evidence_list if ev.signal_strength > 0]
            if strengths:
                avg_strength = sum(strengths) / len(strengths)
                # Invert: low signal = high stealth
                profile.stealth_level = round(max(0.0, 1.0 - avg_strength), 3)

        # --- Deception events → adaptation status ---
        if self._deception:
            attacker_state = self._deception.attacker_state.value
            dec_events = self._deception.events if hasattr(self._deception, "events") else []

            if attacker_state == "contained":
                profile.adaptation_status = "contained"
            elif attacker_state == "trapped":
                profile.adaptation_status = "trapped_in_decoy"
            else:
                # Check if any decoy was bypassed
                bypassed = any(
                    getattr(e, "event_type", None) == "bypassed"
                    for e in dec_events
                )
                profile.adaptation_status = "adapted" if bypassed else "active"

            # Add deception events to behavior history
            for dev in dec_events:
                ts = getattr(dev, "timestamp", datetime.now(timezone.utc))
                if isinstance(ts, str):
                    ts = _parse_ts(ts)
                history.append(AdversaryActivity(
                    timestamp=ts,
                    sector=getattr(dev, "sector", "unknown"),
                    action=f"deception_{getattr(dev, 'event_type', 'interaction')}",
                    technique=getattr(dev, "mitre_technique", None),
                    technique_name=getattr(dev, "mitre_name", None),
                    detail=getattr(dev, "description", ""),
                ))

        # Sort history chronologically and assign
        history.sort(key=lambda a: a.timestamp)
        profile.behavior_history = history

        # Finalise techniques (convert sets to lists)
        profile.observed_techniques = [
            {**t, "sectors": sorted(t["sectors"])}
            for t in sorted(techniques_map.values(), key=lambda x: x["technique"])
        ]

        self._profile = profile
        return profile

    # ------------------------------------------------------------------
    # Public queries
    # ------------------------------------------------------------------

    def profile(self) -> dict:
        """Return the current adversary profile as a dict (always fresh)."""
        return self.update().to_dict()

    # ------------------------------------------------------------------
    # Reset
    # ------------------------------------------------------------------

    def reset(self):
        """Clear the adversary profile (engines are reset externally)."""
        self._profile = AdversaryProfile()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_ts(ts_str: Optional[str]) -> datetime:
    """Safely parse an ISO timestamp string."""
    if not ts_str:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[AdversaryIntelligence] = None


def get_adversary_engine() -> AdversaryIntelligence:
    """Return the global AdversaryIntelligence instance (create on first call)."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = AdversaryIntelligence()
    return _engine_instance
