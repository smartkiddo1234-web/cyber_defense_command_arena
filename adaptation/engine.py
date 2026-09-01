"""
Adaptation Engine

Orchestrates adversary behavioral adaptation when the simulated attacker
encounters deception or containment.  Coordinates:

- Adversary behaviour shift  (sector, technique, stealth, target)
- New synthetic detection event  (fed into evidence chain)
- Deception response  (new decoy selection)
- Adversary intelligence update  (adaptation history)
- Command integration  (updated AI recommendation when significant)

All processing is entirely fictional and local.
"""

import random
from datetime import datetime, timezone
from typing import Dict, List, Optional

from adaptation.models import AdaptationEvent


# ---------------------------------------------------------------------------
# MITRE technique pool for adaptation
# Maps technique ID → (name, base signal strength)
# ---------------------------------------------------------------------------

_MITRE_POOL: Dict[str, tuple] = {
    "T1595": ("Active Scanning", 0.35),
    "T1078": ("Valid Accounts", 0.65),
    "T1021": ("Remote Services", 0.55),
    "T1027": ("Obfuscated Files or Information", 0.45),
    "T1565": ("Data Manipulation", 0.70),
    "T1486": ("Data Encrypted for Impact", 0.80),
}

# Stealth boost applied when the adversary encounters deception
_STEALTH_BOOST_MIN = 0.05
_STEALTH_BOOST_MAX = 0.15

# Signal-strength reduction when the adversary goes more stealthy
_SIGNAL_REDUCE_MIN = 0.05
_SIGNAL_REDUCE_MAX = 0.20

# Significance threshold: stealth increase above this counts as "significant"
_SIGNIFICANT_STEALTH_DELTA = 0.05


class AdaptationEngine:
    """
    Coordinates adversary adaptation when deception is encountered.

    Integration points:
    - Simulator        → current attack position, sector, technique
    - DetectionEngine  ← new detection event (evidence chain)
    - DeceptionEngine  → decoy/containment trigger; ← new decoy selection
    - AdversaryIntel   → updated profile with adaptation history
    - CommandEngine    ← updated recommendation (when significant)
    - DigitalTwin      → sector/asset lookup for new targets
    """

    def __init__(self):
        self._events: List[AdaptationEvent] = []
        self._next_id = 1
        self._simulator = None
        self._detection = None
        self._deception = None
        self._adv_engine = None
        self._cmd_engine = None
        self._twin = None

    # ------------------------------------------------------------------
    # Engine references
    # ------------------------------------------------------------------

    def set_engines(self, simulator, detection_engine, deception_engine,
                    adversary_engine, command_engine, twin):
        """Bind all engine references for cross-module coordination."""
        self._simulator = simulator
        self._detection = detection_engine
        self._deception = deception_engine
        self._adv_engine = adversary_engine
        self._cmd_engine = command_engine
        self._twin = twin

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def events(self) -> List[AdaptationEvent]:
        return list(self._events)

    @property
    def adaptation_count(self) -> int:
        return len(self._events)

    # ------------------------------------------------------------------
    # Core adaptation
    # ------------------------------------------------------------------

    def adapt(self, trigger_event: str = "decoy_encountered") -> Optional[AdaptationEvent]:
        """
        Adapt adversary behaviour in response to a deception trigger.

        1. Capture previous behaviour from simulator / adversary profile
        2. Select a new sector, technique, target, and adjust stealth
        3. Create a synthetic detection event and feed the evidence chain
        4. Recommend a new decoy via the deception engine
        5. Record an adaptation activity in the adversary intelligence profile
        6. Generate an updated command recommendation if the adaptation is significant

        Returns the AdaptationEvent, or None if adaptation is not possible.
        """
        if not self._can_adapt():
            return None

        # ---- Capture previous state --------------------------------
        prev_sector, prev_technique, prev_technique_name, prev_target = (
            self._capture_previous()
        )

        # Profile-based previous stealth
        prev_stealth = 0.0
        if self._adv_engine and hasattr(self._adv_engine, "_profile"):
            prev_stealth = getattr(self._adv_engine._profile, "stealth_level", 0.0)

        # ---- Select new behaviour ----------------------------------
        new_sector = self._select_next_sector(prev_sector)
        new_technique = self._select_next_technique(prev_technique)
        new_technique_name, base_signal = _MITRE_POOL.get(
            new_technique, ("Active Scanning", 0.35)
        )
        new_stealth = self._adjust_stealth(prev_stealth)
        new_signal = self._adjust_signal_strength(base_signal, prev_stealth)

        # New target asset
        new_target = self._select_target_for_sector(new_sector)

        # Reason
        reason = (
            f"Adversary encountered {trigger_event.replace('_', ' ')} in "
            f"{prev_sector or 'unknown'} sector; shifted tactics."
        )

        # ---- Synthetic detection event ------------------------------
        det_evidence_id = None
        if self._detection:
            ev_dict = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sector": new_sector or "unknown",
                "targets": [new_target] if new_target else [],
                "mitre_technique": new_technique,
                "mitre_name": new_technique_name,
                "description": (
                    f"[ADAPTATION] Adversary shifted to {new_technique_name} in "
                    f"{new_sector} sector after encountering deception."
                ),
                "signal_strength": new_signal,
            }
            evidence = self._detection.ingest_event(ev_dict)
            det_evidence_id = evidence.evidence_id

        # ---- Deception response: select new decoy --------------------
        new_decoy_id = None
        new_decoy_name = None
        if self._deception:
            decoy = self._deception.select_decoy_for_threat()
            if decoy:
                new_decoy_id = decoy.decoy_id
                new_decoy_name = decoy.name

        # ---- Significance check --------------------------------------
        significant = self._is_significant(
            prev_sector, new_sector, prev_technique, new_technique,
            prev_stealth, new_stealth,
        )

        # ---- Record adaptation event ---------------------------------
        evt = AdaptationEvent(
            adaptation_id=self._next_id,
            timestamp=datetime.now(timezone.utc),
            trigger=trigger_event,
            previous_sector=prev_sector,
            new_sector=new_sector,
            previous_technique=prev_technique,
            new_technique=new_technique,
            previous_technique_name=prev_technique_name,
            new_technique_name=new_technique_name,
            previous_stealth=prev_stealth,
            new_stealth=new_stealth,
            previous_signal_strength=base_signal,
            new_signal_strength=new_signal,
            previous_target=prev_target,
            new_target=new_target,
            reason=reason,
            significant=significant,
            new_decoy_id=new_decoy_id,
            new_decoy_name=new_decoy_name,
            detection_event_id=det_evidence_id,
        )
        self._next_id += 1
        self._events.append(evt)

        # ---- Update adversary intelligence ---------------------------
        self._update_adversary_intelligence(evt)

        # ---- Command integration (when significant) ------------------
        if significant and self._cmd_engine:
            self._cmd_engine.generate_recommendation()

        return evt

    # ------------------------------------------------------------------
    # Feeding adaptation trigger from deception events
    # ------------------------------------------------------------------

    def evaluate_deception_events(self, events: list) -> List[AdaptationEvent]:
        """
        Inspect a list of DeceptionEvents and trigger adaptation for each
        'triggered' or 'contained' event.  Returns any new AdaptationEvents.
        """
        results: List[AdaptationEvent] = []
        for dev in events:
            etype = getattr(dev, "event_type", None)
            if etype in ("triggered", "contained"):
                adapted = self.adapt(trigger_event=f"deception_{etype}")
                if adapted:
                    results.append(adapted)
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _can_adapt(self) -> bool:
        """Return True when adaptation is possible."""
        if self._deception:
            state = self._deception.attacker_state.value
            if state == "contained":
                return False
        return True

    def _capture_previous(self):
        """Return (sector, technique_id, technique_name, target) from current state."""
        sector = None
        technique = None
        technique_name = None
        target = None

        if self._simulator:
            status = self._simulator.status()
            sector = status.get("current_sector")
            technique = status.get("current_technique")
            technique_name = status.get("current_technique_name")
            # Derive target from last event
            events = status.get("events", [])
            if events:
                targets = events[-1].get("targets", [])
                if targets:
                    target = targets[0]

        return sector, technique, technique_name, target

    def _select_next_sector(self, current_sector: Optional[str]) -> Optional[str]:
        """
        Select the next sector to attack.
        Prefers sectors already in the attack path that differ from current.
        Falls back to other sectors in the Digital Twin.
        """
        attack_path = []
        if self._simulator:
            attack_path = self._simulator.attack_path

        # Sectors in attack path excluding current
        path_candidates = [s for s in attack_path if s != current_sector]
        if path_candidates:
            return random.choice(path_candidates)

        # Fallback: all sectors in twin
        if self._twin:
            all_sectors = list(self._twin.sectors.keys())
            candidates = [s for s in all_sectors if s != current_sector]
            if candidates:
                return random.choice(candidates)

        return current_sector

    def _select_next_technique(self, current_technique: Optional[str]) -> str:
        """
        Select a different MITRE technique from the pool.
        Falls back to the current technique if only one is available.
        """
        alternatives = [t for t in _MITRE_POOL if t != current_technique]
        if alternatives:
            return random.choice(alternatives)
        return current_technique or "T1595"

    def _select_target_for_sector(self, sector: Optional[str]) -> Optional[str]:
        """Pick a target asset from the given sector in the Digital Twin."""
        if not sector or not self._twin:
            return None
        sec = self._twin.get_sector(sector)
        if sec and sec.assets:
            asset = random.choice(sec.assets)
            return asset.asset_id
        return None

    def _adjust_stealth(self, current_stealth: float) -> float:
        """Increase stealth when encountering deception (harder to detect)."""
        boost = random.uniform(_STEALTH_BOOST_MIN, _STEALTH_BOOST_MAX)
        return round(min(1.0, current_stealth + boost), 3)

    def _adjust_signal_strength(self, base_signal: float,
                                 current_stealth: float) -> float:
        """
        Reduce signal strength to reflect increased stealth.
        The more stealthy the adversary already is, the less reduction.
        """
        reduction = random.uniform(_SIGNAL_REDUCE_MIN, _SIGNAL_REDUCE_MAX)
        # Scale reduction inversely with stealth (high stealth → less reduction)
        reduction *= (1.0 - current_stealth)
        return round(max(0.1, base_signal - reduction), 3)

    def _is_significant(self, prev_sector, new_sector,
                        prev_technique, new_technique,
                        prev_stealth, new_stealth) -> bool:
        """An adaptation is significant if sector or technique changed materially."""
        if prev_sector != new_sector:
            return True
        if prev_technique != new_technique:
            return True
        if (new_stealth - prev_stealth) >= _SIGNIFICANT_STEALTH_DELTA:
            return True
        return False

    def _update_adversary_intelligence(self, evt: AdaptationEvent):
        """Record adaptation in adversary intelligence behavior history."""
        if not self._adv_engine:
            return

        from intelligence.models import AdversaryActivity

        activity = AdversaryActivity(
            timestamp=evt.timestamp,
            sector=evt.new_sector or "unknown",
            action="adaptation",
            technique=evt.new_technique,
            technique_name=evt.new_technique_name,
            detail=(
                f"Adversary adapted: {evt.previous_technique}→{evt.new_technique} "
                f"in {evt.new_sector} sector. "
                f"Stealth {evt.previous_stealth:.2f}→{evt.new_stealth:.2f}. "
                f"Trigger: {evt.trigger}."
            ),
        )
        profile = self._adv_engine._profile
        profile.behavior_history.append(activity)
        # Re-derive stealth on the profile
        profile.adaptation_status = "adapted"
        # Trigger a fresh profile update from all engines
        self._adv_engine.update()

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def status(self) -> dict:
        """Return current adaptation state as a dict."""
        last = self._events[-1].to_dict() if self._events else None
        return {
            "adaptation_count": len(self._events),
            "last_adaptation": last,
            "events": [e.to_dict() for e in self._events],
        }

    # ------------------------------------------------------------------
    # Reset
    # ------------------------------------------------------------------

    def reset(self):
        """Clear all adaptation events."""
        self._events.clear()
        self._next_id = 1


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[AdaptationEngine] = None


def get_adaptation_engine() -> AdaptationEngine:
    """Return the global AdaptationEngine instance (create on first call)."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = AdaptationEngine()
    return _engine_instance
