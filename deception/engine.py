"""
Deception Engine

Manages the adaptive deception grid and evaluates simulated attacker
actions against deployed decoys. When the attacker reaches a deception
point the engine:

1. Redirects the simulated attack path into the decoy.
2. Records the deception event.
3. Increases available evidence / observation.
4. Tracks attacker activity inside the decoy.
5. Allows the attacker to eventually recognise and adapt.

Phase 6 additions:
- Adaptive deception posture driven by detection risk level.
- Simulated attacker state tracking (free-roaming / trapped / contained).
- Simulate Attacker → Decoy manual injection.
- Freeze / Contain simulation control.
- Diversion tracking — which real assets were protected.
- Detection evidence chain integration.

All processing is entirely fictional and local.
"""

import random
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from deception.models import (
    ASSET_CATEGORY_DESCRIPTIONS,
    ASSET_CATEGORY_LABELS,
    POSTURE_DESCRIPTIONS,
    AssetCategory,
    AttackerState,
    DeceptionActionType,
    Decoy,
    DeceptionEvent,
    DeceptionPosture,
    DecoyStatus,
    DecoyType,
)


# ---------------------------------------------------------------------------
# Pre-deployed decoy inventory
# ---------------------------------------------------------------------------

DECOY_REGISTRY: List[Dict] = [
    # --- Military sector decoys ---
    {
        "decoy_id": "dec-mil-honeypot",
        "name": "Honeypot Command Relay",
        "type": DecoyType.SERVER,
        "sector": "military",
        "description": "A decoy command-and-control relay mimicking the real mil-cmd-net topology.",
        "trigger_sector": "military",
        "trigger_step_min": 0,
        "retention_steps": 2,
        "linked_asset_ids": ["mil-cmd-net"],
    },
    {
        "decoy_id": "dec-mil-creds",
        "name": "Canary Credentials — Admin Pool",
        "type": DecoyType.CREDENTIAL,
        "sector": "military",
        "description": "Synthetic admin credentials seeded in the military AD. Usage triggers an alert.",
        "trigger_sector": "military",
        "trigger_step_min": 1,
        "retention_steps": 1,
        "linked_asset_ids": ["mil-def-ops"],
    },
    # --- Telecom sector decoys ---
    {
        "decoy_id": "dec-tel-service",
        "name": "Fake SIP Gateway",
        "type": DecoyType.SERVICE,
        "sector": "telecom",
        "description": "A simulated SIP gateway that accepts connections but returns only synthetic traffic data.",
        "trigger_sector": "telecom",
        "trigger_step_min": 2,
        "retention_steps": 2,
        "linked_asset_ids": ["tel-gateway"],
    },
    {
        "decoy_id": "dec-tel-path",
        "name": "False Route — Backbone Loop",
        "type": DecoyType.NETWORK_PATH,
        "sector": "telecom",
        "description": "A fabricated routing path that leads the attacker into a monitored network loop.",
        "trigger_sector": "telecom",
        "trigger_step_min": 3,
        "retention_steps": 2,
        "linked_asset_ids": ["tel-core"],
    },
    # --- Energy sector decoys ---
    {
        "decoy_id": "dec-eng-honeydata",
        "name": "Honey Grid Telemetry",
        "type": DecoyType.HONEY_RESOURCE,
        "sector": "energy",
        "description": "Fabricated SCADA telemetry dataset designed to attract data-manipulation attempts.",
        "trigger_sector": "energy",
        "trigger_step_min": 4,
        "retention_steps": 2,
        "linked_asset_ids": ["eng-grid"],
    },
    {
        "decoy_id": "dec-eng-server",
        "name": "Decoy Power Controller",
        "type": DecoyType.SERVER,
        "sector": "energy",
        "description": "A virtualised power controller that logs all interaction without affecting real systems.",
        "trigger_sector": "energy",
        "trigger_step_min": 5,
        "retention_steps": 2,
        "linked_asset_ids": ["eng-power"],
    },
    # --- Healthcare sector decoys ---
    {
        "decoy_id": "dec-hlt-creds",
        "name": "Canary Credentials — EMR Access",
        "type": DecoyType.CREDENTIAL,
        "sector": "healthcare",
        "description": "Fake electronic-medical-record credentials that log every access attempt.",
        "trigger_sector": "healthcare",
        "trigger_step_min": 6,
        "retention_steps": 1,
        "linked_asset_ids": ["hlt-records"],
    },
    {
        "decoy_id": "dec-hlt-service",
        "name": "Decoy PACS Imaging Server",
        "type": DecoyType.SERVICE,
        "sector": "healthcare",
        "description": "A simulated medical imaging server returning synthetic DICOM data to waste attacker time.",
        "trigger_sector": "healthcare",
        "trigger_step_min": 6,
        "retention_steps": 2,
        "linked_asset_ids": ["hlt-hospital"],
    },
    # --- Cross-sector decoys (activated after multi-sector compromise) ---
    {
        "decoy_id": "dec-xsector-path",
        "name": "False Lateral Path — Gov Bridge",
        "type": DecoyType.NETWORK_PATH,
        "sector": "government",
        "description": "A fabricated network bridge that appears to connect military and government sectors.",
        "trigger_sector": "military",
        "trigger_step_min": 2,
        "retention_steps": 3,
        "linked_asset_ids": ["gov-civic", "gov-admin"],
    },
    {
        "decoy_id": "dec-xsector-honey",
        "name": "Honey Vault — Sector Keys",
        "type": DecoyType.HONEY_RESOURCE,
        "sector": "government",
        "description": "A fake credential vault containing synthetic cross-sector master keys.",
        "trigger_sector": "telecom",
        "trigger_step_min": 4,
        "retention_steps": 2,
        "linked_asset_ids": ["gov-civic"],
    },
    # --- Phase 6: additional sector coverage ---
    {
        "decoy_id": "dec-bnk-docs",
        "name": "Decoy Financial Reports",
        "type": DecoyType.DOCUMENT,
        "sector": "banking",
        "description": "Fabricated quarterly financial reports seeded with tracking beacons to detect exfiltration.",
        "trigger_sector": "banking",
        "trigger_step_min": 0,
        "retention_steps": 2,
        "linked_asset_ids": ["bnk-core", "bnk-swift"],
    },
    {
        "decoy_id": "dec-edu-server",
        "name": "Honeypot Research Portal",
        "type": DecoyType.SERVER,
        "sector": "education",
        "description": "A simulated academic research portal that logs credential stuffing and enumeration attempts.",
        "trigger_sector": "education",
        "trigger_step_min": 0,
        "retention_steps": 2,
        "linked_asset_ids": ["edu-research"],
    },
    {
        "decoy_id": "dec-com-creds",
        "name": "Canary Credentials — Logistics Admin",
        "type": DecoyType.CREDENTIAL,
        "sector": "commercial",
        "description": "Fake admin credentials for the logistics management system. Any usage is logged and alerted.",
        "trigger_sector": "commercial",
        "trigger_step_min": 0,
        "retention_steps": 1,
        "linked_asset_ids": ["com-logistics"],
    },
    # --- Phase 10: dedicated sector service decoys ---
    {
        "decoy_id": "dec-gov-service",
        "name": "Decoy Civic Services Portal",
        "type": DecoyType.SERVER,
        "sector": "government",
        "description": "A simulated government civic-services portal that logs credential abuse and enumeration attempts.",
        "trigger_sector": "government",
        "trigger_step_min": 0,
        "retention_steps": 2,
        "linked_asset_ids": ["gov-civic", "gov-admin"],
    },
    {
        "decoy_id": "dec-bnk-service",
        "name": "Decoy SWIFT Transaction Gateway",
        "type": DecoyType.SERVICE,
        "sector": "banking",
        "description": "A simulated SWIFT gateway returning synthetic transaction data. All access attempts are logged.",
        "trigger_sector": "banking",
        "trigger_step_min": 0,
        "retention_steps": 2,
        "linked_asset_ids": ["bnk-swift", "bnk-core"],
    },
]

# Digital Twin sector → asset mapping (fictional)
SECTOR_ASSETS: Dict[str, List[str]] = {
    "military": ["mil-cmd-net", "mil-def-ops", "mil-intel"],
    "government": ["gov-civic", "gov-admin"],
    "telecom": ["tel-core", "tel-gateway"],
    "energy": ["eng-grid", "eng-power"],
    "banking": ["bnk-core", "bnk-swift"],
    "healthcare": ["hlt-hospital", "hlt-records"],
    "education": ["edu-campus", "edu-research"],
    "commercial": ["com-retail", "com-logistics"],
}

# Simulated attacker activity templates per decoy type
_ACTIVITY_TEMPLATES: Dict[DecoyType, List[str]] = {
    DecoyType.SERVER: [
        "Attacker enumerates services on the decoy server.",
        "Attacker attempts privilege escalation on the decoy.",
        "Attacker deploys persistence mechanism on the decoy.",
    ],
    DecoyType.CREDENTIAL: [
        "Attacker uses canary credential to access decoy resource.",
        "Attacker attempts lateral movement with canary credential.",
    ],
    DecoyType.SERVICE: [
        "Attacker probes the decoy service endpoint.",
        "Attacker sends malformed requests to the decoy service.",
        "Attacker attempts service exploitation on decoy.",
    ],
    DecoyType.NETWORK_PATH: [
        "Attacker follows the false network route.",
        "Attacker discovers the route leads to a monitored segment.",
    ],
    DecoyType.HONEY_RESOURCE: [
        "Attacker accesses the honey resource.",
        "Attacker attempts to exfiltrate synthetic data.",
        "Attacker analyses the honey data for anomalies.",
    ],
    DecoyType.DOCUMENT: [
        "Attacker opens the decoy document.",
        "Attacker attempts to exfiltrate the decoy document.",
        "Attacker searches for additional decoy documents in the same directory.",
    ],
}

# MITRE technique mapping for deception events (fictional)
_DECEPTION_MITRE = {
    DecoyType.SERVER: ("T1595", "Active Scanning"),
    DecoyType.CREDENTIAL: ("T1078", "Valid Accounts"),
    DecoyType.SERVICE: ("T1021", "Remote Services"),
    DecoyType.NETWORK_PATH: ("T1021", "Remote Services"),
    DecoyType.HONEY_RESOURCE: ("T1565", "Data Manipulation"),
    DecoyType.DOCUMENT: ("T1027", "Obfuscated Files or Information"),
}

# Phase 10: DeceptionActionType → (MITRE technique, MITRE name, base signal strength)
ACTION_MITRE_MAP: Dict[DeceptionActionType, tuple] = {
    DeceptionActionType.RECONNAISSANCE: ("T1595", "Active Scanning", 0.35),
    DeceptionActionType.SUSPICIOUS_LOGIN: ("T1078", "Valid Accounts", 0.50),
    DeceptionActionType.CANARY_CREDENTIAL_USE: ("T1078", "Valid Accounts", 0.60),
    DeceptionActionType.SERVICE_PROBING: ("T1021", "Remote Services", 0.40),
    DeceptionActionType.PRIVILEGE_ESCALATION: ("T1078", "Valid Accounts", 0.70),
    DeceptionActionType.SUSPICIOUS_FILE_ACCESS: ("T1027", "Obfuscated Files or Information", 0.45),
}

# Phase 10: DecoyType → list of (DeceptionActionType, description) for interaction cycles
DECOY_ACTION_TEMPLATES: Dict[DecoyType, List[tuple]] = {
    DecoyType.SERVER: [
        (DeceptionActionType.RECONNAISSANCE, "Attacker performs reconnaissance scan on the decoy server."),
        (DeceptionActionType.SERVICE_PROBING, "Attacker probes services running on the decoy server."),
        (DeceptionActionType.PRIVILEGE_ESCALATION, "Attacker attempts privilege escalation on the decoy server."),
        (DeceptionActionType.SUSPICIOUS_FILE_ACCESS, "Attacker searches for sensitive files on the decoy server."),
    ],
    DecoyType.CREDENTIAL: [
        (DeceptionActionType.CANARY_CREDENTIAL_USE, "Attacker uses canary credential to access decoy resource."),
        (DeceptionActionType.SUSPICIOUS_LOGIN, "Attacker attempts login with harvested canary credentials."),
    ],
    DecoyType.SERVICE: [
        (DeceptionActionType.SERVICE_PROBING, "Attacker probes the decoy service endpoint."),
        (DeceptionActionType.SUSPICIOUS_LOGIN, "Attacker attempts authentication on the decoy service."),
        (DeceptionActionType.PRIVILEGE_ESCALATION, "Attacker attempts service exploitation on the decoy."),
    ],
    DecoyType.NETWORK_PATH: [
        (DeceptionActionType.RECONNAISSANCE, "Attacker follows the false network route and scans the path."),
        (DeceptionActionType.SERVICE_PROBING, "Attacker discovers the route leads to a monitored segment."),
    ],
    DecoyType.HONEY_RESOURCE: [
        (DeceptionActionType.SUSPICIOUS_FILE_ACCESS, "Attacker accesses the honey resource data."),
        (DeceptionActionType.SUSPICIOUS_FILE_ACCESS, "Attacker attempts to exfiltrate synthetic data."),
        (DeceptionActionType.RECONNAISSANCE, "Attacker analyses the honey data for anomalies."),
    ],
    DecoyType.DOCUMENT: [
        (DeceptionActionType.SUSPICIOUS_FILE_ACCESS, "Attacker opens the decoy document."),
        (DeceptionActionType.SUSPICIOUS_FILE_ACCESS, "Attacker attempts to exfiltrate the decoy document."),
        (DeceptionActionType.RECONNAISSANCE, "Attacker searches for additional decoy documents in the directory."),
    ],
}


# Risk level → deception posture mapping
_RISK_TO_POSTURE = {
    "normal": DeceptionPosture.MONITOR,
    "suspicious": DeceptionPosture.ACTIVATE,
    "high_risk": DeceptionPosture.REDIRECT,
    "critical": DeceptionPosture.CONTAIN,
}


class DeceptionEngine:
    """
    Evaluates simulated attacker actions against the deception grid.

    Each call to evaluate_step() checks if the current attack triggers
    any armed decoys, records deception events, and manages the
    attacker's time inside active decoys.

    Phase 6 adds:
    - Adaptive posture driven by detection risk level.
    - Attacker state tracking (free-roaming / trapped / contained).
    - simulate_attacker_decoy() — manual decoy injection.
    - contain_attacker() — safe freeze/contain simulation.
    - Diversion tracking — which real assets were protected.
    """

    def __init__(self):
        self.decoys: Dict[str, Decoy] = {}
        self.events: List[DeceptionEvent] = []
        self._next_event_id = 1
        self._active_decoy_ids: List[str] = []  # decoys currently holding the attacker
        self._on_event: Optional[Callable] = None
        # Phase 6 state
        self._attacker_state: AttackerState = AttackerState.FREE_ROAMING
        self._current_decoy_id: Optional[str] = None
        self._posture: DeceptionPosture = DeceptionPosture.MONITOR
        self._total_diversions: int = 0
        self._detection_engine = None
        self._deploy_decoys()

    def _deploy_decoys(self):
        """Instantiate decoys from the registry."""
        for spec in DECOY_REGISTRY:
            d = Decoy(
                decoy_id=spec["decoy_id"],
                name=spec["name"],
                decoy_type=spec["type"],
                sector=spec["sector"],
                description=spec["description"],
                trigger_sector=spec["trigger_sector"],
                trigger_step_min=spec["trigger_step_min"],
            )
            d.retention_steps = spec.get("retention_steps", 2)
            d.linked_asset_ids = list(spec.get("linked_asset_ids", []))
            self.decoys[d.decoy_id] = d

    def set_event_callback(self, callback: Callable):
        """Set a callback invoked on each deception event: callback(event_dict)."""
        self._on_event = callback

    def set_detection_engine(self, det_engine):
        """Wire the detection engine so deception events feed the evidence chain."""
        self._detection_engine = det_engine

    # ------------------------------------------------------------------
    # Evaluation (called by simulator)
    # ------------------------------------------------------------------

    def evaluate_step(self, step_index: int, step_data: dict) -> List[DeceptionEvent]:
        """
        Evaluate one simulator step against the deception grid.

        Returns a list of DeceptionEvent objects generated this step.
        """
        new_events: List[DeceptionEvent] = []
        current_sector = step_data.get("sector", "")

        # If attacker is contained, skip evaluation
        if self._attacker_state == AttackerState.CONTAINED:
            return new_events

        # 1. Check armed decoys for triggering
        for decoy in self.decoys.values():
            if decoy.status != DecoyStatus.ARMED:
                continue
            if decoy.trigger_sector != current_sector:
                continue
            if step_index < decoy.trigger_step_min:
                continue

            # Trigger the decoy
            if decoy.trigger():
                if decoy.decoy_id not in self._active_decoy_ids:
                    self._active_decoy_ids.append(decoy.decoy_id)
                # Track diversion
                decoy.diverted_from = list(decoy.linked_asset_ids)
                self._total_diversions += len(decoy.diverted_from)
                evt = self._make_event(
                    decoy, "triggered",
                    f"Decoy '{decoy.name}' triggered by attacker activity in {decoy.trigger_sector}.",
                    evidence_boost=0.15,
                )
                evt.attacker_state = AttackerState.TRAPPED.value
                evt.diverted_from = list(decoy.diverted_from)
                # Update attacker state
                self._attacker_state = AttackerState.TRAPPED
                self._current_decoy_id = decoy.decoy_id
                new_events.append(evt)

        # 2. Simulate attacker activity in active decoys
        decoys_to_remove = []
        for decoy_id in list(self._active_decoy_ids):
            decoy = self.decoys[decoy_id]
            if decoy.status != DecoyStatus.TRIGGERED:
                decoys_to_remove.append(decoy_id)
                continue

            # Pick an action from the Phase 10 action templates
            action_templates = DECOY_ACTION_TEMPLATES.get(decoy.decoy_type, [])
            idx = decoy.steps_in_decoy % len(action_templates) if action_templates else 0
            if action_templates:
                action_type, activity = action_templates[idx]
            else:
                action_type = None
                activity = "Attacker interacts with decoy."

            decoy.record_activity(activity)
            self._record_interaction(decoy, activity, action_type)

            evt = self._make_event(
                decoy, "activity",
                activity,
                evidence_boost=0.05,
                action_type=action_type,
            )
            evt.attacker_state = AttackerState.TRAPPED.value
            new_events.append(evt)

            # Check if the attacker adapts / bypasses
            if decoy.check_adaptation():
                evt2 = self._make_event(
                    decoy, "bypassed",
                    f"Attacker recognised deception in '{decoy.name}' and adapted.",
                    evidence_boost=0.10,
                )
                evt2.attacker_state = AttackerState.FREE_ROAMING.value
                new_events.append(evt2)
                decoys_to_remove.append(decoy_id)
                # Attacker is free again
                self._attacker_state = AttackerState.FREE_ROAMING
                self._current_decoy_id = None

        for decoy_id in decoys_to_remove:
            if decoy_id in self._active_decoy_ids:
                self._active_decoy_ids.remove(decoy_id)

        # Notify callback and feed detection engine
        for evt in new_events:
            if self._on_event:
                self._on_event(evt.to_dict())
            self._feed_detection(evt)

        return new_events

    # ------------------------------------------------------------------
    # Adaptive deception posture
    # ------------------------------------------------------------------

    def update_posture(self, risk_level_str: str) -> DeceptionPosture:
        """
        Update the deception posture based on the current detection risk level.

        Called by the API layer so the deception engine doesn't need a
        hard dependency on the detection engine.
        """
        new_posture = _RISK_TO_POSTURE.get(risk_level_str, DeceptionPosture.MONITOR)
        self._posture = new_posture
        return new_posture

    @property
    def posture(self) -> DeceptionPosture:
        return self._posture

    # ------------------------------------------------------------------
    # Activate Decoys — operator-initiated decoy arming
    # ------------------------------------------------------------------

    def activate_decoys(self) -> dict:
        """
        Operator command: elevate deception posture to ACTIVATE and record a
        synthetic event for every currently ARMED decoy, signalling that the
        deception grid has been explicitly activated.

        Does NOT inject the attacker into a decoy (use simulate_attacker_decoy
        for that).  Does NOT interact with any real system.

        Returns a summary dict suitable for JSON serialisation.
        """
        # Elevate posture to at least ACTIVATE
        if self._posture in (DeceptionPosture.MONITOR,):
            self._posture = DeceptionPosture.ACTIVATE

        armed = list(self.armed_decoys)
        activated_names: List[str] = []

        for decoy in armed:
            # Emit an "activity" event for each armed decoy to register evidence
            evt = self._make_event(
                decoy,
                "activity",
                f"Decoy '{decoy.name}' activated by operator command — "
                f"deception grid armed and monitoring sector '{decoy.sector}'.",
                evidence_boost=0.08,
                action_type=DeceptionActionType.RECONNAISSANCE,
            )
            evt.attacker_state = self._attacker_state.value
            if self._on_event:
                self._on_event(evt.to_dict())
            self._feed_detection(evt)
            activated_names.append(decoy.name)

        return {
            "ok": True,
            "posture": self._posture.value,
            "armed_count": len(armed),
            "activated_decoys": activated_names,
            "attacker_state": self._attacker_state.value,
            "message": (
                f"Deception grid activated. {len(armed)} decoy(s) armed and monitoring. "
                "No real systems affected."
            ),
        }

    # ------------------------------------------------------------------
    # Simulate Attacker → Decoy (manual injection for demo)
    # ------------------------------------------------------------------

    def simulate_attacker_decoy(self, decoy_id: Optional[str] = None) -> dict:
        """
        Manually inject the simulated attacker into a decoy.

        If decoy_id is None, picks a random ARMED decoy.
        Returns a summary dict with the event and diversion info.
        """
        if self._attacker_state == AttackerState.CONTAINED:
            return {"error": "Attacker is already contained."}

        # Find a target decoy
        target: Optional[Decoy] = None
        if decoy_id and decoy_id in self.decoys:
            target = self.decoys[decoy_id]
        else:
            armed = [d for d in self.decoys.values() if d.status == DecoyStatus.ARMED]
            if armed:
                target = random.choice(armed)
            else:
                # All decoys triggered/bypassed — pick any triggered one
                triggered = [d for d in self.decoys.values() if d.status == DecoyStatus.TRIGGERED]
                if triggered:
                    target = random.choice(triggered)

        if target is None:
            return {"error": "No decoys available."}

        # Force-trigger if still armed
        if target.status == DecoyStatus.ARMED:
            target.trigger()
            if target.decoy_id not in self._active_decoy_ids:
                self._active_decoy_ids.append(target.decoy_id)

        # Track diversion
        target.diverted_from = list(target.linked_asset_ids)
        self._total_diversions += len(target.diverted_from)

        # Update attacker state
        self._attacker_state = AttackerState.TRAPPED
        self._current_decoy_id = target.decoy_id

        # Simulate one activity entry using Phase 10 action templates
        action_templates = DECOY_ACTION_TEMPLATES.get(target.decoy_type, [])
        if action_templates:
            first_action_type, activity = action_templates[0]
        else:
            first_action_type = None
            activity = "Attacker enters the decoy."
        target.record_activity(activity)
        self._record_interaction(target, activity, first_action_type)

        # Create trigger + activity events
        trigger_evt = self._make_event(
            target, "triggered",
            f"Simulated attacker redirected into decoy '{target.name}' "
            f"in the {target.sector} sector.",
            evidence_boost=0.15,
            action_type=DeceptionActionType.RECONNAISSANCE,
        )
        trigger_evt.attacker_state = AttackerState.TRAPPED.value
        trigger_evt.diverted_from = list(target.diverted_from)

        activity_evt = self._make_event(
            target, "activity",
            activity,
            evidence_boost=0.05,
            action_type=first_action_type,
        )
        activity_evt.attacker_state = AttackerState.TRAPPED.value

        # Feed events to detection + callback
        for evt in [trigger_evt, activity_evt]:
            if self._on_event:
                self._on_event(evt.to_dict())
            self._feed_detection(evt)

        # Build sector protection list
        protected_assets = SECTOR_ASSETS.get(target.trigger_sector, [])

        return {
            "decoy_id": target.decoy_id,
            "decoy_name": target.name,
            "decoy_type": target.decoy_type.value,
            "sector": target.sector,
            "attacker_state": self._attacker_state.value,
            "diverted_from": list(target.diverted_from),
            "protected_assets": protected_assets,
            "activity": activity,
            "timestamp": trigger_evt.timestamp.isoformat(),
        }

    # ------------------------------------------------------------------
    # Freeze / Contain simulation
    # ------------------------------------------------------------------

    def contain_attacker(self) -> dict:
        """
        Safely freeze the simulated attacker inside Cyber Arena.

        Changes the attacker's state to CONTAINED.
        Does NOT interact with any real system.
        """
        previous_state = self._attacker_state
        self._attacker_state = AttackerState.CONTAINED

        # Generate a containment event
        current_decoy = None
        if self._current_decoy_id:
            current_decoy = self.decoys.get(self._current_decoy_id)

        decoy_name = current_decoy.name if current_decoy else "Unknown"
        evt = self._make_event(
            current_decoy or next(iter(self.decoys.values())),
            "contained",
            f"Simulated attacker contained by operator command. "
            f"Attacker was in decoy '{decoy_name}'. "
            f"All simulated activity frozen — no real systems affected.",
            evidence_boost=0.20,
        )
        evt.attacker_state = AttackerState.CONTAINED.value

        if self._on_event:
            self._on_event(evt.to_dict())
        self._feed_detection(evt)

        return {
            "attacker_state": self._attacker_state.value,
            "previous_state": previous_state.value,
            "current_decoy": self._current_decoy_id,
            "message": (
                "Simulated attacker contained. All activity frozen within "
                "Cyber Arena. No real systems were affected."
            ),
            "timestamp": evt.timestamp.isoformat(),
        }

    # ------------------------------------------------------------------
    # Detection evidence integration
    # ------------------------------------------------------------------

    def _feed_detection(self, evt: DeceptionEvent):
        """Push a deception event into the detection engine's evidence chain."""
        if self._detection_engine is None:
            return

        # Use Phase 10 fields if available, otherwise fall back to legacy mapping
        mitre_t = evt.mitre_technique or "T1595"
        mitre_n = evt.mitre_name or "Active Scanning"
        # Deception events use a lower signal strength so they don't dominate
        signal = min(0.50, evt.signal_strength if evt.signal_strength > 0 else evt.evidence_boost * 3)
        self._detection_engine.ingest_event({
            "timestamp": evt.timestamp.isoformat(),
            "sector": evt.sector,
            "targets": [evt.decoy_id],
            "mitre_technique": mitre_t,
            "mitre_name": mitre_n,
            "description": f"[DECEPTION] {evt.description}",
            "signal_strength": signal,
        })

    # ------------------------------------------------------------------
    # Phase 10: Interaction recording
    # ------------------------------------------------------------------

    def _record_interaction(self, decoy: Decoy, action_description: str,
                          action_type: Optional[DeceptionActionType] = None):
        """
        Record a structured interaction between the simulated attacker
        and a decoy.  Each record captures: timestamp, sector, decoy,
        action, MITRE technique, signal strength, and confidence contribution.
        """
        now = datetime.now(timezone.utc)

        # Look up MITRE mapping from action type
        mitre_t, mitre_n, base_signal = ("T1595", "Active Scanning", 0.35)
        if action_type and action_type in ACTION_MITRE_MAP:
            mitre_t, mitre_n, base_signal = ACTION_MITRE_MAP[action_type]

        record = {
            "timestamp": now.isoformat(),
            "sector": decoy.sector,
            "decoy_id": decoy.decoy_id,
            "decoy_name": decoy.name,
            "action": action_description,
            "action_type": action_type.value if action_type else None,
            "mitre_technique": mitre_t,
            "mitre_name": mitre_n,
            "signal_strength": base_signal,
            "confidence_contribution": round(base_signal * 0.10, 4),
        }
        decoy.interactions.append(record)

    # ------------------------------------------------------------------
    # Phase 10: Adaptive decoy selection
    # ------------------------------------------------------------------

    def select_decoy_for_threat(self) -> Optional[Decoy]:
        """
        Select the most relevant decoy based on current detection signals.

        Uses the detection engine's threat level and sector heatmap to
        choose a decoy that best matches the active threat profile.
        Higher-confidence threats receive more relevant deception resources.
        """
        if self._detection_engine is None:
            # No detection engine — pick a random armed decoy
            armed = [d for d in self.decoys.values() if d.status == DecoyStatus.ARMED]
            return random.choice(armed) if armed else None

        # Get current detection state
        threat_level = self._detection_engine.threat_level()
        heatmap = self._detection_engine.sector_heatmap()

        # Score sectors by evidence count
        sector_scores: Dict[str, int] = {}
        for entry in heatmap:
            sector_scores[entry["sector"]] = entry["evidence_count"]

        # Score each armed decoy
        best_decoy = None
        best_score = -1

        for decoy in self.decoys.values():
            if decoy.status != DecoyStatus.ARMED:
                continue

            score = 0.0
            # Bonus for decoys in sectors with active threats
            score += sector_scores.get(decoy.trigger_sector, 0) * 2

            # Higher posture = higher bonus for matching sector
            if self._posture in (DeceptionPosture.REDIRECT, DeceptionPosture.CONTAIN):
                score += 3

            # Prefer decoys whose trigger sector matches a hot sector
            if decoy.trigger_sector in sector_scores:
                score += sector_scores[decoy.trigger_sector]

            if score > best_score:
                best_score = score
                best_decoy = decoy

        # Fallback to random if no clear winner
        if best_decoy is None:
            armed = [d for d in self.decoys.values() if d.status == DecoyStatus.ARMED]
            return random.choice(armed) if armed else None

        return best_decoy

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_event(self, decoy: Decoy, event_type: str, description: str,
                    evidence_boost: float = 0.0,
                    action_type: Optional[DeceptionActionType] = None) -> DeceptionEvent:
        evt = DeceptionEvent(
            event_id=self._next_event_id,
            timestamp=datetime.now(timezone.utc),
            decoy_id=decoy.decoy_id,
            decoy_name=decoy.name,
            decoy_type=decoy.decoy_type,
            sector=decoy.sector,
            event_type=event_type,
            description=description,
            evidence_boost=evidence_boost,
        )
        # Phase 10: populate MITRE technique and signal from action type
        if action_type and action_type in ACTION_MITRE_MAP:
            mitre_t, mitre_n, base_signal = ACTION_MITRE_MAP[action_type]
            evt.mitre_technique = mitre_t
            evt.mitre_name = mitre_n
            evt.signal_strength = base_signal
            evt.action_type = action_type
            evt.confidence_contribution = round(base_signal * evidence_boost * 10, 4)
        else:
            # Fallback: use the legacy DecoyType → MITRE mapping
            mitre_t, mitre_n = _DECEPTION_MITRE.get(
                decoy.decoy_type, ("T1595", "Active Scanning"))
            evt.mitre_technique = mitre_t
            evt.mitre_name = mitre_n
            evt.signal_strength = min(0.50, evidence_boost * 3)
        self._next_event_id += 1
        self.events.append(evt)
        return evt

    # ------------------------------------------------------------------
    # State queries
    # ------------------------------------------------------------------

    @property
    def active_decoys(self) -> List[Decoy]:
        return [d for d in self.decoys.values() if d.status == DecoyStatus.TRIGGERED]

    @property
    def armed_decoys(self) -> List[Decoy]:
        return [d for d in self.decoys.values() if d.status == DecoyStatus.ARMED]

    @property
    def triggered_decoys(self) -> List[Decoy]:
        return [d for d in self.decoys.values()
                if d.status in (DecoyStatus.TRIGGERED, DecoyStatus.BYPASSED, DecoyStatus.EXHAUSTED)]

    @property
    def attacker_state(self) -> AttackerState:
        return self._attacker_state

    @property
    def total_diversions(self) -> int:
        return self._total_diversions

    @property
    def total_interactions(self) -> int:
        """Phase 10: total number of structured interactions across all decoys."""
        return sum(len(d.interactions) for d in self.decoys.values())

    def is_contained(self) -> bool:
        return self._attacker_state == AttackerState.CONTAINED

    def asset_categories(self) -> List[dict]:
        """
        Return the asset-type legend data for the UI.
        Shows Real / Decoy / Isolated / Contained Attacker with descriptions.
        """
        result = []
        for cat in AssetCategory:
            result.append({
                "category": cat.value,
                "label": ASSET_CATEGORY_LABELS[cat],
                "description": ASSET_CATEGORY_DESCRIPTIONS[cat],
            })
        return result

    def adaptive_status(self) -> dict:
        """Return the current adaptive deception posture details."""
        return {
            "posture": self._posture.value,
            "description": POSTURE_DESCRIPTIONS[self._posture],
            "attacker_state": self._attacker_state.value,
            "current_decoy_id": self._current_decoy_id,
            "current_decoy_name": (
                self.decoys[self._current_decoy_id].name
                if self._current_decoy_id and self._current_decoy_id in self.decoys
                else None
            ),
            "total_diversions": self._total_diversions,
            "contained": self.is_contained(),
        }

    def status(self) -> dict:
        return {
            "total_decoys": len(self.decoys),
            "armed": len(self.armed_decoys),
            "active": len(self.active_decoys),
            "bypassed": sum(1 for d in self.decoys.values() if d.status == DecoyStatus.BYPASSED),
            "total_events": len(self.events),
            "total_interactions": self.total_interactions,
            "decoys": [d.to_dict() for d in self.decoys.values()],
            "events": [e.to_dict() for e in self.events],
            "active_decoy_ids": list(self._active_decoy_ids),
            "adaptive": self.adaptive_status(),
            "asset_categories": self.asset_categories(),
            "total_diversions": self._total_diversions,
            "attacker_state": self._attacker_state.value,
            "posture": self._posture.value,
        }

    def to_dict(self) -> dict:
        return self.status()

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

    def reset(self):
        """Re-deploy all decoys and clear events."""
        self.decoys.clear()
        self.events.clear()
        self._next_event_id = 1
        self._active_decoy_ids.clear()
        self._attacker_state = AttackerState.FREE_ROAMING
        self._current_decoy_id = None
        self._posture = DeceptionPosture.MONITOR
        self._total_diversions = 0
        self._deploy_decoys()


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[DeceptionEngine] = None


def get_deception_engine() -> DeceptionEngine:
    """Return the global DeceptionEngine instance (create on first call)."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = DeceptionEngine()
    return _engine_instance
