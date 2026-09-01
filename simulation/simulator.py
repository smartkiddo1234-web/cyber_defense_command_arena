"""
Adversary Simulation Engine

Drives a fictional simulated cyber attack through the Digital Twin.
Scenario: Military → Telecom → Energy → Healthcare

All activity is synthetic. No real systems are contacted.
"""

import time
import threading
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from simulation.models import AssetStatus


# ---------------------------------------------------------------------------
# Scenario definition — scripted attack steps per sector
# ---------------------------------------------------------------------------

SCENARIO: List[Dict] = [
    # ---- Step 0: Initial foothold in Military ----
    {
        "sector": "military",
        "targets": ["mil-cmd-net"],
        "target_status": AssetStatus.UNDER_ATTACK,
        "mitre_technique": "T1595",
        "mitre_name": "Active Scanning",
        "description": "Adversary performs reconnaissance probing of the military command network perimeter.",
        "signal_strength": 0.4,
    },
    {
        "sector": "military",
        "targets": ["mil-cmd-net", "mil-def-ops"],
        "target_status": AssetStatus.COMPROMISED,
        "mitre_technique": "T1078",
        "mitre_name": "Valid Accounts",
        "description": "Adversary uses compromised credentials to gain persistent access to military systems.",
        "signal_strength": 0.7,
    },
    # ---- Step 2: Lateral movement into Telecom ----
    {
        "sector": "telecom",
        "targets": ["tel-gateway"],
        "target_status": AssetStatus.UNDER_ATTACK,
        "mitre_technique": "T1021",
        "mitre_name": "Remote Services",
        "description": "Adversary pivots through military-telecom trust link to attack the communications gateway.",
        "signal_strength": 0.5,
    },
    {
        "sector": "telecom",
        "targets": ["tel-core", "tel-gateway"],
        "target_status": AssetStatus.COMPROMISED,
        "mitre_technique": "T1078",
        "mitre_name": "Valid Accounts",
        "description": "Adversary escalates privileges and compromises the core telecom network.",
        "signal_strength": 0.8,
    },
    # ---- Step 4: Disruption moves into Energy ----
    {
        "sector": "energy",
        "targets": ["eng-grid"],
        "target_status": AssetStatus.UNDER_ATTACK,
        "mitre_technique": "T1027",
        "mitre_name": "Obfuscated Files or Information",
        "description": "Adversary deploys obfuscated payloads targeting the grid management server.",
        "signal_strength": 0.6,
    },
    {
        "sector": "energy",
        "targets": ["eng-power", "eng-grid"],
        "target_status": AssetStatus.COMPROMISED,
        "mitre_technique": "T1565",
        "mitre_name": "Data Manipulation",
        "description": "Adversary gains control of power control systems and manipulates grid telemetry data.",
        "signal_strength": 0.9,
    },
    # ---- Step 6: Final target — Healthcare ----
    {
        "sector": "healthcare",
        "targets": ["hlt-hospital"],
        "target_status": AssetStatus.UNDER_ATTACK,
        "mitre_technique": "T1486",
        "mitre_name": "Data Encrypted for Impact",
        "description": "Adversary begins encrypting hospital network systems for maximum disruption.",
        "signal_strength": 0.7,
    },
    {
        "sector": "healthcare",
        "targets": ["hlt-hospital", "hlt-records"],
        "target_status": AssetStatus.COMPROMISED,
        "mitre_technique": "T1486",
        "mitre_name": "Data Encrypted for Impact",
        "description": "Adversary fully compromises healthcare systems including medical records.",
        "signal_strength": 1.0,
    },
]


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique pool for user-controlled simulations
# ---------------------------------------------------------------------------

TECHNIQUE_POOL: Dict[str, str] = {
    "T1595": "Active Scanning",
    "T1078": "Valid Accounts",
    "T1021": "Remote Services",
    "T1027": "Obfuscated Files or Information",
    "T1565": "Data Manipulation",
    "T1486": "Data Encrypted for Impact",
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1059": "Command and Scripting Interpreter",
    "T1055": "Process Injection",
    "T1003": "OS Credential Dumping",
    "T1489": "Service Stop",
    "T1498": "Network Denial of Service",
    "T1531": "Account Access Removal",
    "T1561": "Disk Wipe",
}


def _threat_to_signal(threat_level: str, phase: str = "initial") -> float:
    """Map a user-selected threat level to a signal_strength value."""
    base = {"low": 0.3, "moderate": 0.5, "high": 0.7, "severe": 0.9}
    val = base.get(threat_level, 0.5)
    if phase == "escalation":
        val = min(1.0, val + 0.2)
    return round(val, 2)


class Simulator:
    """
    Drives the scripted attack scenario through the Digital Twin.

    Thread-safe: start() runs the scenario in a background thread,
    stop() halts it, and state can be queried at any time.

    Supports two modes:
      - Default: fixed SCENARIO (Military → Telecom → Energy → Healthcare)
      - Custom: user-configured path via configure()
    """

    STEP_INTERVAL = 3.0  # seconds between scenario steps

    def __init__(self, twin, on_step: Optional[Callable] = None):
        """
        Args:
            twin: The DigitalTwin instance to mutate.
            on_step: Optional callback invoked after each step with
                     (step_index, step_data, event_dict).
        """
        self._twin = twin
        self._on_step = on_step
        self._current_step = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._events: List[dict] = []
        self._attack_path: List[str] = []
        self._custom_scenario: Optional[List[Dict]] = None
        # Application-level standby mode
        self._standby = False
        self._paused_by_standby = False  # was simulation running when standby was entered?

    # ------------------------------------------------------------------
    # Active scenario accessor
    # ------------------------------------------------------------------

    @property
    def _active_scenario(self) -> List[Dict]:
        """Return the currently active scenario (custom or default)."""
        return self._custom_scenario if self._custom_scenario is not None else SCENARIO

    # ------------------------------------------------------------------
    # Public control
    # ------------------------------------------------------------------

    def start(self):
        """Begin (or resume) the scenario in a background thread."""
        with self._lock:
            if self._running:
                return
            if self._standby:
                return  # blocked while in standby
            self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Halt the scenario (can be resumed with start)."""
        with self._lock:
            self._running = False

    # ------------------------------------------------------------------
    # Standby mode — application-level pause (NOT OS sleep)
    # ------------------------------------------------------------------

    @property
    def is_standby(self) -> bool:
        """Return True when the application is in standby mode."""
        return self._standby

    def enter_standby(self) -> Dict:
        """
        Enter standby mode.

        If the simulation is currently running it is paused (the background
        thread is stopped) but all state is preserved.  Returns a status dict.
        """
        with self._lock:
            self._standby = True
            if self._running:
                self._running = False
                self._paused_by_standby = True
            else:
                self._paused_by_standby = False
        return self.standby_info()

    def exit_standby(self) -> Dict:
        """
        Leave standby mode and return to OPERATIONAL.

        If the simulation was paused by standby, it is resumed automatically.
        """
        with self._lock:
            self._standby = False
            should_resume = self._paused_by_standby
            self._paused_by_standby = False

        if should_resume and not self.is_complete:
            self.start()

        return self.standby_info()

    def standby_info(self) -> Dict:
        """Return a summary of the current standby state."""
        return {
            "standby": self._standby,
            "paused_by_standby": self._paused_by_standby,
            "simulation_running": self._running,
            "simulation_complete": self.is_complete,
            "current_step": self._current_step,
            "total_steps": self.total_steps,
        }

    def reset(self):
        """Stop and reset everything to initial state."""
        self.stop()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        with self._lock:
            self._current_step = 0
            self._events.clear()
            self._attack_path.clear()
            self._standby = False
            self._paused_by_standby = False
        self._twin.reset_all()

    def step_once(self):
        """Advance exactly one scenario step (synchronous, for testing)."""
        self._execute_step()

    def configure(self, steps: List[Dict]) -> Dict:
        """
        Configure a custom attack scenario.

        Each step dict must contain:
          - sector: str (sector ID)
          - mitre_technique: str (MITRE ATT&CK technique ID)
          - threat_level: str (one of: low, moderate, high, severe)

        The first step defines the starting sector.
        Subsequent steps must be reachable via Digital Twin dependencies.

        Returns {"ok": True/False, "steps": [...], "errors": [...]}
        """
        errors: List[str] = []
        expanded: List[Dict] = []
        valid_sectors = set(self._twin.sectors.keys())
        sector_path: List[str] = []

        for i, step in enumerate(steps):
            sid = step.get("sector", "")
            technique = step.get("mitre_technique", "T1595")
            threat_level = step.get("threat_level", "moderate")

            if sid not in valid_sectors:
                errors.append(f"Step {i}: unknown sector '{sid}'")
                continue

            # Validate reachability (skip for first step)
            if sector_path:
                reachable = self._reachable_sectors(sector_path[-1])
                if sid not in reachable:
                    errors.append(
                        f"Step {i}: '{sid}' not reachable from "
                        f"'{sector_path[-1]}'. Valid targets: "
                        f"{', '.join(sorted(reachable))}"
                    )
                    continue

            sector_path.append(sid)
            sector = self._twin.get_sector(sid)
            asset_ids = [a.asset_id for a in sector.assets]

            # Expand each sector into 2 steps: under_attack then compromised
            expanded.append({
                "sector": sid,
                "targets": [asset_ids[0]] if asset_ids else [],
                "target_status": AssetStatus.UNDER_ATTACK,
                "mitre_technique": technique,
                "mitre_name": TECHNIQUE_POOL.get(technique, technique),
                "description": (
                    f"Adversary performs {TECHNIQUE_POOL.get(technique, technique).lower()} "
                    f"targeting {sector.name} infrastructure."
                ),
                "signal_strength": _threat_to_signal(threat_level, phase="initial"),
            })
            expanded.append({
                "sector": sid,
                "targets": asset_ids,
                "target_status": AssetStatus.COMPROMISED,
                "mitre_technique": technique,
                "mitre_name": TECHNIQUE_POOL.get(technique, technique),
                "description": (
                    f"Adversary escalates and fully compromises "
                    f"{sector.name} systems."
                ),
                "signal_strength": _threat_to_signal(threat_level, phase="escalation"),
            })

        if errors:
            return {"ok": False, "steps": len(expanded), "errors": errors}

        self._custom_scenario = expanded
        return {"ok": True, "steps": len(expanded), "errors": errors}

    def clear_custom_scenario(self):
        """Revert to the default fixed SCENARIO."""
        self._custom_scenario = None

    # ------------------------------------------------------------------
    # Path validation helpers
    # ------------------------------------------------------------------

    def _reachable_sectors(self, sector_id: str) -> set:
        """Return all sectors reachable from sector_id (both directions)."""
        reachable = set()
        for d in self._twin.dependencies:
            if d.source_id == sector_id:
                reachable.add(d.target_id)
            elif d.target_id == sector_id:
                reachable.add(d.source_id)
        return reachable

    def valid_targets_for(self, sector_id: str) -> List[Dict]:
        """Return valid next-target sectors from a given sector."""
        targets = []
        for d in self._twin.dependencies:
            if d.source_id == sector_id:
                sec = self._twin.get_sector(d.target_id)
                if sec:
                    targets.append({
                        "sector_id": d.target_id,
                        "name": sec.name,
                        "icon": sec.icon,
                        "direction": "outgoing",
                        "label": d.label,
                    })
            elif d.target_id == sector_id:
                sec = self._twin.get_sector(d.source_id)
                if sec:
                    targets.append({
                        "sector_id": d.source_id,
                        "name": sec.name,
                        "icon": sec.icon,
                        "direction": "incoming",
                        "label": d.label,
                    })
        return targets

    # ------------------------------------------------------------------
    # State queries
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def current_step(self) -> int:
        return self._current_step

    @property
    def total_steps(self) -> int:
        return len(self._active_scenario)

    @property
    def is_complete(self) -> bool:
        return self._current_step >= len(self._active_scenario)

    @property
    def events(self) -> List[dict]:
        return list(self._events)

    @property
    def attack_path(self) -> List[str]:
        return list(self._attack_path)

    @property
    def is_custom(self) -> bool:
        return self._custom_scenario is not None

    def status(self) -> dict:
        scenario = self._active_scenario
        step_data = scenario[self._current_step - 1] if self._current_step > 0 else None
        return {
            "running": self._running,
            "current_step": self._current_step,
            "total_steps": self.total_steps,
            "complete": self.is_complete,
            "attack_path": list(self._attack_path),
            "current_sector": step_data["sector"] if step_data else None,
            "current_technique": step_data["mitre_technique"] if step_data else None,
            "current_technique_name": step_data["mitre_name"] if step_data else None,
            "events": list(self._events),
            "mode": "custom" if self.is_custom else "default",
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run_loop(self):
        """Background loop that advances the scenario at fixed intervals."""
        scenario = self._active_scenario
        while True:
            with self._lock:
                if not self._running or self._current_step >= len(scenario):
                    self._running = False
                    break
            self._execute_step()
            time.sleep(self.STEP_INTERVAL)

    def _execute_step(self):
        """Execute the next scenario step."""
        scenario = self._active_scenario
        with self._lock:
            if self._current_step >= len(scenario):
                self._running = False
                return
            step = scenario[self._current_step]
            self._current_step += 1

        sector_id = step["sector"]
        sector = self._twin.get_sector(sector_id)
        if not sector:
            return

        # Track attack path (unique sectors)
        if sector_id not in self._attack_path:
            self._attack_path.append(sector_id)

        # Mutate asset states in the twin
        for asset_id in step["targets"]:
            self._twin.set_asset_status(asset_id, step["target_status"])
            asset = self._twin.get_asset(asset_id)
            if asset:
                asset.threat_state = step["mitre_technique"]
                activity_msg = (
                    f"[{step['mitre_technique']}] {step['mitre_name']} — "
                    f"{step['description']}"
                )
                asset.activity.append(activity_msg)

        # Register the attack path on the twin
        self._twin.clear_attack_paths()
        self._twin.add_attack_path(list(self._attack_path))

        # Build detection event
        now = datetime.now(timezone.utc)
        event = {
            "id": len(self._events) + 1,
            "timestamp": now.isoformat(),
            "step": self._current_step,
            "sector": sector_id,
            "sector_name": sector.name,
            "targets": step["targets"],
            "target_status": step["target_status"].value,
            "mitre_technique": step["mitre_technique"],
            "mitre_name": step["mitre_name"],
            "description": step["description"],
            "signal_strength": step["signal_strength"],
        }
        self._events.append(event)

        # Callback (used by detection engine)
        if self._on_step:
            self._on_step(self._current_step - 1, step, event)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_sim_instance: Optional[Simulator] = None


def get_simulator(twin=None, on_step=None) -> Simulator:
    """Return the global Simulator instance (create on first call)."""
    global _sim_instance
    if _sim_instance is None:
        if twin is None:
            raise ValueError("First call to get_simulator must provide a twin.")
        _sim_instance = Simulator(twin, on_step=on_step)
    return _sim_instance
