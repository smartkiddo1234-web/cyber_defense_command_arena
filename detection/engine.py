"""
Detection Engine

Processes simulated events from the adversary simulator and produces:
- Threat scores with temporal confidence decay
- Evidence chains with explainability
- MITRE ATT&CK technique mapping
- Severity-rated alerts

All processing is entirely fictional and local.
"""

import math
from datetime import datetime, timezone
from typing import Dict, List, Optional

from detection.models import Alert, Evidence, RiskLevel, Severity, SignalType, ThreatLevel


# ---------------------------------------------------------------------------
# Severity thresholds
# ---------------------------------------------------------------------------

SEVERITY_THRESHOLDS = [
    (0.8, Severity.CRITICAL),
    (0.6, Severity.HIGH),
    (0.4, Severity.MEDIUM),
    (0.2, Severity.LOW),
    (0.0, Severity.INFO),
]

# ---------------------------------------------------------------------------
# Risk-level thresholds (system-wide operational posture)
# Distinct from per-event Severity — maps threat_score → RiskLevel
# ---------------------------------------------------------------------------

RISK_THRESHOLDS = [
    (0.70, RiskLevel.CRITICAL),
    (0.40, RiskLevel.HIGH_RISK),
    (0.15, RiskLevel.SUSPICIOUS),
    (0.00, RiskLevel.NORMAL),
]

DECAY_RATE = 0.95  # confidence multiplier per 3-second interval

# Exponential decay constant: -ln(DECAY_RATE) / 3 ≈ 0.0171
# Used by Evidence.exp_confidence() for the continuous formula
DECAY_LAMBDA = 0.0171

# ---------------------------------------------------------------------------
# MITRE technique → SignalType classification
# Maps each simulated MITRE ATT&CK technique to a detection signal type.
# ---------------------------------------------------------------------------

MITRE_TO_SIGNAL: Dict[str, SignalType] = {
    "T1595": SignalType.SUSPICIOUS_NETWORK,       # Active Scanning
    "T1078": SignalType.UNUSUAL_LOGIN,             # Valid Accounts
    "T1021": SignalType.LATERAL_MOVEMENT,          # Remote Services
    "T1027": SignalType.SUSPICIOUS_FILE_ACTIVITY,  # Obfuscated Files
    "T1565": SignalType.ABNORMAL_DATA_ACCESS,      # Data Manipulation
    "T1486": SignalType.SUSPICIOUS_FILE_ACTIVITY,  # Data Encrypted for Impact
}

# ---------------------------------------------------------------------------
# Threat-level thresholds (score → ThreatLevel)
# Distinct from Severity (per-event) and RiskLevel (operational posture).
# ---------------------------------------------------------------------------

THREAT_LEVEL_THRESHOLDS = [
    (0.70, ThreatLevel.CRITICAL),
    (0.40, ThreatLevel.HIGH),
    (0.15, ThreatLevel.MEDIUM),
    (0.00, ThreatLevel.LOW),
]


def _score_to_threat_level(score: float) -> ThreatLevel:
    """Map a 0.0–1.0 threat score to a ThreatLevel."""
    for threshold, level in THREAT_LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return ThreatLevel.LOW

# MITRE ATT&CK reference descriptions (fictional context)
MITRE_REFERENCE: Dict[str, str] = {
    "T1595": "Active Scanning — adversary probes victim infrastructure.",
    "T1078": "Valid Accounts — adversary leverages stolen or legitimate credentials.",
    "T1021": "Remote Services — adversary uses remote access protocols to move laterally.",
    "T1027": "Obfuscated Files or Information — adversary hides malicious payloads.",
    "T1565": "Data Manipulation — adversary alters stored data to disrupt operations.",
    "T1486": "Data Encrypted for Impact — adversary encrypts data for ransom or disruption.",
}


def _score_to_severity(score: float) -> Severity:
    for threshold, severity in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return Severity.INFO


def _score_to_risk(score: float) -> RiskLevel:
    """Map a 0.0–1.0 threat score to an operational RiskLevel."""
    for threshold, level in RISK_THRESHOLDS:
        if score >= threshold:
            return level
    return RiskLevel.NORMAL


# ---------------------------------------------------------------------------
# Synthetic event pool for the "Simulate Attack Event" control
# Each template can target any sector/asset in the Digital Twin.
# All data is entirely fictional.
# ---------------------------------------------------------------------------

SYNTHETIC_EVENTS: List[Dict] = [
    {
        "sector": "military", "targets": ["mil-cmd-net"],
        "mitre_technique": "T1595", "mitre_name": "Active Scanning",
        "description": "Synthetic reconnaissance sweep detected against the military command network perimeter.",
        "signal_strength": 0.45,
    },
    {
        "sector": "military", "targets": ["mil-def-ops"],
        "mitre_technique": "T1078", "mitre_name": "Valid Accounts",
        "description": "Synthetic credential abuse detected on military defense operations system.",
        "signal_strength": 0.70,
    },
    {
        "sector": "telecom", "targets": ["tel-gateway"],
        "mitre_technique": "T1021", "mitre_name": "Remote Services",
        "description": "Synthetic lateral movement via remote services into telecom gateway.",
        "signal_strength": 0.55,
    },
    {
        "sector": "telecom", "targets": ["tel-core"],
        "mitre_technique": "T1078", "mitre_name": "Valid Accounts",
        "description": "Synthetic privilege escalation detected on core telecom switching infrastructure.",
        "signal_strength": 0.75,
    },
    {
        "sector": "energy", "targets": ["eng-grid"],
        "mitre_technique": "T1027", "mitre_name": "Obfuscated Files or Information",
        "description": "Synthetic obfuscated payload deployed against energy grid management server.",
        "signal_strength": 0.65,
    },
    {
        "sector": "energy", "targets": ["eng-power"],
        "mitre_technique": "T1565", "mitre_name": "Data Manipulation",
        "description": "Synthetic telemetry data manipulation detected on power control systems.",
        "signal_strength": 0.85,
    },
    {
        "sector": "healthcare", "targets": ["hlt-hospital"],
        "mitre_technique": "T1486", "mitre_name": "Data Encrypted for Impact",
        "description": "Synthetic ransomware encryption activity detected on hospital network.",
        "signal_strength": 0.80,
    },
    {
        "sector": "healthcare", "targets": ["hlt-records"],
        "mitre_technique": "T1486", "mitre_name": "Data Encrypted for Impact",
        "description": "Synthetic data encryption spreading to medical records system.",
        "signal_strength": 0.90,
    },
    {
        "sector": "banking", "targets": ["bnk-core"],
        "mitre_technique": "T1078", "mitre_name": "Valid Accounts",
        "description": "Synthetic unauthorized access to banking core transaction system.",
        "signal_strength": 0.60,
    },
    {
        "sector": "banking", "targets": ["bnk-swift"],
        "mitre_technique": "T1565", "mitre_name": "Data Manipulation",
        "description": "Synthetic transaction record manipulation detected on SWIFT gateway.",
        "signal_strength": 0.85,
    },
    {
        "sector": "government", "targets": ["gov-civic"],
        "mitre_technique": "T1595", "mitre_name": "Active Scanning",
        "description": "Synthetic network scanning detected against government civic services portal.",
        "signal_strength": 0.40,
    },
    {
        "sector": "government", "targets": ["gov-admin"],
        "mitre_technique": "T1027", "mitre_name": "Obfuscated Files or Information",
        "description": "Synthetic obfuscated script execution detected on government admin workstation.",
        "signal_strength": 0.55,
    },
    {
        "sector": "education", "targets": ["edu-campus"],
        "mitre_technique": "T1021", "mitre_name": "Remote Services",
        "description": "Synthetic RDP brute-force attempt against university campus network.",
        "signal_strength": 0.50,
    },
    {
        "sector": "education", "targets": ["edu-research"],
        "mitre_technique": "T1078", "mitre_name": "Valid Accounts",
        "description": "Synthetic credential reuse attack on university research database.",
        "signal_strength": 0.60,
    },
    {
        "sector": "commercial", "targets": ["com-retail"],
        "mitre_technique": "T1595", "mitre_name": "Active Scanning",
        "description": "Synthetic port scanning detected on commercial retail POS infrastructure.",
        "signal_strength": 0.35,
    },
    {
        "sector": "commercial", "targets": ["com-logistics"],
        "mitre_technique": "T1027", "mitre_name": "Obfuscated Files or Information",
        "description": "Synthetic macro-based payload detected in logistics email system.",
        "signal_strength": 0.50,
    },
]


class DetectionEngine:
    """
    Ingests simulation events and maintains:
    - a chronological evidence chain
    - a weighted threat score with temporal decay
    - active alerts with severity ratings
    """

    def __init__(self):
        self.evidence: List[Evidence] = []
        self.alerts: List[Alert] = []
        self._next_evidence_id = 1
        self._next_alert_id = 1

    # ------------------------------------------------------------------
    # Event ingestion
    # ------------------------------------------------------------------

    def ingest_event(self, event: dict) -> Evidence:
        """
        Convert a simulator event into an Evidence record and
        potentially generate an Alert.
        """
        ts = datetime.fromisoformat(event["timestamp"])
        severity = _score_to_severity(event["signal_strength"])

        # Classify signal type from MITRE technique (or use explicit value)
        signal_type = event.get("signal_type")
        if signal_type is None:
            signal_type = MITRE_TO_SIGNAL.get(event.get("mitre_technique"))
        elif isinstance(signal_type, str):
            # Convert string value back to SignalType enum
            try:
                signal_type = SignalType(signal_type)
            except ValueError:
                signal_type = None

        ev = Evidence(
            evidence_id=self._next_evidence_id,
            timestamp=ts,
            sector=event["sector"],
            targets=event["targets"],
            mitre_technique=event["mitre_technique"],
            mitre_name=event["mitre_name"],
            description=event["description"],
            signal_strength=event["signal_strength"],
            severity=severity,
            signal_type=signal_type,
        )
        self._next_evidence_id += 1
        self.evidence.append(ev)

        # Update score contributions for all evidence
        self._update_score_contributions()

        # Auto-generate an alert if score is high enough
        current_score = self.threat_score()
        if current_score >= 0.4:
            self._generate_alert(ev, current_score)

        return ev

    # ------------------------------------------------------------------
    # Threat score with temporal confidence decay
    # ------------------------------------------------------------------

    def _update_score_contributions(self):
        """
        Recompute each evidence item's score_contribution using the
        exponential-decay confidence formula.

        contribution_i = weight_i × strength_i × e^(-λ × Δt_i)

        where weight_i is a linear recency weight (newer evidence counts more).
        """
        if not self.evidence:
            return
        for i, ev in enumerate(self.evidence):
            recency = (i + 1) / len(self.evidence)
            ev.score_contribution = recency * ev.exp_confidence(DECAY_LAMBDA)

    def threat_score(self) -> float:
        """
        Compute a 0.0–1.0 threat score from the evidence chain.

        Uses the exponential-decay formula:
            score = Σ(weight × strength × e^(-λΔt)) / Σ(weight)

        Each evidence item contributes its decayed confidence, weighted
        by recency.  A sector-diversity boost is added on top.
        """
        if not self.evidence:
            return 0.0

        # Refresh contributions so decay is always current
        self._update_score_contributions()

        weights: List[float] = []
        values: List[float] = []
        for i, ev in enumerate(self.evidence):
            recency = (i + 1) / len(self.evidence)
            weights.append(recency)
            values.append(ev.exp_confidence(DECAY_LAMBDA))

        total_weight = sum(weights)
        if total_weight == 0:
            return 0.0
        raw_score = sum(v * w for v, w in zip(values, weights)) / total_weight

        # Boost if multiple sectors are affected
        affected_sectors = len(set(e.sector for e in self.evidence))
        sector_boost = min(0.15, 0.05 * (affected_sectors - 1))

        return min(1.0, raw_score + sector_boost)

    # ------------------------------------------------------------------
    # Risk level (system-wide operational posture)
    # ------------------------------------------------------------------

    def risk_level(self) -> RiskLevel:
        """Return the current operational RiskLevel based on threat score."""
        return _score_to_risk(self.threat_score())

    def current_severity(self) -> Severity:
        return _score_to_severity(self.threat_score())

    def threat_level(self) -> ThreatLevel:
        """Return the current ThreatLevel (LOW/MEDIUM/HIGH/CRITICAL)."""
        return _score_to_threat_level(self.threat_score())

    # ------------------------------------------------------------------
    # Sector heatmap — which sectors have detection activity
    # ------------------------------------------------------------------

    def sector_heatmap(self) -> List[dict]:
        """
        Return a summary of detection activity per sector.
        Each entry: sector, evidence_count, max_signal, latest_technique.
        """
        sectors: Dict[str, dict] = {}
        for ev in self.evidence:
            if ev.sector not in sectors:
                sectors[ev.sector] = {
                    "sector": ev.sector,
                    "evidence_count": 0,
                    "max_signal": 0.0,
                    "latest_technique": "",
                    "latest_technique_name": "",
                    "latest_timestamp": "",
                }
            entry = sectors[ev.sector]
            entry["evidence_count"] += 1
            entry["max_signal"] = max(entry["max_signal"], ev.signal_strength)
            entry["latest_technique"] = ev.mitre_technique
            entry["latest_technique_name"] = ev.mitre_name
            entry["latest_timestamp"] = ev.timestamp.isoformat()
        return list(sectors.values())

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def _generate_alert(self, evidence: Evidence, score: float):
        severity = _score_to_severity(score)
        title = (
            f"{severity.value.upper()} — "
            f"{evidence.mitre_technique} ({evidence.mitre_name}) "
            f"detected in {evidence.sector}"
        )
        alert = Alert(
            alert_id=self._next_alert_id,
            timestamp=evidence.timestamp,
            severity=severity,
            title=title,
            description=evidence.description,
            sector=evidence.sector,
            evidence_ids=[evidence.evidence_id],
        )
        self._next_alert_id += 1
        self.alerts.append(alert)

    @property
    def active_alerts(self) -> List[Alert]:
        return [a for a in self.alerts if not a.acknowledged]

    # ------------------------------------------------------------------
    # Evidence chain (explainability)
    # ------------------------------------------------------------------

    def evidence_chain(self) -> List[dict]:
        """Return the full evidence chain with decayed confidence values."""
        return [ev.to_dict(DECAY_RATE) for ev in self.evidence]

    def mitre_summary(self) -> List[dict]:
        """Summarize MITRE techniques observed with first/last seen times."""
        seen: Dict[str, dict] = {}
        for ev in self.evidence:
            key = ev.mitre_technique
            if key not in seen:
                seen[key] = {
                    "technique": key,
                    "name": ev.mitre_name,
                    "description": MITRE_REFERENCE.get(key, ""),
                    "first_seen": ev.timestamp.isoformat(),
                    "last_seen": ev.timestamp.isoformat(),
                    "occurrences": 1,
                    "sectors": [ev.sector],
                }
            else:
                entry = seen[key]
                entry["last_seen"] = ev.timestamp.isoformat()
                entry["occurrences"] += 1
                if ev.sector not in entry["sectors"]:
                    entry["sectors"].append(ev.sector)
        return list(seen.values())

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Simulate Attack Event (manual injection for demonstration)
    # ------------------------------------------------------------------

    def simulate_event(self, template_index: int = -1) -> dict:
        """
        Inject a synthetic event from the SYNTHETIC_EVENTS pool.

        If template_index is -1 (default), a random template is selected.
        Returns the injected event dict for the caller to process.
        """
        import random

        if template_index < 0 or template_index >= len(SYNTHETIC_EVENTS):
            template_index = random.randint(0, len(SYNTHETIC_EVENTS) - 1)

        template = SYNTHETIC_EVENTS[template_index]
        now = datetime.now(timezone.utc)
        signal_type = MITRE_TO_SIGNAL.get(template["mitre_technique"])
        event = {
            "id": len(self.evidence) + 1,
            "timestamp": now.isoformat(),
            "step": -1,  # manual events have no scenario step
            "sector": template["sector"],
            "targets": list(template["targets"]),
            "mitre_technique": template["mitre_technique"],
            "mitre_name": template["mitre_name"],
            "description": template["description"],
            "signal_strength": template["signal_strength"],
            "signal_type": signal_type.value if signal_type else None,
        }
        self.ingest_event(event)
        return event

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

    def reset(self):
        """Clear all evidence and alerts."""
        self.evidence.clear()
        self.alerts.clear()
        self._next_evidence_id = 1
        self._next_alert_id = 1
    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def status(self) -> dict:
        score = self.threat_score()
        signal_types = list(set(
            ev.signal_type.value
            for ev in self.evidence
            if ev.signal_type is not None
        ))
        return {
            "threat_score": round(score, 3),
            "confidence_pct": round(score * 100, 1),
            "severity": self.current_severity().value,
            "risk_level": self.risk_level().value,
            "threat_level": self.threat_level().value,
            "decay_lambda": DECAY_LAMBDA,
            "total_evidence": len(self.evidence),
            "active_alerts": len(self.active_alerts),
            "signal_types_active": signal_types,
            "evidence_chain": self.evidence_chain(),
            "alerts": [a.to_dict() for a in self.alerts],
            "mitre_techniques": self.mitre_summary(),
            "sector_heatmap": self.sector_heatmap(),
        }

    def to_dict(self) -> dict:
        return self.status()


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[DetectionEngine] = None


def get_detection_engine() -> DetectionEngine:
    """Return the global DetectionEngine instance (create on first call)."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = DetectionEngine()
    return _engine_instance
