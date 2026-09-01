"""
Digital Twin Engine

Builds and manages the simulated national digital infrastructure.
All sectors, assets, and dependencies are entirely fictional.

This engine is designed to be modified programmatically by later phases
(adversary simulation, detection, deception, defense, etc.).
"""

from typing import Dict, List, Optional

from simulation.models import (
    Asset,
    AssetCriticality,
    AssetStatus,
    Dependency,
    Sector,
)


class DigitalTwin:
    """Manages the full simulated national infrastructure topology."""

    def __init__(self):
        self.sectors: Dict[str, Sector] = {}
        self.dependencies: List[Dependency] = []
        self.attack_paths: List[List[str]] = []  # list of sector_id chains
        self._build_topology()

    # ------------------------------------------------------------------
    # Topology construction
    # ------------------------------------------------------------------

    def _add_sector(self, sector_id: str, name: str, icon: str,
                    description: str, assets: list):
        """Create a sector and attach its assets."""
        sector = Sector(sector_id, name, icon, description)
        for asset_def in assets:
            asset = Asset(
                asset_id=asset_def["id"],
                name=asset_def["name"],
                sector_id=sector_id,
                criticality=AssetCriticality(asset_def.get("criticality", "medium")),
            )
            sector.assets.append(asset)
        self.sectors[sector_id] = sector

    def _build_topology(self):
        """Construct the full simulated national infrastructure."""

        # ---- Military ----
        self._add_sector("military", "Military", "\u2694",
            "National defense command and tactical communication networks.",
            [
                {"id": "mil-cmd-net",   "name": "Command Network",
                 "criticality": "critical"},
                {"id": "mil-def-ops",   "name": "Defense Operations Server",
                 "criticality": "critical"},
                {"id": "mil-intel-srv", "name": "Intelligence Server",
                 "criticality": "high"},
            ])

        # ---- Government ----
        self._add_sector("government", "Government", "\U0001F3DB",
            "Government services, citizen portals, and administrative systems.",
            [
                {"id": "gov-services", "name": "Government Services Server",
                 "criticality": "high"},
                {"id": "gov-citizen",  "name": "Citizen Services Network",
                 "criticality": "medium"},
            ])

        # ---- Telecom ----
        self._add_sector("telecom", "Telecom", "\U0001F4E1",
            "Core telecommunications backbone and gateway infrastructure.",
            [
                {"id": "tel-core",    "name": "Core Network",
                 "criticality": "critical"},
                {"id": "tel-gateway", "name": "Communications Gateway",
                 "criticality": "high"},
            ])

        # ---- Energy ----
        self._add_sector("energy", "Energy", "\u26A1",
            "Power generation, grid management, and distribution control.",
            [
                {"id": "eng-power", "name": "Power Control Center",
                 "criticality": "critical"},
                {"id": "eng-grid",  "name": "Grid Management Server",
                 "criticality": "high"},
            ])

        # ---- Banking & Finance ----
        self._add_sector("banking", "Banking & Finance", "\U0001F3E6",
            "Banking core systems, payment gateways, and financial exchanges.",
            [
                {"id": "bnk-core",    "name": "Banking Core",
                 "criticality": "critical"},
                {"id": "bnk-payment", "name": "Payment Gateway",
                 "criticality": "high"},
            ])

        # ---- Healthcare ----
        self._add_sector("healthcare", "Healthcare", "\U0001F3E5",
            "Hospital networks, medical records, and emergency systems.",
            [
                {"id": "hlt-hospital", "name": "Hospital Network",
                 "criticality": "high"},
                {"id": "hlt-records",  "name": "Medical Records Server",
                 "criticality": "high"},
            ])

        # ---- Education ----
        self._add_sector("education", "Education", "\U0001F393",
            "University networks, research systems, and education services.",
            [
                {"id": "edu-university", "name": "University Network",
                 "criticality": "medium"},
                {"id": "edu-services",   "name": "Education Services Server",
                 "criticality": "low"},
            ])

        # ---- Commercial / Civilian ----
        self._add_sector("commercial", "Commercial / Civilian", "\U0001F3EC",
            "Retail networks, business services, and civilian infrastructure.",
            [
                {"id": "com-retail",  "name": "Retail Network",
                 "criticality": "medium"},
                {"id": "com-business", "name": "Business Services Server",
                 "criticality": "low"},
            ])

        # ---- Dependencies (directed edges) ----
        self.dependencies = [
            Dependency("military", "government", "Command & Policy"),
            Dependency("military", "telecom",    "Secure Comms"),
            Dependency("government", "telecom",  "Admin Comms"),
            Dependency("telecom", "energy",      "Grid Telemetry"),
            Dependency("telecom", "banking",     "Transaction Relay"),
            Dependency("telecom", "healthcare",  "Emergency Comms"),
            Dependency("energy", "banking",      "Power Supply"),
            Dependency("energy", "healthcare",   "Power Supply"),
            Dependency("government", "education", "Research Grants"),
            Dependency("banking", "commercial",  "Financial Services"),
        ]

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_sector(self, sector_id: str) -> Optional[Sector]:
        return self.sectors.get(sector_id)

    def get_asset(self, asset_id: str) -> Optional[Asset]:
        for sector in self.sectors.values():
            for asset in sector.assets:
                if asset.asset_id == asset_id:
                    return asset
        return None

    def outgoing_dependencies(self, sector_id: str) -> List[Dependency]:
        return [d for d in self.dependencies if d.source_id == sector_id]

    def incoming_dependencies(self, sector_id: str) -> List[Dependency]:
        return [d for d in self.dependencies if d.target_id == sector_id]

    def asset_dependencies(self, asset: Asset) -> List[dict]:
        """Return sector-level dependencies relevant to an asset."""
        sector = self.sectors.get(asset.sector_id)
        if not sector:
            return []
        outgoing = [d.to_dict() for d in self.outgoing_dependencies(sector.sector_id)]
        incoming = [d.to_dict() for d in self.incoming_dependencies(sector.sector_id)]
        return outgoing + incoming

    # ------------------------------------------------------------------
    # Aggregate summary
    # ------------------------------------------------------------------

    @property
    def total_sectors(self) -> int:
        return len(self.sectors)

    @property
    def total_assets(self) -> int:
        return sum(s.asset_count for s in self.sectors.values())

    @property
    def total_healthy(self) -> int:
        return sum(s.healthy_count for s in self.sectors.values())

    @property
    def total_warning(self) -> int:
        return sum(s.warning_count for s in self.sectors.values())

    @property
    def total_compromised(self) -> int:
        return sum(s.compromised_count for s in self.sectors.values())

    @property
    def active_attack_paths(self) -> int:
        return len(self.attack_paths)

    def summary(self) -> dict:
        return {
            "total_sectors": self.total_sectors,
            "total_assets": self.total_assets,
            "healthy": self.total_healthy,
            "warning": self.total_warning,
            "compromised": self.total_compromised,
            "attack_paths": self.active_attack_paths,
        }

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize the entire twin for the frontend."""
        return {
            "sectors": {sid: s.to_dict() for sid, s in self.sectors.items()},
            "dependencies": [d.to_dict() for d in self.dependencies],
            "attack_paths": self.attack_paths,
            "summary": self.summary(),
        }

    # ------------------------------------------------------------------
    # State mutation (for later phases)
    # ------------------------------------------------------------------

    def set_asset_status(self, asset_id: str, status: AssetStatus):
        """Change an asset's status and recompute its sector."""
        asset = self.get_asset(asset_id)
        if asset:
            asset.status = status
            sector = self.sectors.get(asset.sector_id)
            if sector:
                sector.recompute_status()

    def set_sector_status(self, sector_id: str, status: AssetStatus):
        """Change all assets in a sector to the given status."""
        sector = self.sectors.get(sector_id)
        if sector:
            for asset in sector.assets:
                asset.status = status
            sector.recompute_status()

    def add_attack_path(self, path: List[str]):
        """Register a simulated attack path (list of sector IDs)."""
        self.attack_paths.append(path)

    def clear_attack_paths(self):
        self.attack_paths.clear()

    def reset_all(self):
        """Reset every asset and sector to healthy."""
        for sector in self.sectors.values():
            for asset in sector.assets:
                asset.status = AssetStatus.HEALTHY
                asset.threat_state = None
                asset.activity.clear()
            sector.recompute_status()
        self.clear_attack_paths()


# ---------------------------------------------------------------------------
# Singleton — one shared instance for the application
# ---------------------------------------------------------------------------

_twin_instance: Optional[DigitalTwin] = None


def get_twin() -> DigitalTwin:
    """Return the global DigitalTwin instance (create on first call)."""
    global _twin_instance
    if _twin_instance is None:
        _twin_instance = DigitalTwin()
    return _twin_instance
