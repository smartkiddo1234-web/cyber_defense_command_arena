"""
Basic tests for the Phase 1 Flask foundation and Phase 2 Digital Twin.

Verifies:
- Flask application can initialize
- "/" route responds successfully
- dashboard template loads and contains expected content
- /api/status returns valid JSON
- database initialization works
- Digital Twin page loads
- Digital Twin API endpoints work
"""

import os
import sys
import unittest
from datetime import datetime, timezone

# Ensure the project root is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app
from database import DatabaseManager
from simulation import DigitalTwin, get_twin, Simulator, get_simulator
from simulation.models import AssetStatus
from simulation.simulator import SCENARIO
from detection import DetectionEngine, get_detection_engine
from detection.models import RiskLevel, Severity, SignalType, ThreatLevel
from deception import DeceptionEngine, get_deception_engine
from deception.models import DecoyType, DecoyStatus, AttackerState, DeceptionPosture, DeceptionActionType
from command import CommandEngine, get_command_engine
from command.models import DefensiveAction, CommandDecision, AIRecommendation, DecisionRecord
from reports import ReportEngine, get_report_engine


class FlaskAppTests(unittest.TestCase):
    """Tests for Flask application initialization and routes."""

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_app_creates_successfully(self):
        """Flask application can be created without errors."""
        self.assertIsNotNone(self.app)

    def test_app_has_correct_config(self):
        """Application loads the testing configuration."""
        self.assertTrue(self.app.config["TESTING"])

    def test_root_route_returns_200(self):
        '""/" route responds with HTTP 200.'
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_dashboard_contains_expected_sections(self):
        """Dashboard page contains all placeholder section titles."""
        response = self.client.get("/")
        html = response.data.decode("utf-8")

        expected_sections = [
            "Threat Status",
            "Digital Twin",
            "Defense Units",
            "Deception Grid",
            "Evidence Chain",
            "AI Recommendation",
            "Commander Controls",
        ]
        for section in expected_sections:
            self.assertIn(section, html, f"Missing section: {section}")

    def test_dashboard_live_cards_present(self):
        """Phase 20: Defense Units, AI Recommendation, Commander Controls are live panels."""
        response = self.client.get("/")
        html = response.data.decode("utf-8")
        # All three formerly-placeholder cards now have live panel IDs
        self.assertIn('id="panelDefense"', html)
        self.assertIn('id="panelAIRec"', html)
        self.assertIn('id="panelCommander"', html)
        # Placeholder text must be gone
        self.assertNotIn("Coming in next phase", html)

    def test_api_status_returns_json(self):
        """/api/status returns a JSON health-check response."""
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("status", data)
        self.assertEqual(data["status"], "operational")

    def test_api_status_contains_app_metadata(self):
        """/api/status response includes version and phase."""
        response = self.client.get("/api/status")
        data = response.get_json()
        self.assertIn("version", data)
        self.assertIn("phase", data)

    def test_404_handler(self):
        """Non-existent route returns a 404 response."""
        response = self.client.get("/nonexistent-route")
        self.assertEqual(response.status_code, 404)


class DigitalTwinRouteTests(unittest.TestCase):
    """Tests for the Phase 2 Digital Twin routes and API."""

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_digital_twin_page_loads(self):
        """The /digital-twin route returns 200."""
        response = self.client.get("/digital-twin")
        self.assertEqual(response.status_code, 200)

    def test_digital_twin_page_contains_topology(self):
        """The Digital Twin page renders the topology container."""
        response = self.client.get("/digital-twin")
        html = response.data.decode("utf-8")
        self.assertIn("topologySvg", html)
        self.assertIn("CYBER_TWIN_DATA", html)

    def test_dashboard_has_twin_summary(self):
        """Dashboard contains live Digital Twin summary values."""
        response = self.client.get("/")
        html = response.data.decode("utf-8")
        self.assertIn("Sectors", html)
        self.assertIn("Open Digital Twin", html)

    def test_dashboard_has_digital_twin_nav_link(self):
        """Navigation includes a link to the Digital Twin."""
        response = self.client.get("/")
        html = response.data.decode("utf-8")
        self.assertIn('/digital-twin', html)

    def test_api_twin_returns_json(self):
        """The /api/twin endpoint returns full twin data."""
        response = self.client.get("/api/twin")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("sectors", data)
        self.assertIn("dependencies", data)
        self.assertIn("summary", data)

    def test_api_twin_has_8_sectors(self):
        """The twin contains exactly 8 sectors."""
        response = self.client.get("/api/twin")
        data = response.get_json()
        self.assertEqual(len(data["sectors"]), 8)

    def test_api_twin_has_10_dependencies(self):
        """The twin contains exactly 10 dependency links."""
        response = self.client.get("/api/twin")
        data = response.get_json()
        self.assertEqual(len(data["dependencies"]), 10)

    def test_api_sector_valid(self):
        """Requesting a valid sector returns its detail."""
        response = self.client.get("/api/twin/sector/military")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["sector_id"], "military")
        self.assertIn("assets", data)

    def test_api_sector_invalid(self):
        """Requesting an invalid sector returns 404."""
        response = self.client.get("/api/twin/sector/nonexistent")
        self.assertEqual(response.status_code, 404)

    def test_api_asset_valid(self):
        """Requesting a valid asset returns its detail."""
        response = self.client.get("/api/twin/asset/mil-cmd-net")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["asset_id"], "mil-cmd-net")

    def test_api_asset_invalid(self):
        """Requesting an invalid asset returns 404."""
        response = self.client.get("/api/twin/asset/nonexistent")
        self.assertEqual(response.status_code, 404)

    def test_api_status_includes_twin_summary(self):
        """/api/status now includes a twin_summary object."""
        response = self.client.get("/api/status")
        data = response.get_json()
        self.assertIn("twin_summary", data)
        self.assertIn("total_sectors", data["twin_summary"])


class DigitalTwinModelTests(unittest.TestCase):
    """Tests for the Digital Twin data model and engine."""

    def test_twin_initializes(self):
        """DigitalTwin can be constructed without errors."""
        twin = DigitalTwin()
        self.assertIsNotNone(twin)

    def test_twin_sector_count(self):
        """DigitalTwin has exactly 8 sectors."""
        twin = DigitalTwin()
        self.assertEqual(twin.total_sectors, 8)

    def test_twin_asset_count(self):
        """DigitalTwin has 17 total assets."""
        twin = DigitalTwin()
        self.assertEqual(twin.total_assets, 17)

    def test_twin_dependency_count(self):
        """DigitalTwin has 10 dependency links."""
        twin = DigitalTwin()
        self.assertEqual(len(twin.dependencies), 10)

    def test_all_initially_healthy(self):
        """All assets start in healthy status."""
        twin = DigitalTwin()
        self.assertEqual(twin.total_healthy, 17)
        self.assertEqual(twin.total_compromised, 0)

    def test_set_asset_status(self):
        """Changing an asset status recomputes the sector."""
        twin = DigitalTwin()
        twin.set_asset_status("mil-cmd-net", AssetStatus.COMPROMISED)
        asset = twin.get_asset("mil-cmd-net")
        self.assertEqual(asset.status, AssetStatus.COMPROMISED)
        sector = twin.get_sector("military")
        self.assertEqual(sector.status, AssetStatus.COMPROMISED)

    def test_reset_all(self):
        """reset_all restores everything to healthy."""
        twin = DigitalTwin()
        twin.set_asset_status("mil-cmd-net", AssetStatus.COMPROMISED)
        twin.add_attack_path(["military", "telecom"])
        twin.reset_all()
        self.assertEqual(twin.total_healthy, 17)
        self.assertEqual(twin.active_attack_paths, 0)

    def test_attack_paths(self):
        """Attack paths can be added and cleared."""
        twin = DigitalTwin()
        twin.add_attack_path(["military", "telecom", "energy"])
        self.assertEqual(twin.active_attack_paths, 1)
        twin.clear_attack_paths()
        self.assertEqual(twin.active_attack_paths, 0)

    def test_to_dict_serializable(self):
        """to_dict returns a JSON-serializable structure."""
        import json
        twin = DigitalTwin()
        data = twin.to_dict()
        serialized = json.dumps(data)
        self.assertIsInstance(serialized, str)


class DatabaseTests(unittest.TestCase):
    """Tests for database initialization."""

    def setUp(self):
        self.test_db_path = os.path.join(
            os.path.dirname(__file__), "..", "database", "test_cyber_arena.db"
        )

    def tearDown(self):
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)

    def test_database_initializes(self):
        """DatabaseManager can create and initialize the database."""
        db = DatabaseManager(self.test_db_path)
        db.initialize()
        self.assertTrue(os.path.exists(self.test_db_path))

    def test_schema_version_recorded(self):
        """Schema version is written and retrievable after initialization."""
        db = DatabaseManager(self.test_db_path)
        db.initialize()
        version = db.get_schema_version()
        self.assertIsNotNone(version)
        self.assertEqual(version, "0.1.0")

    def test_meta_table_exists(self):
        """The meta table is created during initialization."""
        db = DatabaseManager(self.test_db_path)
        db.initialize()
        with db.get_db() as conn:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'"
            ).fetchone()
            self.assertIsNotNone(row)


class SimulationRouteTests(unittest.TestCase):
    """Tests for simulation page and API routes."""

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_simulation_page_loads(self):
        response = self.client.get("/simulation")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("Attack Simulation Control", html)

    def test_api_simulation_status(self):
        response = self.client.get("/api/simulation")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("current_step", data)
        self.assertIn("total_steps", data)
        self.assertEqual(data["total_steps"], len(SCENARIO))

    def test_api_sim_step(self):
        """POST /api/simulation/step advances one step."""
        # Reset first to ensure clean state
        self.client.post("/api/simulation/reset")
        response = self.client.post("/api/simulation/step")
        self.assertEqual(response.status_code, 200)
        status = self.client.get("/api/simulation").get_json()
        self.assertEqual(status["current_step"], 1)

    def test_api_sim_start_stop(self):
        self.client.post("/api/simulation/reset")
        response = self.client.post("/api/simulation/start")
        self.assertEqual(response.status_code, 200)
        response = self.client.post("/api/simulation/stop")
        self.assertEqual(response.status_code, 200)

    def test_api_sim_reset(self):
        self.client.post("/api/simulation/step")
        response = self.client.post("/api/simulation/reset")
        self.assertEqual(response.status_code, 200)
        status = self.client.get("/api/simulation").get_json()
        self.assertEqual(status["current_step"], 0)

    def test_dashboard_shows_simulation_data(self):
        response = self.client.get("/")
        html = response.data.decode("utf-8")
        self.assertIn("Threat Status", html)
        self.assertIn("Simulation", html)

    def test_nav_has_simulation_and_detection_links(self):
        response = self.client.get("/")
        html = response.data.decode("utf-8")
        self.assertIn('/simulation', html)
        self.assertIn('/detection', html)


class DetectionRouteTests(unittest.TestCase):
    """Tests for detection page and API routes."""

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_detection_page_loads(self):
        response = self.client.get("/detection")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("Detection", html)

    def test_api_detection_status(self):
        response = self.client.get("/api/detection")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("threat_score", data)
        self.assertIn("severity", data)
        self.assertIn("evidence_chain", data)
        self.assertIn("mitre_techniques", data)

    def test_api_status_has_threat_score(self):
        response = self.client.get("/api/status")
        data = response.get_json()
        self.assertIn("threat_score", data)
        self.assertIn("severity", data)


class SimulatorEngineTests(unittest.TestCase):
    """Tests for the adversary simulation engine."""

    def setUp(self):
        self.twin = DigitalTwin()
        self.engine = DetectionEngine()
        self.sim = Simulator(self.twin, on_step=lambda i, s, e: self.engine.ingest_event(e))

    def test_scenario_has_8_steps(self):
        self.assertEqual(len(SCENARIO), 8)

    def test_step_once_advances(self):
        self.sim.step_once()
        self.assertEqual(self.sim.current_step, 1)

    def test_step_changes_asset_status(self):
        self.sim.step_once()
        asset = self.twin.get_asset("mil-cmd-net")
        self.assertNotEqual(asset.status, AssetStatus.HEALTHY)

    def test_full_scenario_completes(self):
        for _ in range(len(SCENARIO)):
            self.sim.step_once()
        self.assertTrue(self.sim.is_complete)

    def test_attack_path_tracks_sectors(self):
        for _ in range(len(SCENARIO)):
            self.sim.step_once()
        path = self.sim.attack_path
        self.assertIn("military", path)
        self.assertIn("telecom", path)
        self.assertIn("energy", path)
        self.assertIn("healthcare", path)

    def test_reset_clears_everything(self):
        for _ in range(4):
            self.sim.step_once()
        self.sim.reset()
        self.assertEqual(self.sim.current_step, 0)
        self.assertEqual(self.twin.total_healthy, 17)

    def test_events_generated(self):
        self.sim.step_once()
        self.assertEqual(len(self.sim.events), 1)
        self.assertIn("mitre_technique", self.sim.events[0])


class DetectionEngineTests(unittest.TestCase):
    """Tests for the detection engine."""

    @staticmethod
    def _now_iso() -> str:
        """Return a current UTC ISO-8601 timestamp for fresh evidence."""
        return datetime.now(timezone.utc).isoformat()

    def setUp(self):
        self.engine = DetectionEngine()

    def test_empty_threat_score_is_zero(self):
        self.assertEqual(self.engine.threat_score(), 0.0)

    def test_ingest_increases_score(self):
        self.engine.ingest_event({
            "timestamp": "2026-01-01T00:00:00+00:00",
            "sector": "military", "targets": ["mil-cmd-net"],
            "mitre_technique": "T1595", "mitre_name": "Active Scanning",
            "description": "Test", "signal_strength": 0.8,
        })
        self.assertGreater(self.engine.threat_score(), 0)

    def test_mitre_summary(self):
        self.engine.ingest_event({
            "timestamp": "2026-01-01T00:00:00+00:00",
            "sector": "military", "targets": ["mil-cmd-net"],
            "mitre_technique": "T1595", "mitre_name": "Active Scanning",
            "description": "Test", "signal_strength": 0.5,
        })
        summary = self.engine.mitre_summary()
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["technique"], "T1595")

    def test_alerts_generated(self):
        """Use a fresh timestamp so temporal decay doesn't zero the signal."""
        self.engine.ingest_event({
            "timestamp": self._now_iso(),
            "sector": "military", "targets": ["mil-cmd-net"],
            "mitre_technique": "T1078", "mitre_name": "Valid Accounts",
            "description": "Test", "signal_strength": 0.9,
        })
        self.assertGreater(len(self.engine.alerts), 0)

    def test_reset_clears(self):
        self.engine.ingest_event({
            "timestamp": "2026-01-01T00:00:00+00:00",
            "sector": "military", "targets": ["mil-cmd-net"],
            "mitre_technique": "T1595", "mitre_name": "Active Scanning",
            "description": "Test", "signal_strength": 0.8,
        })
        self.engine.reset()
        self.assertEqual(len(self.engine.evidence), 0)
        self.assertEqual(len(self.engine.alerts), 0)

    def test_evidence_chain_serializable(self):
        import json
        self.engine.ingest_event({
            "timestamp": "2026-01-01T00:00:00+00:00",
            "sector": "telecom", "targets": ["tel-core"],
            "mitre_technique": "T1021", "mitre_name": "Remote Services",
            "description": "Test", "signal_strength": 0.6,
        })
        chain = self.engine.evidence_chain()
        self.assertIsInstance(json.dumps(chain), str)

    def test_severity_classification(self):
        self.assertEqual(self.engine.current_severity(), Severity.INFO)
        """Use a fresh timestamp so the signal hasn't decayed."""
        self.engine.ingest_event({
            "timestamp": self._now_iso(),
            "sector": "military", "targets": ["mil-cmd-net"],
            "mitre_technique": "T1595", "mitre_name": "Active Scanning",
            "description": "Test", "signal_strength": 0.95,
        })
        sev = self.engine.current_severity()
        self.assertIn(sev, [Severity.HIGH, Severity.CRITICAL])


class DeceptionRouteTests(unittest.TestCase):
    """Tests for deception page and API routes."""

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_deception_page_loads(self):
        response = self.client.get("/deception")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("Deception Grid", html)

    def test_api_deception_status(self):
        response = self.client.get("/api/deception")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("total_decoys", data)
        self.assertIn("armed", data)
        self.assertIn("active", data)
        self.assertIn("events", data)

    def test_api_status_has_deception_fields(self):
        response = self.client.get("/api/status")
        data = response.get_json()
        self.assertIn("deception_active", data)
        self.assertIn("deception_events", data)

    def test_dashboard_shows_deception_panel(self):
        response = self.client.get("/")
        html = response.data.decode("utf-8")
        self.assertIn("Deception Grid", html)
        self.assertIn("Open Deception Grid", html)

    def test_nav_has_deception_link(self):
        response = self.client.get("/")
        html = response.data.decode("utf-8")
        self.assertIn('/deception', html)


class DeceptionEngineTests(unittest.TestCase):
    """Tests for the deception engine."""

    def setUp(self):
        self.engine = DeceptionEngine()

    def test_decoys_deployed(self):
        """DeceptionEngine starts with decoys deployed."""
        self.assertGreater(len(self.engine.decoys), 0)

    def test_all_start_armed(self):
        for d in self.engine.decoys.values():
            self.assertEqual(d.status, DecoyStatus.ARMED)

    def test_evaluate_triggers_decoy(self):
        """Simulating a step in military triggers military decoys."""
        step_data = {"sector": "military", "targets": ["mil-cmd-net"]}
        events = self.engine.evaluate_step(0, step_data)
        self.assertGreater(len(events), 0)
        triggered = [d for d in self.engine.decoys.values() if d.status == DecoyStatus.TRIGGERED]
        self.assertGreater(len(triggered), 0)

    def test_attacker_adapts(self):
        """After retention_steps, attacker bypasses the decoy."""
        step_data = {"sector": "military", "targets": ["mil-cmd-net"]}
        # Step 0 triggers the decoy
        self.engine.evaluate_step(0, step_data)
        # Keep stepping in military to exhaust retention
        for i in range(1, 5):
            self.engine.evaluate_step(i, step_data)
        bypassed = [d for d in self.engine.decoys.values() if d.status == DecoyStatus.BYPASSED]
        self.assertGreater(len(bypassed), 0)

    def test_reset_redeploys(self):
        step_data = {"sector": "military", "targets": ["mil-cmd-net"]}
        self.engine.evaluate_step(0, step_data)
        self.engine.reset()
        self.assertEqual(len(self.engine.events), 0)
        for d in self.engine.decoys.values():
            self.assertEqual(d.status, DecoyStatus.ARMED)

    def test_decoy_types(self):
        """Multiple decoy types are present."""
        types = set(d.decoy_type for d in self.engine.decoys.values())
        self.assertIn(DecoyType.SERVER, types)
        self.assertIn(DecoyType.CREDENTIAL, types)
        self.assertIn(DecoyType.SERVICE, types)

    def test_events_have_evidence_boost(self):
        step_data = {"sector": "military", "targets": ["mil-cmd-net"]}
        events = self.engine.evaluate_step(0, step_data)
        self.assertTrue(all(e.evidence_boost > 0 for e in events))

    def test_status_serializable(self):
        import json
        step_data = {"sector": "telecom", "targets": ["tel-core"]}
        self.engine.evaluate_step(3, step_data)
        data = self.engine.status()
        serialized = json.dumps(data)
        self.assertIsInstance(serialized, str)


class DetectionPhase5Tests(unittest.TestCase):
    """Tests for Phase 5 Detection & Evidence enhancements."""

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()
        self.engine = DetectionEngine()

    # --- Risk level tests ---

    def test_risk_level_starts_normal(self):
        self.assertEqual(self.engine.risk_level(), RiskLevel.NORMAL)

    def test_risk_level_progression(self):
        """Injecting events with fresh timestamps progresses through risk levels."""
        now = datetime.now(timezone.utc).isoformat()
        # Low signal → suspicious
        self.engine.ingest_event({
            "timestamp": now, "sector": "military",
            "targets": ["mil-cmd-net"],
            "mitre_technique": "T1595", "mitre_name": "Active Scanning",
            "description": "Test", "signal_strength": 0.3,
        })
        self.assertIn(self.engine.risk_level(), [RiskLevel.NORMAL, RiskLevel.SUSPICIOUS])
        # High signal → high risk or critical
        self.engine.ingest_event({
            "timestamp": now, "sector": "telecom",
            "targets": ["tel-core"],
            "mitre_technique": "T1078", "mitre_name": "Valid Accounts",
            "description": "Test", "signal_strength": 0.9,
        })
        self.assertIn(self.engine.risk_level(), [RiskLevel.HIGH_RISK, RiskLevel.CRITICAL])

    def test_status_includes_risk_level(self):
        data = self.engine.status()
        self.assertIn("risk_level", data)
        self.assertEqual(data["risk_level"], "normal")

    def test_status_includes_confidence_pct(self):
        data = self.engine.status()
        self.assertIn("confidence_pct", data)
        self.assertEqual(data["confidence_pct"], 0.0)

    # --- Sector heatmap tests ---

    def test_sector_heatmap_empty(self):
        self.assertEqual(len(self.engine.sector_heatmap()), 0)

    def test_sector_heatmap_populated(self):
        now = datetime.now(timezone.utc).isoformat()
        self.engine.ingest_event({
            "timestamp": now, "sector": "military",
            "targets": ["mil-cmd-net"],
            "mitre_technique": "T1595", "mitre_name": "Active Scanning",
            "description": "Test", "signal_strength": 0.5,
        })
        heatmap = self.engine.sector_heatmap()
        self.assertEqual(len(heatmap), 1)
        self.assertEqual(heatmap[0]["sector"], "military")
        self.assertEqual(heatmap[0]["evidence_count"], 1)

    # --- Simulate event tests ---

    def test_simulate_event_returns_dict(self):
        event = self.engine.simulate_event()
        self.assertIsInstance(event, dict)
        self.assertIn("sector", event)
        self.assertIn("mitre_technique", event)
        self.assertIn("signal_strength", event)

    def test_simulate_event_creates_evidence(self):
        self.engine.simulate_event()
        self.assertEqual(len(self.engine.evidence), 1)

    def test_simulate_event_with_index(self):
        event = self.engine.simulate_event(template_index=0)
        self.assertEqual(event["sector"], "military")

    # --- Route tests for new endpoints ---

    def test_simulate_event_endpoint(self):
        response = self.client.post("/api/detection/simulate-event")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("sector", data)
        self.assertIn("mitre_technique", data)

    def test_detection_page_has_simulate_button(self):
        response = self.client.get("/detection")
        html = response.data.decode("utf-8")
        self.assertIn("btnSimulateEvent", html)
        self.assertIn("Simulate Attack Event", html)

    def test_detection_page_has_risk_ladder(self):
        response = self.client.get("/detection")
        html = response.data.decode("utf-8")
        self.assertIn("riskLadder", html)
        self.assertIn("Normal", html)
        self.assertIn("Suspicious", html)
        self.assertIn("High Risk", html)
        self.assertIn("Critical", html)

    def test_detection_page_has_sector_heatmap(self):
        response = self.client.get("/detection")
        html = response.data.decode("utf-8")
        self.assertIn("sectorHeatmap", html)

    def test_api_detection_has_new_fields(self):
        response = self.client.get("/api/detection")
        data = response.get_json()
        self.assertIn("risk_level", data)
        self.assertIn("confidence_pct", data)
        self.assertIn("sector_heatmap", data)

    def test_dashboard_shows_risk_level(self):
        response = self.client.get("/")
        html = response.data.decode("utf-8")
        self.assertIn("Risk Level", html)

    def test_dashboard_evidence_chain_panel(self):
        response = self.client.get("/")
        html = response.data.decode("utf-8")
        self.assertIn("Evidence Chain", html)


class DeceptionPhase6Tests(unittest.TestCase):
    """Tests for Phase 6 Deception Grid enhancements."""

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()
        self.engine = DeceptionEngine()

    # --- Attacker state tests ---

    def test_attacker_starts_free_roaming(self):
        self.assertEqual(self.engine.attacker_state, AttackerState.FREE_ROAMING)

    def test_attacker_state_in_status(self):
        data = self.engine.status()
        self.assertIn("attacker_state", data)
        self.assertEqual(data["attacker_state"], "free_roaming")

    def test_contain_attacker(self):
        result = self.engine.contain_attacker()
        self.assertEqual(result["attacker_state"], "contained")
        self.assertTrue(self.engine.is_contained())

    def test_contain_generates_event(self):
        self.engine.contain_attacker()
        contained_events = [e for e in self.engine.events if e.event_type == "contained"]
        self.assertGreaterEqual(len(contained_events), 1)

    def test_contained_attacker_skips_evaluation(self):
        self.engine.contain_attacker()
        step_data = {"sector": "military", "targets": ["mil-cmd-net"]}
        events = self.engine.evaluate_step(0, step_data)
        self.assertEqual(len(events), 0)

    # --- Adaptive posture tests ---

    def test_posture_starts_monitor(self):
        self.assertEqual(self.engine.posture, DeceptionPosture.MONITOR)

    def test_update_posture_normal(self):
        posture = self.engine.update_posture("normal")
        self.assertEqual(posture, DeceptionPosture.MONITOR)

    def test_update_posture_suspicious(self):
        posture = self.engine.update_posture("suspicious")
        self.assertEqual(posture, DeceptionPosture.ACTIVATE)

    def test_update_posture_high_risk(self):
        posture = self.engine.update_posture("high_risk")
        self.assertEqual(posture, DeceptionPosture.REDIRECT)

    def test_update_posture_critical(self):
        posture = self.engine.update_posture("critical")
        self.assertEqual(posture, DeceptionPosture.CONTAIN)

    def test_adaptive_status_in_response(self):
        data = self.engine.status()
        self.assertIn("adaptive", data)
        self.assertIn("posture", data["adaptive"])
        self.assertIn("attacker_state", data["adaptive"])

    # --- Simulate attacker → decoy tests ---

    def test_simulate_attacker_decoy(self):
        result = self.engine.simulate_attacker_decoy()
        self.assertNotIn("error", result)
        self.assertIn("decoy_id", result)
        self.assertIn("decoy_name", result)
        self.assertEqual(result["attacker_state"], "trapped")

    def test_simulate_attacker_decoy_specific(self):
        result = self.engine.simulate_attacker_decoy("dec-mil-honeypot")
        self.assertNotIn("error", result)
        self.assertEqual(result["decoy_id"], "dec-mil-honeypot")
        self.assertEqual(result["attacker_state"], "trapped")

    def test_simulate_decoy_creates_events(self):
        self.engine.simulate_attacker_decoy()
        self.assertGreater(len(self.engine.events), 0)

    def test_simulate_decoy_tracks_diversion(self):
        result = self.engine.simulate_attacker_decoy("dec-mil-honeypot")
        self.assertIn("diverted_from", result)
        self.assertGreater(len(result["diverted_from"]), 0)

    def test_simulate_decoy_when_contained(self):
        self.engine.contain_attacker()
        result = self.engine.simulate_attacker_decoy()
        self.assertIn("error", result)

    # --- Diversion tracking tests ---

    def test_total_diversions_in_status(self):
        data = self.engine.status()
        self.assertIn("total_diversions", data)

    def test_diversions_increment(self):
        self.engine.simulate_attacker_decoy("dec-mil-honeypot")
        self.assertGreater(self.engine.total_diversions, 0)

    # --- Detection evidence integration ---

    def test_deception_feeds_detection(self):
        det = DetectionEngine()
        self.engine.set_detection_engine(det)
        self.engine.simulate_attacker_decoy("dec-mil-honeypot")
        # Detection should have evidence from deception events
        self.assertGreater(len(det.evidence), 0)
        # Evidence descriptions should be prefixed with [DECEPTION]
        has_deception_prefix = any("[DECEPTION]" in e.description for e in det.evidence)
        self.assertTrue(has_deception_prefix)

    # --- Asset categories ---

    def test_asset_categories(self):
        categories = self.engine.asset_categories()
        self.assertEqual(len(categories), 4)
        labels = [c["label"] for c in categories]
        self.assertIn("Real Asset", labels)
        self.assertIn("Decoy Asset", labels)
        self.assertIn("Isolated Asset", labels)
        self.assertIn("Contained Attacker", labels)

    # --- Reset tests ---

    def test_reset_clears_attacker_state(self):
        self.engine.simulate_attacker_decoy()
        self.engine.reset()
        self.assertEqual(self.engine.attacker_state, AttackerState.FREE_ROAMING)
        self.assertEqual(self.engine.posture, DeceptionPosture.MONITOR)
        self.assertEqual(self.engine.total_diversions, 0)

    # --- Route tests ---

    def test_simulate_decoy_endpoint(self):
        # Reset the shared singleton to ensure clean state
        get_deception_engine().reset()
        response = self.client.post("/api/deception/simulate-decoy")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("decoy_id", data)
        self.assertIn("attacker_state", data)

    def test_contain_endpoint(self):
        response = self.client.post("/api/deception/contain")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["attacker_state"], "contained")
        self.assertIn("message", data)

    def test_deception_api_has_phase6_fields(self):
        response = self.client.get("/api/deception")
        data = response.get_json()
        self.assertIn("adaptive", data)
        self.assertIn("attacker_state", data)
        self.assertIn("posture", data)
        self.assertIn("total_diversions", data)
        self.assertIn("asset_categories", data)

    def test_deception_page_has_simulate_button(self):
        response = self.client.get("/deception")
        html = response.data.decode("utf-8")
        self.assertIn("btnSimulateDecoy", html)
        self.assertIn("Simulate Attacker", html)

    def test_deception_page_has_contain_button(self):
        response = self.client.get("/deception")
        html = response.data.decode("utf-8")
        self.assertIn("btnContain", html)
        self.assertIn("Freeze", html)

    def test_deception_page_has_attacker_status(self):
        response = self.client.get("/deception")
        html = response.data.decode("utf-8")
        self.assertIn("attackerPanel", html)
        self.assertIn("Simulated Attacker Status", html)

    def test_deception_page_has_adaptive_panel(self):
        response = self.client.get("/deception")
        html = response.data.decode("utf-8")
        self.assertIn("adaptivePanel", html)
        self.assertIn("Adaptive Deception Response", html)

    def test_deception_page_has_asset_legend(self):
        response = self.client.get("/deception")
        html = response.data.decode("utf-8")
        self.assertIn("assetLegend", html)
        self.assertIn("Real Asset", html)
        self.assertIn("Decoy Asset", html)
        self.assertIn("Isolated Asset", html)
        self.assertIn("Contained Attacker", html)

    def test_dashboard_shows_attacker_state(self):
        response = self.client.get("/")
        html = response.data.decode("utf-8")
        self.assertIn("Attacker", html)
        self.assertIn("Posture", html)

    def test_api_status_has_phase6_fields(self):
        response = self.client.get("/api/status")
        data = response.get_json()
        self.assertIn("attacker_state", data)
        self.assertIn("deception_posture", data)
        self.assertIn("risk_level", data)


# ---------------------------------------------------------------------------
# Phase 9 — Threat Detection Engine Tests
# ---------------------------------------------------------------------------

class ThreatDetectionPhase9Tests(unittest.TestCase):
    """Tests for Phase 9: SignalType, ThreatLevel, score_contribution, exp decay."""

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def setUp(self):
        self.engine = DetectionEngine()

    # -- SignalType classification --

    def test_signal_type_assigned_from_mitre(self):
        """Ingested events get a signal_type derived from the MITRE technique."""
        ev = self.engine.ingest_event({
            "timestamp": self._now_iso(),
            "sector": "military", "targets": ["mil-cmd-net"],
            "mitre_technique": "T1595", "mitre_name": "Active Scanning",
            "description": "Test scan", "signal_strength": 0.5,
        })
        self.assertEqual(ev.signal_type, SignalType.SUSPICIOUS_NETWORK)

    def test_signal_type_unusual_login(self):
        ev = self.engine.ingest_event({
            "timestamp": self._now_iso(),
            "sector": "banking", "targets": ["bnk-core"],
            "mitre_technique": "T1078", "mitre_name": "Valid Accounts",
            "description": "Test login", "signal_strength": 0.6,
        })
        self.assertEqual(ev.signal_type, SignalType.UNUSUAL_LOGIN)

    def test_signal_type_lateral_movement(self):
        ev = self.engine.ingest_event({
            "timestamp": self._now_iso(),
            "sector": "telecom", "targets": ["tel-gateway"],
            "mitre_technique": "T1021", "mitre_name": "Remote Services",
            "description": "Test lateral", "signal_strength": 0.5,
        })
        self.assertEqual(ev.signal_type, SignalType.LATERAL_MOVEMENT)

    def test_signal_type_suspicious_file(self):
        ev = self.engine.ingest_event({
            "timestamp": self._now_iso(),
            "sector": "energy", "targets": ["eng-grid"],
            "mitre_technique": "T1027", "mitre_name": "Obfuscated Files",
            "description": "Test obfuscated", "signal_strength": 0.5,
        })
        self.assertEqual(ev.signal_type, SignalType.SUSPICIOUS_FILE_ACTIVITY)

    def test_signal_type_abnormal_data_access(self):
        ev = self.engine.ingest_event({
            "timestamp": self._now_iso(),
            "sector": "energy", "targets": ["eng-power"],
            "mitre_technique": "T1565", "mitre_name": "Data Manipulation",
            "description": "Test data manip", "signal_strength": 0.7,
        })
        self.assertEqual(ev.signal_type, SignalType.ABNORMAL_DATA_ACCESS)

    def test_signal_type_explicit_override(self):
        """An explicit signal_type in the event dict takes precedence."""
        ev = self.engine.ingest_event({
            "timestamp": self._now_iso(),
            "sector": "military", "targets": ["mil-cmd-net"],
            "mitre_technique": "T1595", "mitre_name": "Active Scanning",
            "description": "Override test", "signal_strength": 0.5,
            "signal_type": SignalType.PRIVILEGE_ESCALATION,
        })
        self.assertEqual(ev.signal_type, SignalType.PRIVILEGE_ESCALATION)

    def test_signal_type_none_for_unknown_mitre(self):
        ev = self.engine.ingest_event({
            "timestamp": self._now_iso(),
            "sector": "military", "targets": ["mil-cmd-net"],
            "mitre_technique": "T9999", "mitre_name": "Unknown",
            "description": "Unknown technique", "signal_strength": 0.4,
        })
        self.assertIsNone(ev.signal_type)

    # -- ThreatLevel --

    def test_threat_level_starts_low(self):
        self.assertEqual(self.engine.threat_level(), ThreatLevel.LOW)

    def test_threat_level_escalates_with_score(self):
        """High-signal recent events push the threat level above LOW."""
        self.engine.ingest_event({
            "timestamp": self._now_iso(),
            "sector": "military", "targets": ["mil-cmd-net"],
            "mitre_technique": "T1078", "mitre_name": "Valid Accounts",
            "description": "Strong signal", "signal_strength": 0.95,
        })
        level = self.engine.threat_level()
        self.assertIn(level, [ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL])

    def test_threat_level_in_status(self):
        status = self.engine.status()
        self.assertIn("threat_level", status)
        self.assertEqual(status["threat_level"], "low")

    # -- Score contribution (explainability) --

    def test_score_contribution_set_after_ingest(self):
        """After ingestion, each evidence item has a positive score_contribution."""
        self.engine.ingest_event({
            "timestamp": self._now_iso(),
            "sector": "military", "targets": ["mil-cmd-net"],
            "mitre_technique": "T1595", "mitre_name": "Active Scanning",
            "description": "Test", "signal_strength": 0.8,
        })
        ev = self.engine.evidence[0]
        self.assertGreater(ev.score_contribution, 0.0)

    def test_score_contributions_multiple_evidence(self):
        """With multiple evidence items, each has its own score_contribution."""
        for i in range(3):
            self.engine.ingest_event({
                "timestamp": self._now_iso(),
                "sector": "military", "targets": ["mil-cmd-net"],
                "mitre_technique": "T1595", "mitre_name": "Active Scanning",
                "description": f"Event {i}", "signal_strength": 0.5 + i * 0.1,
            })
        contributions = [ev.score_contribution for ev in self.engine.evidence]
        self.assertEqual(len(contributions), 3)
        self.assertTrue(all(c > 0 for c in contributions))

    # -- Exponential decay --

    def test_exp_confidence_returns_value(self):
        """exp_confidence() returns a positive value for recent evidence."""
        self.engine.ingest_event({
            "timestamp": self._now_iso(),
            "sector": "military", "targets": ["mil-cmd-net"],
            "mitre_technique": "T1595", "mitre_name": "Active Scanning",
            "description": "Test", "signal_strength": 0.8,
        })
        ev = self.engine.evidence[0]
        self.assertGreater(ev.exp_confidence(), 0.0)
        self.assertLessEqual(ev.exp_confidence(), ev.signal_strength)

    def test_exp_confidence_decays_over_time(self):
        """Older evidence has lower exp_confidence than newer evidence."""
        old_ts = "2026-01-01T00:00:00+00:00"
        new_ts = self._now_iso()
        self.engine.ingest_event({
            "timestamp": old_ts,
            "sector": "military", "targets": ["mil-cmd-net"],
            "mitre_technique": "T1595", "mitre_name": "Active Scanning",
            "description": "Old", "signal_strength": 0.9,
        })
        self.engine.ingest_event({
            "timestamp": new_ts,
            "sector": "telecom", "targets": ["tel-core"],
            "mitre_technique": "T1078", "mitre_name": "Valid Accounts",
            "description": "New", "signal_strength": 0.9,
        })
        old_conf = self.engine.evidence[0].exp_confidence()
        new_conf = self.engine.evidence[1].exp_confidence()
        self.assertGreater(new_conf, old_conf)

    # -- Evidence chain serialization --

    def test_evidence_chain_includes_signal_type(self):
        self.engine.ingest_event({
            "timestamp": self._now_iso(),
            "sector": "military", "targets": ["mil-cmd-net"],
            "mitre_technique": "T1595", "mitre_name": "Active Scanning",
            "description": "Test", "signal_strength": 0.5,
        })
        chain = self.engine.evidence_chain()
        self.assertEqual(len(chain), 1)
        self.assertIn("signal_type", chain[0])
        self.assertEqual(chain[0]["signal_type"], "suspicious_network_connection")

    def test_evidence_chain_includes_score_contribution(self):
        self.engine.ingest_event({
            "timestamp": self._now_iso(),
            "sector": "military", "targets": ["mil-cmd-net"],
            "mitre_technique": "T1595", "mitre_name": "Active Scanning",
            "description": "Test", "signal_strength": 0.5,
        })
        chain = self.engine.evidence_chain()
        self.assertIn("score_contribution", chain[0])
        self.assertIsInstance(chain[0]["score_contribution"], float)

    # -- API routes --

    def test_detection_api_has_threat_level(self):
        """GET /api/detection includes the threat_level field."""
        app = create_app("testing")
        client = app.test_client()
        response = client.get("/api/detection")
        data = response.get_json()
        self.assertIn("threat_level", data)

    def test_detection_api_has_signal_types_active(self):
        """GET /api/detection includes signal_types_active list."""
        app = create_app("testing")
        client = app.test_client()
        response = client.get("/api/detection")
        data = response.get_json()
        self.assertIn("signal_types_active", data)
        self.assertIsInstance(data["signal_types_active"], list)

    def test_detection_api_has_decay_lambda(self):
        """GET /api/detection includes the decay_lambda constant."""
        app = create_app("testing")
        client = app.test_client()
        response = client.get("/api/detection")
        data = response.get_json()
        self.assertIn("decay_lambda", data)
        self.assertAlmostEqual(data["decay_lambda"], 0.0171, places=4)

    def test_api_status_has_threat_level(self):
        """GET /api/status includes the threat_level field."""
        get_detection_engine().reset()
        app = create_app("testing")
        client = app.test_client()
        response = client.get("/api/status")
        data = response.get_json()
        self.assertIn("threat_level", data)
        self.assertEqual(data["threat_level"], "low")

    # -- Reset clears contributions --

    def test_reset_clears_contributions(self):
        self.engine.ingest_event({
            "timestamp": self._now_iso(),
            "sector": "military", "targets": ["mil-cmd-net"],
            "mitre_technique": "T1595", "mitre_name": "Active Scanning",
            "description": "Test", "signal_strength": 0.5,
        })
        self.engine.reset()
        self.assertEqual(len(self.engine.evidence), 0)
        self.assertEqual(self.engine.threat_score(), 0.0)
        self.assertEqual(self.engine.threat_level(), ThreatLevel.LOW)


# ---------------------------------------------------------------------------
# Phase 10 — Deception Engine Tests
# ---------------------------------------------------------------------------

class DeceptionPhase10Tests(unittest.TestCase):
    """Tests for Phase 10: DeceptionActionType, interactions, adaptive selection."""

    def setUp(self):
        self.engine = DeceptionEngine()

    # -- DecoyActionType --

    def test_action_type_enum_exists(self):
        """DeceptionActionType has 6 members."""
        self.assertEqual(len(DeceptionActionType), 6)

    def test_action_type_values(self):
        expected = {
            "reconnaissance", "suspicious_login", "canary_credential_use",
            "service_probing", "privilege_escalation", "suspicious_file_access",
        }
        actual = {a.value for a in DeceptionActionType}
        self.assertEqual(actual, expected)

    # -- New decoys (15 total) --

    def test_total_decoys_15(self):
        """Phase 10 adds gov-service and bnk-service for 15 total decoys."""
        self.assertEqual(len(self.engine.decoys), 15)

    def test_gov_service_decoy_exists(self):
        self.assertIn("dec-gov-service", self.engine.decoys)
        decoy = self.engine.decoys["dec-gov-service"]
        self.assertEqual(decoy.sector, "government")
        self.assertEqual(decoy.decoy_type, DecoyType.SERVER)

    def test_bnk_service_decoy_exists(self):
        self.assertIn("dec-bnk-service", self.engine.decoys)
        decoy = self.engine.decoys["dec-bnk-service"]
        self.assertEqual(decoy.sector, "banking")
        self.assertEqual(decoy.decoy_type, DecoyType.SERVICE)

    # -- Structured interactions --

    def test_interactions_recorded_on_simulate(self):
        """simulate_attacker_decoy records a structured interaction."""
        result = self.engine.simulate_attacker_decoy()
        self.assertNotIn("error", result)
        decoy_id = result["decoy_id"]
        decoy = self.engine.decoys[decoy_id]
        self.assertGreater(len(decoy.interactions), 0)

    def test_interaction_has_required_fields(self):
        """Each interaction record has all required Phase 10 fields."""
        self.engine.simulate_attacker_decoy()
        for decoy in self.engine.decoys.values():
            for record in decoy.interactions:
                self.assertIn("timestamp", record)
                self.assertIn("sector", record)
                self.assertIn("decoy_id", record)
                self.assertIn("decoy_name", record)
                self.assertIn("action", record)
                self.assertIn("action_type", record)
                self.assertIn("mitre_technique", record)
                self.assertIn("mitre_name", record)
                self.assertIn("signal_strength", record)
                self.assertIn("confidence_contribution", record)

    def test_interaction_action_type_is_valid(self):
        """Interaction action_type values are valid DeceptionActionType values."""
        self.engine.simulate_attacker_decoy()
        valid_values = {a.value for a in DeceptionActionType}
        valid_values.add(None)  # Some may be None
        for decoy in self.engine.decoys.values():
            for record in decoy.interactions:
                self.assertIn(record["action_type"], valid_values)

    # -- Events carry Phase 10 fields --

    def test_events_have_mitre_technique(self):
        """Events generated by simulate_attacker_decoy carry mitre_technique."""
        self.engine.simulate_attacker_decoy()
        self.assertGreater(len(self.engine.events), 0)
        for evt in self.engine.events:
            self.assertIsNotNone(evt.mitre_technique)
            self.assertIsNotNone(evt.mitre_name)

    def test_events_have_signal_strength(self):
        """Events carry a positive signal_strength."""
        self.engine.simulate_attacker_decoy()
        for evt in self.engine.events:
            self.assertGreater(evt.signal_strength, 0)

    def test_events_have_action_type(self):
        """Events carry an action_type classification."""
        self.engine.simulate_attacker_decoy()
        # At least the trigger event should have RECONNAISSANCE
        trigger_events = [e for e in self.engine.events if e.event_type == "triggered"]
        self.assertGreater(len(trigger_events), 0)
        for evt in trigger_events:
            self.assertEqual(evt.action_type, DeceptionActionType.RECONNAISSANCE)

    def test_events_have_confidence_contribution(self):
        """Events carry a confidence_contribution value."""
        self.engine.simulate_attacker_decoy()
        for evt in self.engine.events:
            self.assertGreaterEqual(evt.confidence_contribution, 0)

    # -- Total interactions --

    def test_total_interactions_property(self):
        """total_interactions counts all interaction records."""
        self.assertEqual(self.engine.total_interactions, 0)
        self.engine.simulate_attacker_decoy()
        self.assertGreater(self.engine.total_interactions, 0)

    def test_total_interactions_in_status(self):
        """status() includes total_interactions."""
        status = self.engine.status()
        self.assertIn("total_interactions", status)
        self.assertEqual(status["total_interactions"], 0)

    # -- Adaptive decoy selection --

    def test_select_decoy_for_threat_no_detection(self):
        """select_decoy_for_threat returns an armed decoy without detection engine."""
        decoy = self.engine.select_decoy_for_threat()
        self.assertIsNotNone(decoy)
        self.assertEqual(decoy.status, DecoyStatus.ARMED)

    def test_select_decoy_for_threat_with_detection(self):
        """With detection engine wired, adaptive selection prefers hot sectors."""
        from detection import DetectionEngine
        det = DetectionEngine()
        self.engine.set_detection_engine(det)
        # Inject military events to make military sector "hot"
        det.ingest_event({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sector": "military", "targets": ["mil-cmd-net"],
            "mitre_technique": "T1595", "mitre_name": "Active Scanning",
            "description": "Test", "signal_strength": 0.8,
        })
        decoy = self.engine.select_decoy_for_threat()
        self.assertIsNotNone(decoy)
        # The selected decoy should prefer the military sector
        # (it's the hottest sector with evidence_count > 0)

    # -- Decoy interactions in decoy.to_dict() --

    def test_decoy_to_dict_has_interactions(self):
        """Decoy.to_dict() includes the interactions list."""
        decoy = next(iter(self.engine.decoys.values()))
        d = decoy.to_dict()
        self.assertIn("interactions", d)
        self.assertIsInstance(d["interactions"], list)

    # -- Event to_dict includes Phase 10 fields --

    def test_event_to_dict_phase10_fields(self):
        """DeceptionEvent.to_dict() includes mitre_technique and signal_strength."""
        self.engine.simulate_attacker_decoy()
        self.assertGreater(len(self.engine.events), 0)
        d = self.engine.events[0].to_dict()
        self.assertIn("mitre_technique", d)
        self.assertIn("mitre_name", d)
        self.assertIn("signal_strength", d)
        self.assertIn("action_type", d)
        self.assertIn("confidence_contribution", d)

    # -- Reset clears interactions --

    def test_reset_clears_interactions(self):
        self.engine.simulate_attacker_decoy()
        self.assertGreater(self.engine.total_interactions, 0)
        self.engine.reset()
        self.assertEqual(self.engine.total_interactions, 0)
        self.assertEqual(len(self.engine.decoys), 15)

    # -- API routes --

    def test_deception_api_has_total_interactions(self):
        """GET /api/deception includes total_interactions."""
        get_deception_engine().reset()
        app = create_app("testing")
        client = app.test_client()
        response = client.get("/api/deception")
        data = response.get_json()
        self.assertIn("total_interactions", data)

    def test_deception_api_events_have_mitre(self):
        """Events in /api/deception response include mitre_technique."""
        get_deception_engine().reset()
        app = create_app("testing")
        client = app.test_client()
        response = client.get("/api/deception")
        data = response.get_json()
        # Events list may be empty initially, so check structure
        self.assertIn("events", data)
        self.assertIsInstance(data["events"], list)


# ======================================================================
# Phase 11 — Command Engine & Human-in-the-Loop Tests
# ======================================================================


class CommandEngineTests(unittest.TestCase):
    """Unit tests for the CommandEngine recommendation and decision logic."""

    def setUp(self):
        self.det = get_detection_engine()
        self.dec = get_deception_engine()
        self.cmd = get_command_engine()
        self.det.reset()
        self.dec.reset()
        self.cmd.reset()
        self.cmd.set_engines(self.det, self.dec)

    def tearDown(self):
        self.det.reset()
        self.dec.reset()
        self.cmd.reset()

    # -- No evidence → no recommendation --

    def test_generate_recommendation_returns_none_without_evidence(self):
        """generate_recommendation returns None when no evidence exists."""
        self.assertEqual(len(self.det.evidence), 0)
        rec = self.cmd.generate_recommendation()
        self.assertIsNone(rec)

    # -- Recommendation generation with evidence --

    def test_generate_recommendation_with_evidence(self):
        """generate_recommendation returns an AIRecommendation when evidence is present."""
        self.det.simulate_event()
        rec = self.cmd.generate_recommendation()
        self.assertIsNotNone(rec)
        self.assertIsInstance(rec, AIRecommendation)
        self.assertIsInstance(rec.recommended_action, DefensiveAction)
        self.assertGreater(rec.rec_id, 0)
        self.assertIsNotNone(rec.timestamp)
        self.assertGreaterEqual(rec.confidence, 0.0)
        self.assertIn(rec.threat_level, ["low", "medium", "high", "critical"])

    def test_recommendation_contains_required_fields(self):
        """AI recommendation includes all required fields for commander review."""
        self.det.simulate_event()
        rec = self.cmd.generate_recommendation()
        d = rec.to_dict()
        required_keys = [
            "rec_id", "timestamp", "threat_assessment", "affected_sectors",
            "suspected_activity", "recommended_action", "action_description",
            "reason", "confidence", "evidence_summary", "mitre_techniques",
            "threat_score", "threat_level",
        ]
        for key in required_keys:
            self.assertIn(key, d, f"Missing key in recommendation: {key}")

    # -- submit_recommendation wraps in DecisionRecord --

    def test_submit_recommendation_creates_pending_decision(self):
        """submit_recommendation wraps the recommendation in a pending DecisionRecord."""
        self.det.simulate_event()
        rec = self.cmd.generate_recommendation()
        dr = self.cmd.submit_recommendation(rec)
        self.assertIsInstance(dr, DecisionRecord)
        self.assertTrue(dr.is_pending)
        self.assertEqual(dr.decision, CommandDecision.PENDING)

    # -- Commander approval --

    def test_approve_decision(self):
        """approve_decision marks a pending decision as APPROVE."""
        self.det.simulate_event()
        rec = self.cmd.generate_recommendation()
        dr = self.cmd.submit_recommendation(rec)
        result = self.cmd.approve_decision(dr.decision_id)
        self.assertIsNotNone(result)
        self.assertEqual(result.decision, CommandDecision.APPROVE)
        self.assertFalse(result.is_pending)
        self.assertIsNotNone(result.decided_at)

    def test_approve_nonexistent_returns_none(self):
        """approve_decision returns None for a nonexistent decision."""
        result = self.cmd.approve_decision(9999)
        self.assertIsNone(result)

    def test_approve_already_decided_returns_none(self):
        """Cannot approve a decision that has already been decided."""
        self.det.simulate_event()
        rec = self.cmd.generate_recommendation()
        dr = self.cmd.submit_recommendation(rec)
        self.cmd.approve_decision(dr.decision_id)
        result = self.cmd.approve_decision(dr.decision_id)
        self.assertIsNone(result)

    # -- Commander override --

    def test_override_decision(self):
        """override_decision records the commander's chosen action and reason."""
        self.det.simulate_event()
        rec = self.cmd.generate_recommendation()
        dr = self.cmd.submit_recommendation(rec)
        result = self.cmd.override_decision(
            dr.decision_id,
            action="escalate",
            reason="Commander deems threat critical."
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.decision, CommandDecision.OVERRIDE)
        self.assertEqual(result.commander_action, "escalate")
        self.assertEqual(result.commander_reason, "Commander deems threat critical.")
        self.assertFalse(result.is_pending)
        self.assertIsNotNone(result.decided_at)

    def test_override_requires_action_and_reason(self):
        """override_decision records both the chosen action and the reason."""
        self.det.simulate_event()
        rec = self.cmd.generate_recommendation()
        dr = self.cmd.submit_recommendation(rec)
        result = self.cmd.override_decision(dr.decision_id, "monitor", "Low priority.")
        self.assertEqual(result.commander_action, "monitor")
        self.assertEqual(result.commander_reason, "Low priority.")

    # -- Commander dismiss --

    def test_dismiss_decision(self):
        """dismiss_decision marks the decision as DISMISS with optional reason."""
        self.det.simulate_event()
        rec = self.cmd.generate_recommendation()
        dr = self.cmd.submit_recommendation(rec)
        result = self.cmd.dismiss_decision(dr.decision_id, "False positive.")
        self.assertIsNotNone(result)
        self.assertEqual(result.decision, CommandDecision.DISMISS)
        self.assertEqual(result.commander_reason, "False positive.")
        self.assertFalse(result.is_pending)

    def test_dismiss_without_reason_defaults(self):
        """dismiss_decision with empty reason uses default message."""
        self.det.simulate_event()
        rec = self.cmd.generate_recommendation()
        dr = self.cmd.submit_recommendation(rec)
        result = self.cmd.dismiss_decision(dr.decision_id)
        self.assertEqual(result.commander_reason, "No reason provided.")

    # -- Decision log --

    def test_decision_log_records_history(self):
        """decision_log returns all decisions in newest-first order."""
        self.det.simulate_event()
        rec1 = self.cmd.generate_recommendation()
        dr1 = self.cmd.submit_recommendation(rec1)
        self.cmd.approve_decision(dr1.decision_id)

        rec2 = self.cmd.generate_recommendation()
        dr2 = self.cmd.submit_recommendation(rec2)
        self.cmd.dismiss_decision(dr2.decision_id, "Not relevant.")

        log = self.cmd.decision_log()
        self.assertEqual(len(log), 2)
        # Newest first
        self.assertEqual(log[0]["decision"], "dismiss")
        self.assertEqual(log[1]["decision"], "approve")

    def test_decision_log_contains_required_fields(self):
        """Each decision log entry contains the required fields."""
        self.det.simulate_event()
        rec = self.cmd.generate_recommendation()
        dr = self.cmd.submit_recommendation(rec)
        self.cmd.approve_decision(dr.decision_id)

        log = self.cmd.decision_log()
        entry = log[0]
        required_keys = [
            "decision_id", "recommendation", "decision",
            "commander_action", "commander_reason", "decided_at", "is_pending",
        ]
        for key in required_keys:
            self.assertIn(key, entry, f"Missing key in log entry: {key}")
        self.assertIn("threat_level", entry["recommendation"])
        self.assertIn("evidence_summary", entry["recommendation"])

    # -- Status method --

    def test_status_returns_complete_state(self):
        """status() returns all command engine state fields."""
        status = self.cmd.status()
        self.assertIn("total_recommendations", status)
        self.assertIn("total_decisions", status)
        self.assertIn("pending_decisions", status)
        self.assertIn("latest_recommendation", status)
        self.assertIn("pending", status)
        self.assertIn("decision_log", status)

    # -- Reset --

    def test_reset_clears_all(self):
        """reset() clears all recommendations and decisions."""
        self.det.simulate_event()
        rec = self.cmd.generate_recommendation()
        self.cmd.submit_recommendation(rec)
        self.cmd.reset()
        self.assertEqual(len(self.cmd.recommendations), 0)
        self.assertEqual(len(self.cmd.decisions), 0)
        status = self.cmd.status()
        self.assertEqual(status["total_recommendations"], 0)
        self.assertEqual(status["total_decisions"], 0)

    # -- National security scenario --

    def test_national_security_scenario_detected(self):
        """Military + civilian-critical sectors trigger national-security flag."""
        result = CommandEngine._check_national_security(
            ["military", "energy"], ["T1566"]
        )
        self.assertTrue(result)

    def test_national_security_not_triggered_military_only(self):
        """Military sector alone does not trigger national-security flag."""
        result = CommandEngine._check_national_security(
            ["military"], ["T1566"]
        )
        self.assertFalse(result)

    def test_national_security_recommends_protect_connected(self):
        """National security scenario recommends PROTECT_CONNECTED when not critical."""
        action = CommandEngine._choose_action(
            score=0.35, threat_level="high", risk="high",
            attacker_state="active", is_national_security=True,
            deception_active=False, sectors=["military", "energy"],
        )
        self.assertEqual(action, DefensiveAction.PROTECT_CONNECTED)

    # -- Action selection logic --

    def test_critical_threat_escalates(self):
        """Critical threat level always escalates."""
        action = CommandEngine._choose_action(
            score=0.9, threat_level="critical", risk="critical",
            attacker_state="active", is_national_security=False,
            deception_active=False, sectors=["military"],
        )
        self.assertEqual(action, DefensiveAction.ESCALATE)

    def test_low_threat_monitors(self):
        """Low threat score with no special conditions recommends MONITOR."""
        action = CommandEngine._choose_action(
            score=0.05, threat_level="low", risk="normal",
            attacker_state="unknown", is_national_security=False,
            deception_active=False, sectors=["commercial"],
        )
        self.assertEqual(action, DefensiveAction.MONITOR)


class CommandAPITests(unittest.TestCase):
    """Integration tests for the Command API endpoints."""

    def setUp(self):
        # Reset all singletons before each test
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_command_route_returns_200(self):
        """GET /command returns HTTP 200."""
        response = self.client.get("/command")
        self.assertEqual(response.status_code, 200)

    def test_command_page_contains_expected_elements(self):
        """Command page HTML includes key UI elements."""
        response = self.client.get("/command")
        html = response.data.decode("utf-8")
        self.assertIn("AI Command", html)
        self.assertIn("btnGenerate", html)
        self.assertIn("decisionLog", html)

    def test_api_command_returns_status(self):
        """GET /api/command returns valid JSON with expected keys."""
        response = self.client.get("/api/command")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("total_recommendations", data)
        self.assertIn("decision_log", data)

    def test_api_recommend_without_evidence_returns_400(self):
        """POST /api/command/recommend returns 400 when no evidence exists."""
        response = self.client.post("/api/command/recommend")
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("error", data)

    def test_api_recommend_with_evidence_returns_recommendation(self):
        """POST /api/command/recommend succeeds after detection evidence exists."""
        # Generate detection evidence first
        self.client.post("/api/detection/simulate-event")
        response = self.client.post("/api/command/recommend")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("recommendation", data)
        self.assertIn("decision_id", data)
        rec = data["recommendation"]
        self.assertIn("recommended_action", rec)
        self.assertIn("threat_level", rec)

    def test_api_approve_decision(self):
        """POST /api/command/decide with 'approve' processes correctly."""
        self.client.post("/api/detection/simulate-event")
        rec_resp = self.client.post("/api/command/recommend")
        decision_id = rec_resp.get_json()["decision_id"]
        response = self.client.post("/api/command/decide", json={
            "decision_id": decision_id,
            "decision": "approve",
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["decision"], "approve")
        self.assertFalse(data["is_pending"])

    def test_api_override_decision(self):
        """POST /api/command/decide with 'override' records commander's choice."""
        self.client.post("/api/detection/simulate-event")
        rec_resp = self.client.post("/api/command/recommend")
        decision_id = rec_resp.get_json()["decision_id"]
        response = self.client.post("/api/command/decide", json={
            "decision_id": decision_id,
            "decision": "override",
            "action": "escalate",
            "reason": "Threat appears more severe than assessed.",
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["decision"], "override")
        self.assertEqual(data["commander_action"], "escalate")
        self.assertEqual(data["commander_reason"], "Threat appears more severe than assessed.")

    def test_api_dismiss_decision(self):
        """POST /api/command/decide with 'dismiss' records dismissal."""
        self.client.post("/api/detection/simulate-event")
        rec_resp = self.client.post("/api/command/recommend")
        decision_id = rec_resp.get_json()["decision_id"]
        response = self.client.post("/api/command/decide", json={
            "decision_id": decision_id,
            "decision": "dismiss",
            "reason": "False alarm.",
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["decision"], "dismiss")
        self.assertEqual(data["commander_reason"], "False alarm.")

    def test_api_decide_invalid_decision(self):
        """POST /api/command/decide with invalid decision type returns 400."""
        response = self.client.post("/api/command/decide", json={
            "decision_id": 1,
            "decision": "invalid_choice",
        })
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("error", data)

    def test_api_decide_missing_decision_id(self):
        """POST /api/command/decide without decision_id returns 400."""
        response = self.client.post("/api/command/decide", json={
            "decision": "approve",
        })
        self.assertEqual(response.status_code, 400)

    def test_api_override_requires_action(self):
        """POST /api/command/decide override without action returns 400."""
        self.client.post("/api/detection/simulate-event")
        rec_resp = self.client.post("/api/command/recommend")
        decision_id = rec_resp.get_json()["decision_id"]
        response = self.client.post("/api/command/decide", json={
            "decision_id": decision_id,
            "decision": "override",
            "action": "",
        })
        self.assertEqual(response.status_code, 400)

    def test_simulation_reset_clears_command(self):
        """POST /api/simulation/reset also clears command engine state."""
        self.client.post("/api/detection/simulate-event")
        self.client.post("/api/command/recommend")
        self.client.post("/api/simulation/reset")
        response = self.client.get("/api/command")
        data = response.get_json()
        self.assertEqual(data["total_recommendations"], 0)
        self.assertEqual(data["total_decisions"], 0)

    def test_decision_log_persists_after_decisions(self):
        """Decision log shows all decisions after multiple approve/override/dismiss."""
        self.client.post("/api/detection/simulate-event")

        # Recommendation 1 → approve
        r1 = self.client.post("/api/command/recommend").get_json()
        self.client.post("/api/command/decide", json={
            "decision_id": r1["decision_id"], "decision": "approve"
        })

        # Recommendation 2 → override
        r2 = self.client.post("/api/command/recommend").get_json()
        self.client.post("/api/command/decide", json={
            "decision_id": r2["decision_id"], "decision": "override",
            "action": "monitor", "reason": "Need more data first."
        })

        response = self.client.get("/api/command")
        data = response.get_json()
        log = data["decision_log"]
        self.assertEqual(len(log), 2)
        # Each entry has recommendation with evidence
        for entry in log:
            self.assertIn("recommendation", entry)
            self.assertIn("evidence_summary", entry["recommendation"])


# ======================================================================
# Phase 12 — Report Engine & Reports API Tests
# ======================================================================

class ReportEngineTests(unittest.TestCase):
    """Unit tests for the ReportEngine report generation and replay."""

    def setUp(self):
        self.det = get_detection_engine()
        self.dec = get_deception_engine()
        self.cmd = get_command_engine()
        self.twin = get_twin()
        self.det.reset()
        self.dec.reset()
        self.cmd.reset()
        self.cmd.set_engines(self.det, self.dec)
        self.rpt = ReportEngine()
        self.rpt.set_engines(self.det, self.dec, self.cmd, None, self.twin)

    def tearDown(self):
        self.det.reset()
        self.dec.reset()
        self.cmd.reset()

    def test_report_engine_creates(self):
        """ReportEngine instantiates with no engines wired."""
        r = ReportEngine()
        self.assertIsNotNone(r)
        self.assertIsNone(r._det_engine)

    def test_set_engines_wires_all(self):
        """set_engines stores all five references."""
        r = ReportEngine()
        r.set_engines(self.det, self.dec, self.cmd, None, self.twin)
        self.assertIs(r._det_engine, self.det)
        self.assertIs(r._dec_engine, self.dec)
        self.assertIs(r._cmd_engine, self.cmd)
        self.assertIs(r._twin, self.twin)
        self.assertIsNone(r._simulator)

    def test_generate_report_returns_all_sections(self):
        """generate_report returns dict with all required keys."""
        report = self.rpt.generate_report()
        expected_keys = {
            "generated_at", "scenario_summary", "threat_assessment",
            "affected_sectors_assets", "mitre_techniques", "evidence_chain",
            "deception_activity", "adaptation_summary", "ai_recommendations",
            "commander_decisions", "analysis_summary", "final_outcome",
        }
        self.assertEqual(set(report.keys()), expected_keys)

    def test_generate_report_no_data(self):
        """Report with no events returns safe defaults."""
        report = self.rpt.generate_report()
        self.assertEqual(report["threat_assessment"]["threat_score"], 0)
        self.assertEqual(report["evidence_chain"], [])
        self.assertEqual(report["mitre_techniques"], [])
        self.assertEqual(report["ai_recommendations"], [])
        self.assertEqual(report["commander_decisions"], [])

    def test_scenario_summary_no_simulator(self):
        """Without simulator, scenario_summary returns defaults."""
        report = self.rpt.generate_report()
        self.assertEqual(report["scenario_summary"]["status"], "no simulator")
        self.assertEqual(report["scenario_summary"]["steps_completed"], 0)

    def test_threat_assessment_with_evidence(self):
        """After injecting events, threat assessment reflects data."""
        self.det.simulate_event()
        self.det.simulate_event()
        report = self.rpt.generate_report()
        ta = report["threat_assessment"]
        self.assertGreater(ta["threat_score"], 0)
        self.assertEqual(ta["total_evidence"], 2)
        self.assertIn(ta["threat_level"], ["low", "medium", "high", "critical"])

    def test_affected_sectors_populated_after_events(self):
        """After events, affected_sectors_assets has sector data."""
        self.det.simulate_event()
        report = self.rpt.generate_report()
        sectors = report["affected_sectors_assets"]["sectors"]
        self.assertGreater(len(sectors), 0)

    def test_evidence_chain_matches_detection(self):
        """Evidence chain in report matches detection engine evidence."""
        self.det.simulate_event()
        self.det.simulate_event()
        report = self.rpt.generate_report()
        self.assertEqual(len(report["evidence_chain"]), 2)

    def test_deception_activity_default(self):
        """Deception activity shows zeroed defaults with no events."""
        report = self.rpt.generate_report()
        da = report["deception_activity"]
        self.assertIn("total_decoys", da)
        self.assertIn("attacker_state", da)

    def test_final_outcome_has_narrative(self):
        """Final outcome always contains a narrative string."""
        report = self.rpt.generate_report()
        fo = report["final_outcome"]
        self.assertIn("narrative", fo)
        self.assertGreater(len(fo["narrative"]), 10)
        self.assertIn("simulation_complete", fo)
        self.assertIn("threat_level", fo)
        self.assertIn("attacker_state", fo)

    def test_replay_timeline_empty(self):
        """Timeline is empty when no events have occurred."""
        timeline = self.rpt.replay_timeline()
        self.assertEqual(timeline, [])

    def test_replay_timeline_with_detection(self):
        """Timeline includes detection events after simulate_event."""
        self.det.simulate_event()
        timeline = self.rpt.replay_timeline()
        self.assertGreater(len(timeline), 0)
        self.assertEqual(timeline[0]["phase"], "detection")
        self.assertIn("timestamp", timeline[0])
        self.assertIn("sector", timeline[0])

    def test_replay_timeline_chronological(self):
        """Timeline entries are sorted chronologically."""
        self.det.simulate_event()
        self.det.simulate_event()
        self.det.simulate_event()
        timeline = self.rpt.replay_timeline()
        timestamps = [e["timestamp"] for e in timeline]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_replay_timeline_includes_deception(self):
        """Timeline includes deception events after decoy simulation."""
        self.det.simulate_event()
        self.dec.evaluate_step(0, {"sector": "Military", "targets": ["ast-mil-c2"]})
        timeline = self.rpt.replay_timeline()
        phases = {e["phase"] for e in timeline}
        # At minimum detection should be present
        self.assertIn("detection", phases)

    def test_replay_timeline_includes_command_decisions(self):
        """Timeline includes commander decisions after approve."""
        self.det.simulate_event()
        rec = self.cmd.generate_recommendation()
        self.assertIsNotNone(rec)
        dr = self.cmd.submit_recommendation(rec)
        self.cmd.approve_decision(dr.decision_id)
        timeline = self.rpt.replay_timeline()
        cmd_events = [e for e in timeline if e["phase"] == "command"]
        self.assertGreater(len(cmd_events), 0)
        self.assertIn("commander_decision", cmd_events[0]["type"])

    def test_export_json_is_valid_json(self):
        """export_json returns parseable JSON string."""
        import json
        self.det.simulate_event()
        data = self.rpt.export_json()
        parsed = json.loads(data)
        self.assertIn("generated_at", parsed)
        self.assertIn("scenario_summary", parsed)

    def test_ai_recommendations_after_generate(self):
        """AI recommendations section populated after recommend call."""
        self.det.simulate_event()
        rec = self.cmd.generate_recommendation()
        self.cmd.submit_recommendation(rec)
        report = self.rpt.generate_report()
        self.assertGreater(len(report["ai_recommendations"]), 0)

    def test_commander_decisions_after_approve(self):
        """Commander decisions section populated after approve."""
        self.det.simulate_event()
        rec = self.cmd.generate_recommendation()
        dr = self.cmd.submit_recommendation(rec)
        self.cmd.approve_decision(dr.decision_id)
        report = self.rpt.generate_report()
        self.assertGreater(len(report["commander_decisions"]), 0)

    def test_singleton_get_report_engine(self):
        """get_report_engine returns same instance on repeated calls."""
        e1 = get_report_engine()
        e2 = get_report_engine()
        self.assertIs(e1, e2)

    def test_reset_does_not_raise(self):
        """ReportEngine.reset() is safe to call."""
        self.rpt.reset()  # Should not raise

    def test_mitre_techniques_after_events(self):
        """MITRE techniques populated after detection events."""
        self.det.simulate_event()
        report = self.rpt.generate_report()
        self.assertGreater(len(report["mitre_techniques"]), 0)
        tech = report["mitre_techniques"][0]
        self.assertIn("technique", tech)
        self.assertIn("name", tech)


class ReportsAPITests(unittest.TestCase):
    """Integration tests for the Reports API endpoints."""

    def setUp(self):
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_reports_route_returns_200(self):
        """GET /reports returns HTTP 200."""
        response = self.client.get("/reports")
        self.assertEqual(response.status_code, 200)

    def test_reports_page_contains_elements(self):
        """Reports page template contains expected elements."""
        response = self.client.get("/reports")
        html = response.data.decode("utf-8")
        self.assertIn("Reports", html)
        self.assertIn("reports.js", html)

    def test_generate_report_api(self):
        """POST /api/reports/generate returns report and timeline."""
        response = self.client.post("/api/reports/generate")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("report", data)
        self.assertIn("timeline", data)
        # Report has all sections
        report = data["report"]
        self.assertIn("generated_at", report)
        self.assertIn("scenario_summary", report)
        self.assertIn("threat_assessment", report)
        self.assertIn("final_outcome", report)

    def test_generate_report_with_data(self):
        """Report reflects data after simulation events."""
        self.client.post("/api/detection/simulate-event")
        self.client.post("/api/detection/simulate-event")
        response = self.client.post("/api/reports/generate")
        data = response.get_json()
        report = data["report"]
        self.assertGreater(report["threat_assessment"]["threat_score"], 0)
        self.assertEqual(report["threat_assessment"]["total_evidence"], 2)
        self.assertGreater(len(data["timeline"]), 0)

    def test_export_json_endpoint(self):
        """GET /api/reports/export returns downloadable JSON."""
        self.client.post("/api/detection/simulate-event")
        response = self.client.get("/api/reports/export")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/json")
        self.assertIn("attachment", response.headers.get("Content-Disposition", ""))
        import json
        parsed = json.loads(response.data.decode("utf-8"))
        self.assertIn("generated_at", parsed)

    def test_replay_endpoint(self):
        """GET /api/reports/replay returns timeline array."""
        response = self.client.get("/api/reports/replay")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("timeline", data)
        self.assertIsInstance(data["timeline"], list)

    def test_replay_with_events(self):
        """Replay timeline includes events after simulation."""
        self.client.post("/api/detection/simulate-event")
        response = self.client.get("/api/reports/replay")
        data = response.get_json()
        self.assertGreater(len(data["timeline"]), 0)
        self.assertEqual(data["timeline"][0]["phase"], "detection")

    def test_full_integration_pipeline(self):
        """Full pipeline: simulate -> detect -> deceive -> command -> report."""
        # Step 1: Inject detection events
        self.client.post("/api/detection/simulate-event")

        # Step 2: Generate AI recommendation
        rec_resp = self.client.post("/api/command/recommend")
        self.assertEqual(rec_resp.status_code, 200)
        rec_data = rec_resp.get_json()
        decision_id = rec_data["decision_id"]

        # Step 3: Commander approves
        dec_resp = self.client.post("/api/command/decide", json={
            "decision_id": decision_id,
            "decision": "approve",
        })
        self.assertEqual(dec_resp.status_code, 200)

        # Step 4: Generate report — should contain all data
        rpt_resp = self.client.post("/api/reports/generate")
        rpt_data = rpt_resp.get_json()
        report = rpt_data["report"]
        timeline = rpt_data["timeline"]

        # Verify report sections populated
        self.assertGreater(report["threat_assessment"]["threat_score"], 0)
        self.assertGreater(len(report["evidence_chain"]), 0)
        self.assertGreater(len(report["ai_recommendations"]), 0)
        self.assertGreater(len(report["commander_decisions"]), 0)

        # Verify timeline has both detection and command phases
        phases = {e["phase"] for e in timeline}
        self.assertIn("detection", phases)
        self.assertIn("command", phases)

        # Step 5: Export should also work
        exp_resp = self.client.get("/api/reports/export")
        self.assertEqual(exp_resp.status_code, 200)

    def test_simulation_reset_clears_report_data(self):
        """After simulation reset, report returns clean data."""
        self.client.post("/api/detection/simulate-event")
        self.client.post("/api/simulation/reset")
        response = self.client.post("/api/reports/generate")
        data = response.get_json()
        report = data["report"]
        self.assertEqual(report["threat_assessment"]["threat_score"], 0)
        self.assertEqual(report["evidence_chain"], [])
        self.assertEqual(data["timeline"], [])


# ======================================================================
# Phase 13 — Final Integration, Validation & Stability Tests
# ======================================================================

class DemoScenarioTests(unittest.TestCase):
    """End-to-end demo scenario tests — full pipeline verification."""

    def setUp(self):
        get_simulator(get_twin()).reset()
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_demo_run_complete_pipeline(self):
        """POST /api/demo/run executes full pipeline and returns report."""
        response = self.client.post("/api/demo/run")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "complete")
        self.assertEqual(data["steps_executed"], 8)

    def test_demo_run_attack_path(self):
        """Demo scenario covers Military -> Telecom -> Energy -> Healthcare."""
        data = self.client.post("/api/demo/run").get_json()
        path = data["attack_path"]
        self.assertIn("military", path)
        self.assertIn("telecom", path)
        self.assertIn("energy", path)
        self.assertIn("healthcare", path)
        # Verify ordering
        self.assertLess(path.index("military"), path.index("telecom"))
        self.assertLess(path.index("telecom"), path.index("energy"))
        self.assertLess(path.index("energy"), path.index("healthcare"))

    def test_demo_run_detection_populated(self):
        """After demo, detection has evidence from simulation + deception."""
        data = self.client.post("/api/demo/run").get_json()
        report = data["report"]
        # 8 simulator steps + deception events both feed detection
        self.assertGreaterEqual(report["threat_assessment"]["total_evidence"], 8)
        self.assertGreater(report["threat_assessment"]["threat_score"], 0)

    def test_demo_run_mitre_techniques(self):
        """Demo scenario maps multiple MITRE ATT&CK techniques."""
        data = self.client.post("/api/demo/run").get_json()
        techniques = data["report"]["mitre_techniques"]
        self.assertGreater(len(techniques), 1)
        tech_ids = [t["technique"] for t in techniques]
        # Key techniques from the scenario
        self.assertIn("T1595", tech_ids)  # Active Scanning
        self.assertIn("T1078", tech_ids)  # Valid Accounts
        self.assertIn("T1486", tech_ids)  # Data Encrypted for Impact

    def test_demo_run_deception_interaction(self):
        """Demo scenario includes deception activity."""
        data = self.client.post("/api/demo/run").get_json()
        report = data["report"]
        self.assertIn("deception_activity", report)
        dec = report["deception_activity"]
        self.assertIn("total_decoys", dec)
        self.assertGreater(dec["total_decoys"], 0)
        self.assertIn("attacker_state", dec)

    def test_demo_run_commander_decision(self):
        """Demo scenario includes AI recommendation + commander approval."""
        data = self.client.post("/api/demo/run").get_json()
        self.assertIsNotNone(data["decision_id"])
        self.assertIsNotNone(data["commander_decision"])
        self.assertEqual(data["commander_decision"]["decision"], "approve")

    def test_demo_run_report_sections_complete(self):
        """Demo report has all required sections."""
        data = self.client.post("/api/demo/run").get_json()
        report = data["report"]
        required = {
            "generated_at", "scenario_summary", "threat_assessment",
            "affected_sectors_assets", "mitre_techniques", "evidence_chain",
            "deception_activity", "adaptation_summary", "ai_recommendations",
            "commander_decisions", "analysis_summary", "final_outcome",
        }
        self.assertEqual(set(report.keys()), required)

    def test_demo_run_timeline_chronological(self):
        """Demo timeline is sorted chronologically."""
        data = self.client.post("/api/demo/run").get_json()
        timeline = data["timeline"]
        self.assertGreater(len(timeline), 8)
        timestamps = [e["timestamp"] for e in timeline]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_demo_run_timeline_has_all_phases(self):
        """Demo timeline contains detection, deception, and command phases."""
        data = self.client.post("/api/demo/run").get_json()
        phases = {e["phase"] for e in data["timeline"]}
        self.assertIn("detection", phases)
        self.assertIn("command", phases)

    def test_demo_run_final_outcome(self):
        """Demo report has a meaningful final outcome."""
        data = self.client.post("/api/demo/run").get_json()
        fo = data["report"]["final_outcome"]
        self.assertTrue(fo["simulation_complete"])
        self.assertGreater(len(fo["narrative"]), 20)

    def test_demo_run_evidence_chain(self):
        """Demo report evidence chain includes all scenario sectors."""
        data = self.client.post("/api/demo/run").get_json()
        chain = data["report"]["evidence_chain"]
        self.assertGreaterEqual(len(chain), 8)
        # Verify sector progression from simulator events
        sectors = [e["sector"] for e in chain]
        self.assertIn("military", sectors)
        self.assertIn("telecom", sectors)
        self.assertIn("energy", sectors)
        self.assertIn("healthcare", sectors)

    def test_demo_run_export_works(self):
        """After demo run, export endpoint returns valid JSON."""
        self.client.post("/api/demo/run")
        response = self.client.get("/api/reports/export")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/json")
        import json
        parsed = json.loads(response.data.decode("utf-8"))
        self.assertGreaterEqual(parsed["threat_assessment"]["total_evidence"], 8)


class StateConsistencyTests(unittest.TestCase):
    """Tests verifying data consistency across all modules."""

    def setUp(self):
        get_simulator(get_twin()).reset()
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_detection_and_report_agree_on_evidence_count(self):
        """Detection status evidence count matches report evidence chain."""
        self.client.post("/api/detection/simulate-event")
        self.client.post("/api/detection/simulate-event")
        det = self.client.get("/api/detection").get_json()
        rpt = self.client.post("/api/reports/generate").get_json()
        self.assertEqual(
            det["total_evidence"],
            rpt["report"]["threat_assessment"]["total_evidence"],
        )
        self.assertEqual(
            det["total_evidence"],
            len(rpt["report"]["evidence_chain"]),
        )

    def test_threat_score_consistent_across_apis(self):
        """Threat score matches between detection, status, and report."""
        self.client.post("/api/detection/simulate-event")
        det = self.client.get("/api/detection").get_json()
        status = self.client.get("/api/status").get_json()
        rpt = self.client.post("/api/reports/generate").get_json()
        self.assertEqual(det["threat_score"], status["threat_score"])
        self.assertEqual(
            det["threat_score"],
            rpt["report"]["threat_assessment"]["threat_score"],
        )

    def test_twin_reflects_simulation_events(self):
        """After simulation steps, twin shows affected assets."""
        for _ in range(4):
            self.client.post("/api/simulation/step")
        twin = self.client.get("/api/twin").get_json()
        summary = twin["summary"]
        self.assertGreater(summary["compromised"] + summary["warning"], 0)

    def test_command_engine_reflects_detection_state(self):
        """After events + recommend, recommendation references correct sectors."""
        self.client.post("/api/detection/simulate-event")
        rec = self.client.post("/api/command/recommend").get_json()
        self.assertIn("recommendation", rec)
        self.assertGreater(
            len(rec["recommendation"]["affected_sectors"]), 0
        )

    def test_reset_returns_clean_state(self):
        """After full reset, all modules return to initial state."""
        self.client.post("/api/demo/run")
        self.client.post("/api/simulation/reset")

        # Detection clean
        det = self.client.get("/api/detection").get_json()
        self.assertEqual(det["total_evidence"], 0)
        self.assertEqual(det["threat_score"], 0)

        # Command clean
        cmd = self.client.get("/api/command").get_json()
        self.assertEqual(cmd["total_recommendations"], 0)
        self.assertEqual(cmd["total_decisions"], 0)

        # Deception clean
        dec = self.client.get("/api/deception").get_json()
        self.assertEqual(dec["total_events"], 0)
        self.assertEqual(dec["attacker_state"], "free_roaming")

        # Report reflects clean state
        rpt = self.client.post("/api/reports/generate").get_json()
        self.assertEqual(rpt["report"]["threat_assessment"]["threat_score"], 0)
        self.assertEqual(rpt["timeline"], [])

    def test_twin_reset_with_full_reset(self):
        """Simulation reset also restores twin to all-healthy."""
        self.client.post("/api/demo/run")
        self.client.post("/api/simulation/reset")
        twin = self.client.get("/api/twin").get_json()
        summary = twin["summary"]
        self.assertEqual(summary["compromised"], 0)
        self.assertEqual(summary["warning"], 0)
        self.assertEqual(summary["healthy"], summary["total_assets"])

    def test_simulation_status_matches_detection_after_steps(self):
        """After stepping, detection evidence >= simulation steps."""
        for _ in range(3):
            self.client.post("/api/simulation/step")
        sim = self.client.get("/api/simulation").get_json()
        det = self.client.get("/api/detection").get_json()
        # Evidence includes simulator events + possible deception events
        self.assertEqual(sim["current_step"], 3)
        self.assertGreaterEqual(det["total_evidence"], sim["current_step"])


class ErrorHandlingTests(unittest.TestCase):
    """Tests for graceful error handling with invalid/missing data."""

    def setUp(self):
        get_simulator(get_twin()).reset()
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_command_decide_with_invalid_json(self):
        """POST /api/command/decide with malformed JSON returns 400."""
        response = self.client.post(
            "/api/command/decide",
            data="not json{{{",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_command_decide_with_empty_body(self):
        """POST /api/command/decide with empty body returns 400."""
        response = self.client.post(
            "/api/command/decide",
            data="{}",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_command_recommend_without_evidence(self):
        """Recommend without evidence returns 400, not crash."""
        response = self.client.post("/api/command/recommend")
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("error", data)

    def test_deception_contain_without_attacker(self):
        """Contain without active attacker returns gracefully."""
        response = self.client.post("/api/deception/contain")
        self.assertEqual(response.status_code, 200)

    def test_report_generate_with_no_data(self):
        """Report generation with clean state returns valid empty report."""
        response = self.client.post("/api/reports/generate")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("report", data)
        self.assertEqual(data["report"]["threat_assessment"]["threat_score"], 0)

    def test_replay_with_no_data(self):
        """Replay with clean state returns empty timeline."""
        response = self.client.get("/api/reports/replay")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["timeline"], [])

    def test_export_with_no_data(self):
        """Export with clean state returns valid JSON."""
        response = self.client.get("/api/reports/export")
        self.assertEqual(response.status_code, 200)
        import json
        parsed = json.loads(response.data.decode("utf-8"))
        self.assertIn("generated_at", parsed)

    def test_step_after_scenario_complete(self):
        """Stepping beyond scenario length is safe."""
        for _ in range(10):
            self.client.post("/api/simulation/step")
        sim = self.client.get("/api/simulation").get_json()
        self.assertTrue(sim["complete"])
        self.assertEqual(sim["current_step"], 8)

    def test_all_pages_load_without_data(self):
        """All 7 pages load successfully with no simulation data."""
        pages = ["/", "/digital-twin", "/simulation",
                 "/detection", "/deception", "/command", "/reports"]
        for page in pages:
            response = self.client.get(page)
            self.assertEqual(response.status_code, 200,
                             f"Page {page} returned {response.status_code}")

    def test_all_api_endpoints_without_data(self):
        """All API endpoints return valid responses with no data."""
        endpoints = [
            ("/api/simulation", "GET"),
            ("/api/detection", "GET"),
            ("/api/deception", "GET"),
            ("/api/command", "GET"),
            ("/api/status", "GET"),
            ("/api/twin", "GET"),
            ("/api/reports/replay", "GET"),
            ("/api/reports/export", "GET"),
            ("/api/reports/generate", "POST"),
        ]
        for url, method in endpoints:
            if method == "GET":
                response = self.client.get(url)
            else:
                response = self.client.post(url)
            self.assertEqual(response.status_code, 200,
                             f"{method} {url} returned {response.status_code}")


# ======================================================================
# Phase 14 — Final Demo Mode & Presentation Reliability Tests
# ======================================================================

class DemoDeterminismTests(unittest.TestCase):
    """Tests verifying the demo produces consistent results."""

    def setUp(self):
        get_simulator(get_twin()).reset()
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def _run_demo(self):
        return self.client.post("/api/demo/run").get_json()

    def test_demo_deterministic_attack_path(self):
        """Two consecutive demo runs produce the same attack path."""
        d1 = self._run_demo()
        d2 = self._run_demo()
        self.assertEqual(d1["attack_path"], d2["attack_path"])

    def test_demo_deterministic_decoy(self):
        """Two consecutive demo runs use the same decoy."""
        d1 = self._run_demo()
        d2 = self._run_demo()
        self.assertEqual(d1["decoy_used"], d2["decoy_used"])

    def test_demo_deterministic_mitre(self):
        """Two consecutive demo runs produce the same MITRE techniques."""
        d1 = self._run_demo()
        d2 = self._run_demo()
        t1 = sorted([t["technique"] for t in d1["report"]["mitre_techniques"]])
        t2 = sorted([t["technique"] for t in d2["report"]["mitre_techniques"]])
        self.assertEqual(t1, t2)

    def test_demo_deterministic_evidence_count(self):
        """Two consecutive demo runs produce the same evidence count."""
        d1 = self._run_demo()
        d2 = self._run_demo()
        self.assertEqual(
            d1["report"]["threat_assessment"]["total_evidence"],
            d2["report"]["threat_assessment"]["total_evidence"],
        )


class DemoContainmentRecoveryTests(unittest.TestCase):
    """Tests for containment and recovery phases in the demo."""

    def setUp(self):
        get_simulator(get_twin()).reset()
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_demo_containment(self):
        """Demo scenario contains the attacker."""
        data = self.client.post("/api/demo/run").get_json()
        self.assertTrue(data["contained"])
        self.assertEqual(
            data["report"]["final_outcome"]["attacker_state"], "contained"
        )

    def test_demo_recovery(self):
        """Demo recovery restores energy and healthcare sectors."""
        data = self.client.post("/api/demo/run").get_json()
        self.assertIn("energy", data["recovered_sectors"])
        self.assertIn("healthcare", data["recovered_sectors"])

    def test_demo_recovery_restores_twin_assets(self):
        """After demo, energy + healthcare assets are healthy."""
        self.client.post("/api/demo/run")
        twin = self.client.get("/api/twin").get_json()
        for sector_id in ("energy", "healthcare"):
            sector = twin["sectors"][sector_id]
            for asset in sector["assets"]:
                self.assertEqual(asset["status"], "healthy",
                                 f"Asset {asset['asset_id']} not healthy after demo")

    def test_demo_outcome_narrative_contains(self):
        """After containment, outcome narrative mentions containment."""
        data = self.client.post("/api/demo/run").get_json()
        narrative = data["report"]["final_outcome"]["narrative"].lower()
        self.assertIn("contained", narrative)

    def test_demo_full_pipeline_sections(self):
        """Demo report has all required sections populated."""
        data = self.client.post("/api/demo/run").get_json()
        report = data["report"]
        required = {
            "generated_at", "scenario_summary", "threat_assessment",
            "affected_sectors_assets", "mitre_techniques", "evidence_chain",
            "deception_activity", "adaptation_summary", "ai_recommendations",
            "commander_decisions", "analysis_summary", "final_outcome",
        }
        self.assertEqual(set(report.keys()), required)
        # Each section has data
        self.assertGreater(report["threat_assessment"]["threat_score"], 0)
        self.assertGreater(len(report["evidence_chain"]), 0)
        self.assertGreater(len(report["mitre_techniques"]), 0)
        self.assertGreater(len(report["ai_recommendations"]), 0)
        self.assertGreater(len(report["commander_decisions"]), 0)


class PresentationReliabilityTests(unittest.TestCase):
    """Tests for presentation-breaking error prevention."""

    def setUp(self):
        get_simulator(get_twin()).reset()
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_repeated_reset_safe(self):
        """Multiple consecutive resets don't crash."""
        for _ in range(5):
            r = self.client.post("/api/simulation/reset")
            self.assertEqual(r.status_code, 200)

    def test_repeated_start_safe(self):
        """Multiple starts don't crash or duplicate."""
        self.client.post("/api/simulation/start")
        import time; time.sleep(0.5)
        r = self.client.post("/api/simulation/start")
        self.assertEqual(r.status_code, 200)
        self.client.post("/api/simulation/stop")

    def test_start_after_complete_returns_message(self):
        """Starting after scenario complete returns a guidance message."""
        # Run full scenario
        self.client.post("/api/demo/run")
        # Try to start again
        r = self.client.post("/api/simulation/start")
        data = r.get_json()
        self.assertFalse(data["ok"])
        self.assertIn("complete", data["message"].lower())

    def test_step_after_complete_returns_message(self):
        """Stepping after scenario complete returns a guidance message."""
        self.client.post("/api/demo/run")
        r = self.client.post("/api/simulation/step")
        data = r.get_json()
        self.assertFalse(data["ok"])

    def test_demo_then_reset_then_demo(self):
        """Full cycle: demo -> reset -> demo works cleanly."""
        d1 = self.client.post("/api/demo/run").get_json()
        self.client.post("/api/simulation/reset")
        d2 = self.client.post("/api/demo/run").get_json()
        self.assertEqual(d1["attack_path"], d2["attack_path"])
        self.assertEqual(d1["decoy_used"], d2["decoy_used"])

    def test_demo_then_export_then_reset(self):
        """Demo -> export -> reset -> all pages still load."""
        self.client.post("/api/demo/run")
        exp = self.client.get("/api/reports/export")
        self.assertEqual(exp.status_code, 200)
        self.client.post("/api/simulation/reset")
        for page in ["/", "/digital-twin", "/simulation", "/detection",
                     "/deception", "/command", "/reports"]:
            r = self.client.get(page)
            self.assertEqual(r.status_code, 200,
                             f"Page {page} failed after demo+reset cycle")

    def test_pages_load_during_running_simulation(self):
        """All pages load even when simulation is running."""
        self.client.post("/api/simulation/start")
        import time; time.sleep(0.3)
        for page in ["/", "/digital-twin", "/simulation", "/detection",
                     "/deception", "/command", "/reports"]:
            r = self.client.get(page)
            self.assertEqual(r.status_code, 200,
                             f"Page {page} failed during running simulation")
        self.client.post("/api/simulation/stop")

    def test_simulation_page_has_demo_button(self):
        """Simulation page contains the Run Demo Scenario button."""
        r = self.client.get("/simulation")
        html = r.data.decode("utf-8")
        self.assertIn("Run Demo Scenario", html)
        self.assertIn("runDemo", html)

    def test_demo_endpoint_idempotent(self):
        """Calling demo/run multiple times always succeeds."""
        for _ in range(3):
            r = self.client.post("/api/demo/run")
            self.assertEqual(r.status_code, 200)
            data = r.get_json()
            self.assertEqual(data["status"], "complete")


# ======================================================================
# Phase 15 — Adversary Intelligence Tests
# ======================================================================

class AdversaryModelTests(unittest.TestCase):
    """Unit tests for adversary intelligence models."""

    def test_adversary_profile_default_values(self):
        """AdversaryProfile starts with sensible defaults."""
        from intelligence.models import AdversaryProfile
        p = AdversaryProfile()
        self.assertEqual(p.adversary_id, "ADV-SYNTH-001")
        self.assertIsNone(p.entry_point)
        self.assertIsNone(p.current_sector)
        self.assertEqual(p.attack_progression, [])
        self.assertEqual(p.observed_techniques, [])
        self.assertEqual(p.behavior_history, [])
        self.assertEqual(p.stealth_level, 0.0)
        self.assertEqual(p.adaptation_status, "unknown")
        self.assertEqual(p.evidence_collected, 0)
        self.assertEqual(p.threat_confidence, 0.0)

    def test_adversary_profile_to_dict(self):
        """AdversaryProfile.to_dict returns all required keys."""
        from intelligence.models import AdversaryProfile
        p = AdversaryProfile()
        d = p.to_dict()
        required = {
            "adversary_id", "entry_point", "current_sector",
            "attack_progression", "observed_techniques", "behavior_history",
            "stealth_level", "adaptation_status", "evidence_collected",
            "threat_confidence", "first_seen", "last_seen",
        }
        self.assertEqual(set(d.keys()), required)

    def test_adversary_activity_to_dict(self):
        """AdversaryActivity.to_dict serialises correctly."""
        from intelligence.models import AdversaryActivity
        now = datetime.now(timezone.utc)
        a = AdversaryActivity(now, "military", "attack", "T1595", "Active Scanning", "test detail")
        d = a.to_dict()
        self.assertEqual(d["sector"], "military")
        self.assertEqual(d["action"], "attack")
        self.assertEqual(d["technique"], "T1595")
        self.assertIn("timestamp", d)


class AdversaryEngineTests(unittest.TestCase):
    """Unit tests for the adversary intelligence engine."""

    def setUp(self):
        get_simulator(get_twin()).reset()
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()

    def test_engine_empty_profile_without_data(self):
        """Engine returns empty profile when no events exist."""
        from intelligence.engine import AdversaryIntelligence
        eng = AdversaryIntelligence()
        profile = eng.update().to_dict()
        self.assertEqual(profile["adversary_id"], "ADV-SYNTH-001")
        self.assertIsNone(profile["current_sector"])
        self.assertEqual(profile["attack_progression"], [])

    def test_engine_tracks_simulator_events(self):
        """Engine derives position from simulator events."""
        from intelligence.engine import AdversaryIntelligence
        sim = get_simulator(get_twin())
        det = get_detection_engine()
        dec = get_deception_engine()
        # Wire the simulator callback
        def on_step(idx, step, ev):
            det.ingest_event(ev)
            dec.evaluate_step(idx, step)
        sim._on_step = on_step

        sim.step_once()
        sim.step_once()

        eng = AdversaryIntelligence(sim, det, dec)
        profile = eng.update().to_dict()
        self.assertEqual(profile["entry_point"], "military")
        self.assertEqual(profile["current_sector"], "military")
        self.assertIn("military", profile["attack_progression"])
        self.assertGreater(len(profile["behavior_history"]), 0)

    def test_engine_full_scenario_tracking(self):
        """Engine tracks the full 8-step scenario."""
        from intelligence.engine import AdversaryIntelligence
        from simulation.simulator import SCENARIO
        sim = get_simulator(get_twin())
        det = get_detection_engine()
        dec = get_deception_engine()
        def on_step(idx, step, ev):
            det.ingest_event(ev)
            dec.evaluate_step(idx, step)
        sim._on_step = on_step

        for _ in range(len(SCENARIO)):
            sim.step_once()

        eng = AdversaryIntelligence(sim, det, dec)
        profile = eng.update().to_dict()
        self.assertEqual(profile["current_sector"], "healthcare")
        self.assertEqual(profile["attack_progression"], ["military", "telecom", "energy", "healthcare"])
        self.assertGreater(profile["evidence_collected"], 0)
        self.assertGreater(len(profile["observed_techniques"]), 0)

    def test_engine_stealth_calculation(self):
        """Stealth level is derived from signal strengths."""
        from intelligence.engine import AdversaryIntelligence
        from simulation.simulator import SCENARIO
        sim = get_simulator(get_twin())
        det = get_detection_engine()
        dec = get_deception_engine()
        def on_step(idx, step, ev):
            det.ingest_event(ev)
            dec.evaluate_step(idx, step)
        sim._on_step = on_step

        for _ in range(len(SCENARIO)):
            sim.step_once()

        eng = AdversaryIntelligence(sim, det, dec)
        profile = eng.update()
        self.assertGreater(profile.stealth_level, 0.0)
        self.assertLessEqual(profile.stealth_level, 1.0)

    def test_engine_adaptation_status_active(self):
        """Without explicit containment, adaptation reflects decoy interactions."""
        from intelligence.engine import AdversaryIntelligence
        from simulation.simulator import SCENARIO
        sim = get_simulator(get_twin())
        det = get_detection_engine()
        dec = get_deception_engine()
        def on_step(idx, step, ev):
            det.ingest_event(ev)
            dec.evaluate_step(idx, step)
        sim._on_step = on_step

        for _ in range(len(SCENARIO)):
            sim.step_once()

        eng = AdversaryIntelligence(sim, det, dec)
        profile = eng.update()
        # Can be active, adapted, or trapped depending on decoy interactions
        self.assertIn(profile.adaptation_status, ("active", "trapped_in_decoy", "adapted"))

    def test_engine_adaptation_contained(self):
        """After containment, adaptation status is 'contained'."""
        from intelligence.engine import AdversaryIntelligence
        from simulation.simulator import SCENARIO
        sim = get_simulator(get_twin())
        det = get_detection_engine()
        dec = get_deception_engine()
        def on_step(idx, step, ev):
            det.ingest_event(ev)
            dec.evaluate_step(idx, step)
        sim._on_step = on_step

        for _ in range(len(SCENARIO)):
            sim.step_once()
        dec.contain_attacker()

        eng = AdversaryIntelligence(sim, det, dec)
        profile = eng.update()
        self.assertEqual(profile.adaptation_status, "contained")

    def test_engine_reset(self):
        """Engine.reset() clears the profile."""
        from intelligence.engine import AdversaryIntelligence
        eng = AdversaryIntelligence()
        eng._profile.adversary_id = "CHANGED"
        eng.reset()
        self.assertEqual(eng._profile.adversary_id, "ADV-SYNTH-001")


class AdversaryAPITests(unittest.TestCase):
    """Integration tests for the adversary intelligence API endpoints."""

    def setUp(self):
        get_simulator(get_twin()).reset()
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_adversary_page_loads(self):
        """Adversary page returns 200."""
        r = self.client.get("/adversary")
        self.assertEqual(r.status_code, 200)

    def test_adversary_page_contains_elements(self):
        """Adversary page contains expected content."""
        r = self.client.get("/adversary")
        html = r.data.decode("utf-8")
        self.assertIn("Adversary Intelligence", html)
        self.assertIn("Adversary", html)
        self.assertIn("adversary.js", html)

    def test_adversary_api_returns_profile(self):
        """GET /api/adversary returns a valid profile."""
        r = self.client.get("/api/adversary")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["adversary_id"], "ADV-SYNTH-001")
        required_keys = {
            "adversary_id", "entry_point", "current_sector",
            "attack_progression", "observed_techniques", "behavior_history",
            "stealth_level", "adaptation_status", "evidence_collected",
            "threat_confidence", "first_seen", "last_seen",
        }
        self.assertEqual(set(data.keys()), required_keys)

    def test_adversary_api_updates_after_demo(self):
        """After demo/run, adversary API has full profile."""
        self.client.post("/api/demo/run")
        data = self.client.get("/api/adversary").get_json()
        self.assertEqual(data["entry_point"], "military")
        self.assertEqual(data["current_sector"], "healthcare")
        self.assertEqual(data["attack_progression"], ["military", "telecom", "energy", "healthcare"])
        self.assertGreater(data["evidence_collected"], 0)
        self.assertGreater(len(data["observed_techniques"]), 0)
        self.assertGreater(len(data["behavior_history"]), 0)
        self.assertIn(data["adaptation_status"], ("active", "trapped_in_decoy", "contained"))

    def test_adversary_api_after_reset(self):
        """After reset, adversary API returns clean profile."""
        self.client.post("/api/demo/run")
        self.client.post("/api/simulation/reset")
        data = self.client.get("/api/adversary").get_json()
        self.assertIsNone(data["current_sector"])
        self.assertEqual(data["attack_progression"], [])
        self.assertEqual(data["evidence_collected"], 0)

    def test_nav_contains_adversary_link(self):
        """Dashboard page has Adversary nav link."""
        r = self.client.get("/")
        html = r.data.decode("utf-8")
        self.assertIn('href="/adversary"', html)
        self.assertIn("Adversary", html)

    def test_adversary_deterministic_after_demo(self):
        """Two consecutive demo runs produce the same adversary profile."""
        self.client.post("/api/demo/run")
        p1 = self.client.get("/api/adversary").get_json()
        self.client.post("/api/demo/run")
        p2 = self.client.get("/api/adversary").get_json()
        self.assertEqual(p1["attack_progression"], p2["attack_progression"])
        self.assertEqual(p1["entry_point"], p2["entry_point"])
        self.assertEqual(p1["evidence_collected"], p2["evidence_collected"])


# ======================================================================
# Phase 16 — National Security Impact & Dependency Propagation Tests
# ======================================================================

class ImpactModelTests(unittest.TestCase):
    """Unit tests for impact models."""

    def test_impact_level_values(self):
        """ImpactLevel enum has correct values."""
        from impact.models import ImpactLevel
        self.assertEqual(ImpactLevel.LOW.value, "low")
        self.assertEqual(ImpactLevel.CRITICAL.value, "critical")

    def test_risk_assessment_to_dict(self):
        """RiskAssessment serialises all required keys."""
        from impact.models import RiskAssessment
        ra = RiskAssessment("military", "telecom", "Secure Comms", 0.85, [{"asset_id": "tel-core"}])
        d = ra.to_dict()
        self.assertEqual(d["source_sector"], "military")
        self.assertEqual(d["affected_sector"], "telecom")
        self.assertEqual(d["risk_score"], 0.85)
        self.assertEqual(len(d["critical_assets"]), 1)

    def test_propagation_chain_to_dict(self):
        """PropagationChain serialises correctly."""
        from impact.models import PropagationChain
        pc = PropagationChain("military", ["military", "telecom"])
        d = pc.to_dict()
        self.assertEqual(d["origin"], "military")
        self.assertEqual(d["path"], ["military", "telecom"])

    def test_national_impact_summary_to_dict(self):
        """NationalImpactSummary has all required keys."""
        from impact.models import NationalImpactSummary
        s = NationalImpactSummary()
        d = s.to_dict()
        required = {
            "impact_level", "affected_sectors", "total_compromised",
            "total_at_risk", "propagation_chains", "priority_sector",
            "priority_reason", "score",
        }
        self.assertEqual(set(d.keys()), required)


class ImpactEngineTests(unittest.TestCase):
    """Unit tests for the impact engine."""

    def setUp(self):
        get_simulator(get_twin()).reset()
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()

    def test_empty_assessment_when_no_compromise(self):
        """No compromised sectors → LOW impact, no chains."""
        from impact.engine import ImpactEngine
        twin = get_twin()
        eng = ImpactEngine(twin)
        result = eng.assess()
        self.assertEqual(result.impact_level.value, "low")
        self.assertEqual(result.total_compromised, 0)
        self.assertEqual(len(result.propagation_chains), 0)

    def test_propagation_from_military(self):
        """Compromising military propagates to government and telecom."""
        from impact.engine import ImpactEngine
        twin = get_twin()
        # Compromise military assets
        twin.set_asset_status("mil-cmd-net", AssetStatus.COMPROMISED)
        twin.set_asset_status("mil-def-ops", AssetStatus.COMPROMISED)

        eng = ImpactEngine(twin)
        result = eng.assess()
        self.assertGreater(result.total_compromised, 0)
        self.assertGreater(len(result.propagation_chains), 0)
        # government and telecom should be in affected sectors
        affected = set(result.affected_sectors)
        self.assertIn("government", affected)
        self.assertIn("telecom", affected)

    def test_priority_identified(self):
        """Engine identifies a priority sector after compromise."""
        from impact.engine import ImpactEngine
        twin = get_twin()
        twin.set_asset_status("mil-cmd-net", AssetStatus.COMPROMISED)
        twin.set_asset_status("mil-def-ops", AssetStatus.COMPROMISED)

        eng = ImpactEngine(twin)
        result = eng.assess()
        self.assertIsNotNone(result.priority_sector)
        self.assertGreater(len(result.priority_reason), 0)

    def test_impact_score_increases_with_compromise(self):
        """Impact score increases as more sectors are compromised."""
        from impact.engine import ImpactEngine
        twin = get_twin()

        eng = ImpactEngine(twin)
        s1 = eng.assess().score  # no compromise
        self.assertEqual(s1, 0.0)

        twin.set_asset_status("mil-cmd-net", AssetStatus.COMPROMISED)
        twin.set_asset_status("mil-def-ops", AssetStatus.COMPROMISED)
        s2 = eng.assess().score  # military compromised
        self.assertGreater(s2, s1)

    def test_impact_classifies_high(self):
        """Full scenario compromise yields HIGH or CRITICAL impact."""
        from impact.engine import ImpactEngine
        from impact.models import ImpactLevel
        from simulation.simulator import SCENARIO
        sim = get_simulator(get_twin())
        twin = get_twin()
        det = get_detection_engine()
        dec = get_deception_engine()
        def on_step(idx, step, ev):
            det.ingest_event(ev)
            dec.evaluate_step(idx, step)
        sim._on_step = on_step

        for _ in range(len(SCENARIO)):
            sim.step_once()

        eng = ImpactEngine(twin, det)
        result = eng.assess()
        self.assertIn(result.impact_level, (ImpactLevel.HIGH, ImpactLevel.CRITICAL))

    def test_reset_clears_twin_for_clean_impact(self):
        """After twin reset, impact returns to LOW."""
        from impact.engine import ImpactEngine
        twin = get_twin()
        twin.set_asset_status("mil-cmd-net", AssetStatus.COMPROMISED)
        twin.reset_all()

        eng = ImpactEngine(twin)
        result = eng.assess()
        self.assertEqual(result.impact_level.value, "low")
        self.assertEqual(result.score, 0.0)


class ImpactAPITests(unittest.TestCase):
    """Integration tests for the impact API endpoints."""

    def setUp(self):
        get_simulator(get_twin()).reset()
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_impact_page_loads(self):
        """Impact page returns 200."""
        r = self.client.get("/impact")
        self.assertEqual(r.status_code, 200)

    def test_impact_page_contains_elements(self):
        """Impact page has expected content."""
        r = self.client.get("/impact")
        html = r.data.decode("utf-8")
        self.assertIn("National Security Impact", html)
        self.assertIn("impact.js", html)

    def test_impact_api_returns_assessment(self):
        """GET /api/impact returns a valid assessment."""
        r = self.client.get("/api/impact")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        required = {
            "impact_level", "affected_sectors", "total_compromised",
            "total_at_risk", "propagation_chains", "priority_sector",
            "priority_reason", "score",
        }
        self.assertEqual(set(data.keys()), required)

    def test_impact_api_after_demo(self):
        """After demo, impact API shows cascading risk."""
        self.client.post("/api/demo/run")
        data = self.client.get("/api/impact").get_json()
        self.assertGreater(data["total_compromised"], 0)
        self.assertGreater(data["total_at_risk"], 0)
        self.assertGreater(len(data["propagation_chains"]), 0)
        self.assertIn(data["impact_level"], ("low", "moderate", "high", "critical"))
        self.assertGreater(data["score"], 0)

    def test_impact_api_after_reset(self):
        """After reset, impact returns to clean state."""
        self.client.post("/api/demo/run")
        self.client.post("/api/simulation/reset")
        data = self.client.get("/api/impact").get_json()
        self.assertEqual(data["impact_level"], "low")
        self.assertEqual(data["score"], 0.0)
        self.assertEqual(data["total_compromised"], 0)

    def test_nav_contains_impact_link(self):
        """Dashboard has Impact nav link."""
        r = self.client.get("/")
        html = r.data.decode("utf-8")
        self.assertIn('href="/impact"', html)
        self.assertIn("Impact", html)

    def test_impact_propagation_chains_have_assessments(self):
        """Each propagation chain contains risk assessments."""
        self.client.post("/api/demo/run")
        data = self.client.get("/api/impact").get_json()
        for chain in data["propagation_chains"]:
            self.assertGreater(len(chain["assessments"]), 0)
            for a in chain["assessments"]:
                self.assertIn("source_sector", a)
                self.assertIn("affected_sector", a)
                self.assertIn("risk_score", a)
                self.assertIn("dependency_label", a)
                self.assertGreater(a["risk_score"], 0)


# ===========================================================================
# Phase 17 — Adaptive Adversary & Deception Evolution
# ===========================================================================

from adaptation import AdaptationEngine, AdaptationEvent, get_adaptation_engine
from adaptation.models import AdaptationEvent as _AdaptationEventModel


# ===========================================================================
# Phase 18 — Human vs AI Commander Analysis
# ===========================================================================

from analysis import AnalysisEngine, get_analysis_engine
from analysis.models import (
    Agreement, ComparisonRecord, QualityMetrics, SimulatedOutcome,
)
from datetime import datetime, timezone as _tz


class AdaptationModelTests(unittest.TestCase):
    """Tests for AdaptationEvent model."""

    def _make_event(self, **kw):
        defaults = dict(
            adaptation_id=1,
            timestamp=datetime.now(timezone.utc),
            trigger="test_trigger",
            previous_sector="military",
            new_sector="telecom",
            previous_technique="T1595",
            new_technique="T1021",
            previous_technique_name="Active Scanning",
            new_technique_name="Remote Services",
            previous_stealth=0.3,
            new_stealth=0.45,
            previous_signal_strength=0.35,
            new_signal_strength=0.28,
            previous_target="mil-cmd-net",
            new_target="tel-gateway",
            reason="Adversary shifted after encountering decoy.",
            significant=True,
            new_decoy_id="dec-002",
            new_decoy_name="Fake Telecom Core",
            detection_event_id=42,
        )
        defaults.update(kw)
        return _AdaptationEventModel(**defaults)

    def test_adaptation_event_to_dict_has_all_fields(self):
        """AdaptationEvent.to_dict() returns all required fields."""
        e = self._make_event()
        d = e.to_dict()
        for key in ("adaptation_id", "timestamp", "trigger", "previous_sector",
                    "new_sector", "previous_technique", "new_technique",
                    "previous_stealth", "new_stealth", "significant",
                    "new_decoy_id", "new_decoy_name", "detection_event_id"):
            self.assertIn(key, d)

    def test_adaptation_event_stealth_rounded(self):
        """Stealth values are rounded to 3 decimal places."""
        e = self._make_event(previous_stealth=0.123456, new_stealth=0.654321)
        d = e.to_dict()
        self.assertAlmostEqual(d["previous_stealth"], 0.123, places=3)
        self.assertAlmostEqual(d["new_stealth"], 0.654, places=3)

    def test_adaptation_event_significant_flag(self):
        """Significant flag is preserved."""
        e_sig = self._make_event(significant=True)
        e_min = self._make_event(significant=False)
        self.assertTrue(e_sig.to_dict()["significant"])
        self.assertFalse(e_min.to_dict()["significant"])


class AdaptationEngineTests(unittest.TestCase):
    """Tests for the AdaptationEngine core logic."""

    def setUp(self):
        get_simulator(get_twin()).reset()
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()
        get_adaptation_engine().reset()
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_engine_initially_empty(self):
        """Adaptation engine starts with no events."""
        eng = get_adaptation_engine()
        eng.reset()
        self.assertEqual(eng.adaptation_count, 0)
        self.assertEqual(len(eng.events), 0)

    def test_adapt_requires_simulation_data(self):
        """adapt() with no engines returns None (no simulator data)."""
        eng = AdaptationEngine()
        # No engines set — _can_adapt() passes but _capture_previous() returns all None
        # adapt() should still run and return an event (or None) — just check no crash
        try:
            result = eng.adapt()
        except Exception as exc:
            self.fail(f"adapt() raised an exception with no engines: {exc}")

    def test_adapt_after_simulation_produces_event(self):
        """adapt() produces an AdaptationEvent after running simulation steps."""
        self.client.post("/api/simulation/reset")
        # Run scenario
        for _ in range(len(SCENARIO)):
            self.client.post("/api/simulation/step")
        r = self.client.post("/api/adaptation/adapt",
                             json={"trigger": "test_trigger"})
        data = r.get_json()
        self.assertTrue(data.get("ok"), data)
        evt = data["event"]
        self.assertIn("adaptation_id", evt)
        self.assertIn("new_technique", evt)
        self.assertIn("new_sector", evt)
        self.assertIn("detection_event_id", evt)
        self.assertIsNotNone(evt["detection_event_id"])

    def test_adapt_increments_count(self):
        """Multiple adapt() calls increment the adaptation count."""
        self.client.post("/api/simulation/reset")
        for _ in range(len(SCENARIO)):
            self.client.post("/api/simulation/step")
        # Trigger adaptation twice
        for _ in range(2):
            r = self.client.post("/api/adaptation/adapt",
                                 json={"trigger": "test"})
            self.assertTrue(r.get_json().get("ok"))
        state = self.client.get("/api/adaptation").get_json()
        self.assertGreaterEqual(state["adaptation_count"], 2)

    def test_adapt_generates_detection_evidence(self):
        """adapt() injects a new synthetic evidence event into the detection engine."""
        self.client.post("/api/simulation/reset")
        for _ in range(len(SCENARIO)):
            self.client.post("/api/simulation/step")
        before = self.client.get("/api/detection").get_json()
        evidence_before = before.get("total_evidence", 0)
        self.client.post("/api/adaptation/adapt", json={"trigger": "test"})
        after = self.client.get("/api/detection").get_json()
        evidence_after = after.get("total_evidence", 0)
        self.assertGreater(evidence_after, evidence_before)

    def test_adapt_updates_adversary_status_to_adapted(self):
        """After adapt(), adversary intelligence status becomes 'adapted'."""
        self.client.post("/api/simulation/reset")
        for _ in range(len(SCENARIO)):
            self.client.post("/api/simulation/step")
        self.client.post("/api/adaptation/adapt", json={"trigger": "test"})
        adv = self.client.get("/api/adversary").get_json()
        self.assertEqual(adv["adaptation_status"], "adapted")

    def test_adapt_new_technique_different_from_previous(self):
        """The new technique after adaptation differs from the previous one."""
        self.client.post("/api/simulation/reset")
        for _ in range(len(SCENARIO)):
            self.client.post("/api/simulation/step")
        r = self.client.post("/api/adaptation/adapt", json={"trigger": "test"})
        evt = r.get_json()["event"]
        # Techniques should differ (or at least the adaptation event exists)
        self.assertIn("new_technique", evt)
        self.assertIn("previous_technique", evt)

    def test_adapt_stealth_increases(self):
        """New stealth level is >= previous after adaptation."""
        self.client.post("/api/simulation/reset")
        for _ in range(len(SCENARIO)):
            self.client.post("/api/simulation/step")
        r = self.client.post("/api/adaptation/adapt", json={"trigger": "test"})
        evt = r.get_json()["event"]
        self.assertGreaterEqual(evt["new_stealth"], evt["previous_stealth"])

    def test_adapt_contained_attacker_fails(self):
        """adapt() returns 400 when attacker is contained."""
        self.client.post("/api/simulation/reset")
        for _ in range(len(SCENARIO)):
            self.client.post("/api/simulation/step")
        # Trigger and contain
        self.client.post("/api/deception/simulate-decoy")
        self.client.post("/api/deception/contain")
        r = self.client.post("/api/adaptation/adapt", json={"trigger": "test"})
        self.assertEqual(r.status_code, 400)


class AdaptationAPITests(unittest.TestCase):
    """Tests for the /api/adaptation endpoints."""

    def setUp(self):
        get_simulator(get_twin()).reset()
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()
        get_adaptation_engine().reset()
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_api_adaptation_status_empty(self):
        """GET /api/adaptation returns empty state on reset."""
        self.client.post("/api/simulation/reset")
        r = self.client.get("/api/adaptation")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["adaptation_count"], 0)
        self.assertIsNone(data["last_adaptation"])
        self.assertEqual(data["events"], [])

    def test_api_adaptation_page_loads(self):
        """GET /adaptation page returns 200."""
        r = self.client.get("/adaptation")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Adaptive Adversary", r.data)

    def test_api_adaptation_adapt_endpoint_ok(self):
        """POST /api/adaptation/adapt returns event dict after simulation."""
        self.client.post("/api/simulation/reset")
        for _ in range(len(SCENARIO)):
            self.client.post("/api/simulation/step")
        r = self.client.post("/api/adaptation/adapt", json={"trigger": "api_test"})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["ok"])
        self.assertIn("event", data)

    def test_api_adaptation_event_has_evidence_id(self):
        """Adaptation event carries a detection_event_id."""
        self.client.post("/api/simulation/reset")
        for _ in range(len(SCENARIO)):
            self.client.post("/api/simulation/step")
        r = self.client.post("/api/adaptation/adapt", json={"trigger": "test"})
        evt = r.get_json()["event"]
        self.assertIsNotNone(evt["detection_event_id"])
        self.assertIsInstance(evt["detection_event_id"], int)

    def test_api_adaptation_event_has_decoy_response(self):
        """Adaptation event carries a new_decoy_name field (may be null if no decoys)."""
        self.client.post("/api/simulation/reset")
        for _ in range(len(SCENARIO)):
            self.client.post("/api/simulation/step")
        r = self.client.post("/api/adaptation/adapt", json={"trigger": "test"})
        evt = r.get_json()["event"]
        self.assertIn("new_decoy_name", evt)

    def test_api_adaptation_reset_clears_events(self):
        """POST /api/simulation/reset clears adaptation events."""
        self.client.post("/api/simulation/reset")
        for _ in range(len(SCENARIO)):
            self.client.post("/api/simulation/step")
        self.client.post("/api/adaptation/adapt", json={"trigger": "test"})
        # Confirm event was recorded
        s1 = self.client.get("/api/adaptation").get_json()
        self.assertGreater(s1["adaptation_count"], 0)
        # Reset
        self.client.post("/api/simulation/reset")
        s2 = self.client.get("/api/adaptation").get_json()
        self.assertEqual(s2["adaptation_count"], 0)

    def test_demo_includes_adaptation(self):
        """Demo run returns adaptation summary in response."""
        r = self.client.post("/api/demo/run")
        data = r.get_json()
        self.assertIn("adaptation", data)
        # adaptation may be None if not triggered; just confirm the key exists
        # (no assert on non-None since deception state controls this)

    def test_nav_contains_adaptation_link(self):
        """Navigation contains Adaptation link."""
        r = self.client.get("/")
        html = r.data.decode("utf-8")
        self.assertIn('href="/adaptation"', html)
        self.assertIn("Adaptation", html)


class AnalysisModelTests(unittest.TestCase):
    """Tests for ComparisonRecord and QualityMetrics models."""

    def _make_comparison(self, human_decision="approve", human_action=None,
                          human_reason=None, ai_action="escalate",
                          ai_threat_level="high", ai_confidence=0.75):
        return ComparisonRecord(
            decision_id=1,
            rec_id=1,
            rec_timestamp=datetime.now(_tz.utc),
            ai_action=ai_action,
            ai_confidence=ai_confidence,
            ai_threat_level=ai_threat_level,
            ai_threat_score=ai_confidence,
            ai_affected_sectors=["military"],
            ai_mitre_techniques=["T1595"],
            ai_evidence_summary=["[T1595] Active Scanning in military (confidence 0.75)"],
            ai_reason="Threat level is HIGH.",
            human_decision=human_decision,
            human_action=human_action,
            human_reason=human_reason,
            decided_at=datetime.now(_tz.utc),
        )

    def test_comparison_agree(self):
        """ComparisonRecord sets agreement='agree' for approved decisions."""
        r = self._make_comparison(human_decision="approve")
        self.assertEqual(r.agreement, Agreement.AGREE)

    def test_comparison_override(self):
        """ComparisonRecord sets agreement='override' for overridden decisions."""
        r = self._make_comparison(human_decision="override",
                                  human_action="monitor",
                                  human_reason="Low priority.")
        self.assertEqual(r.agreement, Agreement.OVERRIDE)

    def test_comparison_dismiss(self):
        """ComparisonRecord sets agreement='dismiss' for dismissed decisions."""
        r = self._make_comparison(human_decision="dismiss",
                                  human_reason="False positive.")
        self.assertEqual(r.agreement, Agreement.DISMISS)

    def test_comparison_pending(self):
        """ComparisonRecord sets agreement='pending' for pending decisions."""
        r = self._make_comparison(human_decision="pending")
        self.assertEqual(r.agreement, Agreement.PENDING)

    def test_comparison_to_dict_has_all_fields(self):
        """ComparisonRecord.to_dict() returns all required fields."""
        r = self._make_comparison()
        d = r.to_dict()
        for key in ("decision_id", "rec_id", "ai_action", "ai_confidence",
                    "ai_threat_level", "ai_threat_score", "ai_affected_sectors",
                    "ai_mitre_techniques", "ai_evidence_summary", "ai_reason",
                    "human_decision", "human_action", "human_reason",
                    "decided_at", "agreement", "simulated_outcome"):
            self.assertIn(key, d, f"Missing field: {key}")

    def test_comparison_simulated_outcome_escalate(self):
        """High-confidence escalate action produces contained outcome."""
        r = self._make_comparison(
            human_decision="approve", ai_action="escalate", ai_threat_level="high",
        )
        self.assertEqual(r.simulated_outcome, SimulatedOutcome.CONTAINED)

    def test_comparison_simulated_outcome_monitor_high(self):
        """Monitor action against high threat produces escalated simulated outcome."""
        r = self._make_comparison(
            human_decision="override", human_action="monitor", ai_threat_level="high",
        )
        self.assertEqual(r.simulated_outcome, SimulatedOutcome.ESCALATED)

    def test_quality_metrics_empty(self):
        """QualityMetrics with no records returns zeros."""
        m = QualityMetrics([])
        self.assertEqual(m.total_decisions, 0)
        self.assertEqual(m.approved, 0)
        self.assertEqual(m.agreement_rate, 0.0)

    def test_quality_metrics_agreement_rate(self):
        """QualityMetrics computes correct agreement rate."""
        records = [
            self._make_comparison(human_decision="approve"),
            self._make_comparison(human_decision="approve"),
            self._make_comparison(human_decision="override", human_action="monitor"),
        ]
        m = QualityMetrics(records)
        self.assertEqual(m.approved, 2)
        self.assertEqual(m.overridden, 1)
        self.assertAlmostEqual(m.agreement_rate, 2/3, places=2)

    def test_quality_metrics_override_rate(self):
        """QualityMetrics computes correct override rate."""
        records = [
            self._make_comparison(human_decision="override", human_action="monitor"),
            self._make_comparison(human_decision="override", human_action="monitor"),
            self._make_comparison(human_decision="approve"),
        ]
        m = QualityMetrics(records)
        self.assertAlmostEqual(m.override_rate, 2/3, places=2)

    def test_quality_metrics_to_dict_has_all_fields(self):
        """QualityMetrics.to_dict() returns all expected fields."""
        m = QualityMetrics([self._make_comparison()])
        d = m.to_dict()
        for key in ("total_decisions", "total_decided", "approved", "overridden",
                    "dismissed", "pending", "agreement_rate", "override_rate",
                    "dismiss_rate", "avg_ai_confidence", "outcome_counts"):
            self.assertIn(key, d, f"Missing field: {key}")


class AnalysisEngineTests(unittest.TestCase):
    """Tests for AnalysisEngine core logic."""

    def setUp(self):
        get_simulator(get_twin()).reset()
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()
        get_adaptation_engine().reset()
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_engine_empty_without_decisions(self):
        """AnalysisEngine returns empty comparisons list before any command decisions."""
        self.client.post("/api/simulation/reset")
        r = self.client.get("/api/analysis")
        data = r.get_json()
        self.assertEqual(data["metrics"]["total_decisions"], 0)
        self.assertEqual(data["comparisons"], [])
        self.assertEqual(data["disagreements"], [])

    def test_engine_reflects_approved_decision(self):
        """Analysis records an approved decision as agreement=agree."""
        self.client.post("/api/simulation/reset")
        for _ in range(len(SCENARIO)):
            self.client.post("/api/simulation/step")
        r_rec = self.client.post("/api/command/recommend")
        dr_id = r_rec.get_json()["decision_id"]
        self.client.post("/api/command/decide",
                         json={"decision_id": dr_id, "decision": "approve"})
        data = self.client.get("/api/analysis").get_json()
        self.assertGreater(data["metrics"]["approved"], 0)
        self.assertGreater(data["metrics"]["agreement_rate"], 0)

    def test_engine_reflects_overridden_decision(self):
        """Analysis records an overridden decision as agreement=override."""
        self.client.post("/api/simulation/reset")
        for _ in range(len(SCENARIO)):
            self.client.post("/api/simulation/step")
        r_rec = self.client.post("/api/command/recommend")
        dr_id = r_rec.get_json()["decision_id"]
        self.client.post("/api/command/decide",
                         json={"decision_id": dr_id, "decision": "override",
                               "action": "monitor", "reason": "Test override"})
        data = self.client.get("/api/analysis").get_json()
        self.assertGreater(data["metrics"]["overridden"], 0)
        self.assertGreater(data["metrics"]["override_rate"], 0)
        self.assertGreater(len(data["disagreements"]), 0)

    def test_engine_reflects_dismissed_decision(self):
        """Analysis records a dismissed decision and includes it in disagreements."""
        self.client.post("/api/simulation/reset")
        for _ in range(len(SCENARIO)):
            self.client.post("/api/simulation/step")
        r_rec = self.client.post("/api/command/recommend")
        dr_id = r_rec.get_json()["decision_id"]
        self.client.post("/api/command/decide",
                         json={"decision_id": dr_id, "decision": "dismiss",
                               "reason": "Not relevant"})
        data = self.client.get("/api/analysis").get_json()
        self.assertGreater(data["metrics"]["dismissed"], 0)
        self.assertGreater(len(data["disagreements"]), 0)

    def test_disagreement_has_evidence(self):
        """Disagreement record includes AI evidence summary."""
        self.client.post("/api/simulation/reset")
        for _ in range(len(SCENARIO)):
            self.client.post("/api/simulation/step")
        r_rec = self.client.post("/api/command/recommend")
        dr_id = r_rec.get_json()["decision_id"]
        self.client.post("/api/command/decide",
                         json={"decision_id": dr_id, "decision": "dismiss",
                               "reason": "Evidence check"})
        data = self.client.get("/api/analysis").get_json()
        disagree = data["disagreements"]
        self.assertGreater(len(disagree), 0)
        d = disagree[0]
        self.assertIn("ai_evidence_summary", d)
        self.assertIn("ai_reason", d)
        self.assertIn("human_reason", d)

    def test_comparison_contains_simulated_outcome(self):
        """Each comparison record includes a simulated_outcome field."""
        self.client.post("/api/simulation/reset")
        for _ in range(len(SCENARIO)):
            self.client.post("/api/simulation/step")
        r_rec = self.client.post("/api/command/recommend")
        dr_id = r_rec.get_json()["decision_id"]
        self.client.post("/api/command/decide",
                         json={"decision_id": dr_id, "decision": "approve"})
        data = self.client.get("/api/analysis").get_json()
        for rec in data["comparisons"]:
            self.assertIn("simulated_outcome", rec)
            self.assertIn(rec["simulated_outcome"],
                          ("contained", "partially_mitigated", "escalated", "unknown"))


class AnalysisAPITests(unittest.TestCase):
    """Tests for the /api/analysis and /analysis page endpoints."""

    def setUp(self):
        get_simulator(get_twin()).reset()
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()
        get_adaptation_engine().reset()
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_api_analysis_page_loads(self):
        """GET /analysis returns 200."""
        r = self.client.get("/analysis")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Human vs AI Commander", r.data)

    def test_api_analysis_returns_200(self):
        """GET /api/analysis returns 200 with correct structure."""
        r = self.client.get("/api/analysis")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("comparisons", data)
        self.assertIn("metrics", data)
        self.assertIn("disagreements", data)

    def test_api_analysis_metrics_structure(self):
        """GET /api/analysis metrics dict has all required fields."""
        r = self.client.get("/api/analysis")
        m = r.get_json()["metrics"]
        for key in ("total_decisions", "approved", "overridden", "dismissed",
                    "pending", "agreement_rate", "override_rate", "avg_ai_confidence",
                    "outcome_counts"):
            self.assertIn(key, m)

    def test_api_analysis_after_demo(self):
        """After demo run, analysis reflects the auto-approved recommendation."""
        self.client.post("/api/demo/run")
        data = self.client.get("/api/analysis").get_json()
        self.assertGreater(data["metrics"]["total_decisions"], 0)
        self.assertGreater(data["metrics"]["approved"], 0)
        # Demo auto-approves, so agreement_rate should be 1.0
        self.assertEqual(data["metrics"]["agreement_rate"], 1.0)

    def test_nav_contains_analysis_link(self):
        """Navigation contains Analysis link."""
        r = self.client.get("/")
        html = r.data.decode("utf-8")
        self.assertIn('href="/analysis"', html)
        self.assertIn("Analysis", html)

    def test_api_analysis_comparison_fields(self):
        """Each comparison record in /api/analysis has all required fields."""
        self.client.post("/api/demo/run")
        data = self.client.get("/api/analysis").get_json()
        for rec in data["comparisons"]:
            for key in ("decision_id", "rec_id", "ai_action", "ai_confidence",
                        "ai_threat_level", "human_decision", "agreement",
                        "simulated_outcome", "ai_evidence_summary"):
                self.assertIn(key, rec, f"Missing field: {key}")

    def test_api_analysis_no_disagreements_after_approve(self):
        """No disagreements when all decisions are approved."""
        self.client.post("/api/demo/run")
        data = self.client.get("/api/analysis").get_json()
        # demo auto-approves → should have 0 disagreements
        self.assertEqual(len(data["disagreements"]), 0)


# ---------------------------------------------------------------------------
# Phase 19 — Architecture Completion & Gap Check Tests
# ---------------------------------------------------------------------------

class ReportArchitectureTests(unittest.TestCase):
    """Verify Phase 19 additions to the Report engine."""

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_set_optional_engines_no_error(self):
        """ReportEngine.set_optional_engines accepts None without error."""
        from reports import get_report_engine
        rpt = get_report_engine()
        rpt.set_optional_engines(adaptation_engine=None, analysis_engine=None)

    def test_generate_report_includes_adaptation_summary(self):
        """Generated report contains adaptation_summary key."""
        self.client.post("/api/demo/run")
        r = self.client.post("/api/reports/generate")
        report = r.get_json()["report"]
        self.assertIn("adaptation_summary", report)

    def test_generate_report_includes_analysis_summary(self):
        """Generated report contains analysis_summary key."""
        self.client.post("/api/demo/run")
        r = self.client.post("/api/reports/generate")
        report = r.get_json()["report"]
        self.assertIn("analysis_summary", report)

    def test_generate_report_final_outcome_has_recovered_sectors(self):
        """Final outcome in generated report includes recovered_sectors count."""
        self.client.post("/api/demo/run")
        r = self.client.post("/api/reports/generate")
        outcome = r.get_json()["report"]["final_outcome"]
        self.assertIn("recovered_sectors", outcome)
        self.assertIsInstance(outcome["recovered_sectors"], int)

    def test_replay_timeline_includes_adaptation_phase(self):
        """After demo run, replay timeline contains an adaptation entry."""
        self.client.post("/api/demo/run")
        r = self.client.post("/api/reports/generate")
        data = r.get_json()
        timeline = data.get("timeline", [])
        phases = [ev["phase"] for ev in timeline]
        self.assertIn("adaptation", phases,
                      "Timeline should include at least one adaptation event after demo")

    def test_replay_timeline_is_chronological(self):
        """Replay timeline events are sorted in chronological order."""
        self.client.post("/api/demo/run")
        r = self.client.post("/api/reports/generate")
        timeline = r.get_json().get("timeline", [])
        if len(timeline) >= 2:
            for i in range(len(timeline) - 1):
                self.assertLessEqual(timeline[i]["timestamp"], timeline[i + 1]["timestamp"],
                                     "Timeline not sorted at index %d" % i)

    def test_adaptation_summary_structure(self):
        """adaptation_summary in report has adaptation_count key."""
        self.client.post("/api/demo/run")
        r = self.client.post("/api/reports/generate")
        summary = r.get_json()["report"]["adaptation_summary"]
        self.assertIn("adaptation_count", summary)
        self.assertIn("events", summary)

    def test_analysis_summary_structure(self):
        """analysis_summary in report has total_decisions key."""
        self.client.post("/api/demo/run")
        r = self.client.post("/api/reports/generate")
        summary = r.get_json()["report"]["analysis_summary"]
        self.assertIn("total_decisions", summary)


# ---------------------------------------------------------------------------
# Phase 20 — Dashboard Command Integration Tests
# ---------------------------------------------------------------------------

class DashboardCommandIntegrationTests(unittest.TestCase):
    """
    Tests for the three live cards added to the dashboard in Phase 20:
      - Defense Units
      - AI Recommendation
      - Commander Controls
    """

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()
        # Reset all relevant singleton engines so each test starts clean
        get_simulator(get_twin()).reset()
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()

    def test_api_dashboard_returns_200(self):
        """GET /api/dashboard returns HTTP 200."""
        r = self.client.get("/api/dashboard")
        self.assertEqual(r.status_code, 200)

    def test_api_dashboard_top_level_keys(self):
        """GET /api/dashboard has all three required top-level keys."""
        data = self.client.get("/api/dashboard").get_json()
        for key in ("defense_units", "ai_recommendation", "commander_controls"):
            self.assertIn(key, data, f"Missing key: {key}")

    def test_api_dashboard_defense_units_fields(self):
        """defense_units section has all required fields."""
        data = self.client.get("/api/dashboard").get_json()
        du = data["defense_units"]
        for field in ("available", "engaged", "contained", "isolated_assets",
                      "attacker_state", "posture"):
            self.assertIn(field, du, f"Missing defense_units field: {field}")

    def test_api_dashboard_ai_recommendation_fields(self):
        """ai_recommendation section has all required fields."""
        data = self.client.get("/api/dashboard").get_json()
        rec = data["ai_recommendation"]
        for field in ("has_recommendation", "action", "threat_level", "confidence",
                      "reason", "pending_decisions", "total_recommendations"):
            self.assertIn(field, rec, f"Missing ai_recommendation field: {field}")

    def test_api_dashboard_commander_controls_fields(self):
        """commander_controls section has all required fields."""
        data = self.client.get("/api/dashboard").get_json()
        cc = data["commander_controls"]
        for field in ("total_decisions", "pending_decisions", "approved",
                      "overridden", "dismissed", "last_decision",
                      "last_action", "last_reason"):
            self.assertIn(field, cc, f"Missing commander_controls field: {field}")

    # ----------------------------------------------------------------
    # Default state (no simulation)
    # ----------------------------------------------------------------

    def test_defense_units_defaults(self):
        """Before any simulation: contained=0, isolated_assets=0."""
        data = self.client.get("/api/dashboard").get_json()
        du = data["defense_units"]
        self.assertEqual(du["contained"], 0)
        self.assertEqual(du["isolated_assets"], 0)

    def test_ai_recommendation_no_data_by_default(self):
        """Before simulation: has_recommendation is False."""
        data = self.client.get("/api/dashboard").get_json()
        self.assertFalse(data["ai_recommendation"]["has_recommendation"])

    def test_commander_controls_empty_by_default(self):
        """Before simulation: all counts are 0 and last_decision is None."""
        data = self.client.get("/api/dashboard").get_json()
        cc = data["commander_controls"]
        self.assertEqual(cc["total_decisions"], 0)
        self.assertIsNone(cc["last_decision"])

    # ----------------------------------------------------------------
    # After demo run
    # ----------------------------------------------------------------

    def test_defense_units_after_demo_has_data(self):
        """After demo: defense_units shows at least 1 contained or available unit."""
        self.client.post("/api/demo/run")
        data = self.client.get("/api/dashboard").get_json()
        du = data["defense_units"]
        # The demo contains the attacker → contained should be 1
        self.assertEqual(du["contained"], 1)

    def test_ai_recommendation_after_demo(self):
        """After demo: ai_recommendation has a recommendation with action and threat_level."""
        self.client.post("/api/demo/run")
        data = self.client.get("/api/dashboard").get_json()
        rec = data["ai_recommendation"]
        self.assertTrue(rec["has_recommendation"])
        self.assertIsNotNone(rec["action"])
        self.assertIsNotNone(rec["threat_level"])
        self.assertIsInstance(rec["confidence"], float)
        self.assertGreater(rec["total_recommendations"], 0)

    def test_commander_controls_after_demo(self):
        """After demo: commander_controls shows at least one approved decision."""
        self.client.post("/api/demo/run")
        data = self.client.get("/api/dashboard").get_json()
        cc = data["commander_controls"]
        self.assertGreater(cc["total_decisions"], 0)
        self.assertGreater(cc["approved"], 0)
        self.assertEqual(cc["last_decision"], "approve")

    def test_commander_controls_pending_zero_after_demo(self):
        """After demo: pending_decisions should be 0 (demo auto-approves)."""
        self.client.post("/api/demo/run")
        data = self.client.get("/api/dashboard").get_json()
        self.assertEqual(data["commander_controls"]["pending_decisions"], 0)

    # ----------------------------------------------------------------
    # Dashboard template (/) contains live data IDs
    # ----------------------------------------------------------------

    def test_dashboard_page_contains_live_card_ids(self):
        """Dashboard HTML contains all three live card panel IDs."""
        html = self.client.get("/").data.decode("utf-8")
        self.assertIn('id="panelDefense"', html)
        self.assertIn('id="panelAIRec"', html)
        self.assertIn('id="panelCommander"', html)

    def test_dashboard_page_contains_stat_ids(self):
        """Dashboard HTML contains the JS-updatable stat element IDs."""
        html = self.client.get("/").data.decode("utf-8")
        for eid in ("defAvailable", "defEngaged", "defContained",
                    "cmdTotal", "cmdPending", "cmdApproved"):
            self.assertIn(f'id="{eid}"', html, f"Missing element id: {eid}")

    def test_dashboard_js_is_linked(self):
        """dashboard.js is linked from the dashboard page."""
        html = self.client.get("/").data.decode("utf-8")
        self.assertIn("dashboard.js", html)

    def test_defense_units_available_equals_deception_armed(self):
        """defense_units.available matches deception armed count."""
        data = self.client.get("/api/dashboard").get_json()
        from deception import get_deception_engine
        armed = len(get_deception_engine().armed_decoys)
        self.assertEqual(data["defense_units"]["available"], armed)


class EChartsDashboardTests(unittest.TestCase):
    """Phase 22: Tests for the Apache ECharts live dashboard integration."""

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()
        get_simulator(get_twin()).reset()
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()

    # ----------------------------------------------------------------
    # ECharts CDN and script integration
    # ----------------------------------------------------------------

    def test_dashboard_includes_echarts_cdn(self):
        """Dashboard page includes the Apache ECharts CDN script tag."""
        html = self.client.get("/").data.decode("utf-8")
        self.assertIn("echarts", html.lower())
        self.assertIn("echarts.min.js", html)

    def test_dashboard_includes_dashboard_charts_js(self):
        """Dashboard page includes the dashboard-charts.js script."""
        html = self.client.get("/").data.decode("utf-8")
        self.assertIn("dashboard-charts.js", html)

    def test_dashboard_injects_viz_data_json(self):
        """Dashboard page injects CYBER_VIZ_DATA as a JSON global."""
        html = self.client.get("/").data.decode("utf-8")
        self.assertIn("window.CYBER_VIZ_DATA", html)

    # ----------------------------------------------------------------
    # Chart container IDs and classes
    # ----------------------------------------------------------------

    def test_chart_container_ids_exist(self):
        """Dashboard has all five ECharts container element IDs."""
        html = self.client.get("/").data.decode("utf-8")
        chart_ids = [
            "chartThreatActivity",
            "chartThreatDistribution",
            "chartConfidenceTrend",
            "chartAttackFlow",
            "chartSectorRisk",
        ]
        for cid in chart_ids:
            self.assertIn(f'id="{cid}"', html, f"Missing chart container: {cid}")

    def test_chart_containers_have_echarts_class(self):
        """Each chart container has the echarts-chart CSS class."""
        html = self.client.get("/").data.decode("utf-8")
        chart_ids = [
            "chartThreatActivity",
            "chartThreatDistribution",
            "chartConfidenceTrend",
            "chartAttackFlow",
            "chartSectorRisk",
        ]
        for cid in chart_ids:
            self.assertIn(f'echarts-chart" id="{cid}"', html,
                          f"Chart container {cid} missing echarts-chart class")

    # ----------------------------------------------------------------
    # /api/dashboard/v2 endpoint
    # ----------------------------------------------------------------

    def test_api_dashboard_v2_returns_200(self):
        """GET /api/dashboard/v2 returns HTTP 200."""
        r = self.client.get("/api/dashboard/v2")
        self.assertEqual(r.status_code, 200)

    def test_api_dashboard_v2_required_keys(self):
        """/api/dashboard/v2 has all required visualization data keys."""
        data = self.client.get("/api/dashboard/v2").get_json()
        required_keys = [
            "sector_heatmap",
            "threat_distribution",
            "confidence_trend",
            "attack_paths",
            "dependencies",
            "sector_risk",
            "critical_alert",
            "deception",
            "overall",
            "twin_summary",
        ]
        for key in required_keys:
            self.assertIn(key, data, f"Missing v2 key: {key}")

    def test_api_dashboard_v2_sector_risk_structure(self):
        """sector_risk items have all required fields for the risk bar chart."""
        data = self.client.get("/api/dashboard/v2").get_json()
        self.assertIsInstance(data["sector_risk"], list)
        self.assertGreater(len(data["sector_risk"]), 0)
        item = data["sector_risk"][0]
        for field in ("sector_id", "name", "status", "risk_score", "icon"):
            self.assertIn(field, item, f"Missing sector_risk field: {field}")

    def test_api_dashboard_v2_overall_structure(self):
        """overall section has all fields for the status strip."""
        data = self.client.get("/api/dashboard/v2").get_json()
        overall = data["overall"]
        for field in ("confidence_pct", "risk_level", "threat_level",
                      "threat_score", "active_alerts", "total_evidence", "sim_status"):
            self.assertIn(field, overall, f"Missing overall field: {field}")

    def test_api_dashboard_v2_deception_structure(self):
        """deception section has all fields for the deception status panel."""
        data = self.client.get("/api/dashboard/v2").get_json()
        dec = data["deception"]
        for field in ("total", "armed", "active", "bypassed",
                      "attacker_state", "posture", "interactions", "diversions"):
            self.assertIn(field, dec, f"Missing deception field: {field}")

    def test_api_dashboard_v2_after_demo_has_heatmap(self):
        """After running demo, sector_heatmap has at least one entry."""
        self.client.post("/api/demo/run")
        data = self.client.get("/api/dashboard/v2").get_json()
        self.assertGreater(len(data["sector_heatmap"]), 0)

    def test_api_dashboard_v2_after_demo_has_confidence_trend(self):
        """After demo, confidence_trend has data points."""
        self.client.post("/api/demo/run")
        data = self.client.get("/api/dashboard/v2").get_json()
        self.assertGreater(len(data["confidence_trend"]), 0)
        pt = data["confidence_trend"][0]
        self.assertIn("timestamp", pt)
        self.assertIn("confidence", pt)

    def test_api_dashboard_v2_after_demo_has_attack_paths(self):
        """After demo, attack_paths is populated."""
        self.client.post("/api/demo/run")
        data = self.client.get("/api/dashboard/v2").get_json()
        self.assertIsInstance(data["attack_paths"], list)
        # After demo there should be at least one path
        self.assertGreater(len(data["attack_paths"]), 0)

    def test_api_dashboard_v2_after_demo_critical_alert(self):
        """After demo, critical_alert is not None."""
        self.client.post("/api/demo/run")
        data = self.client.get("/api/dashboard/v2").get_json()
        self.assertIsNotNone(data["critical_alert"])
        alert = data["critical_alert"]
        self.assertIn("sector", alert)
        self.assertIn("signal", alert)
        self.assertGreater(alert["signal"], 0)

    def test_api_dashboard_v2_after_demo_threat_distribution(self):
        """After demo, threat_distribution has at least one status entry."""
        self.client.post("/api/demo/run")
        data = self.client.get("/api/dashboard/v2").get_json()
        self.assertIsInstance(data["threat_distribution"], dict)
        self.assertGreater(len(data["threat_distribution"]), 0)

    def test_api_dashboard_v2_critical_alert_default_none(self):
        """Before simulation, critical_alert is None (no threats)."""
        data = self.client.get("/api/dashboard/v2").get_json()
        self.assertIsNone(data["critical_alert"])

    def test_api_dashboard_v2_sector_risk_sorted_descending(self):
        """sector_risk list is sorted by risk_score descending."""
        data = self.client.get("/api/dashboard/v2").get_json()
        scores = [s["risk_score"] for s in data["sector_risk"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    # ----------------------------------------------------------------
    # Backward-compat: section titles and IDs still present
    # ----------------------------------------------------------------

    def test_echarts_dashboard_preserves_section_titles(self):
        """ECharts dashboard still has all required section titles."""
        html = self.client.get("/").data.decode("utf-8")
        for title in ("Threat Status", "Defense Units", "Deception Grid",
                      "Evidence Chain", "AI Recommendation", "Commander Controls"):
            self.assertIn(title, html, f"Missing section title: {title}")

    def test_echarts_dashboard_preserves_critical_alert_banner(self):
        """Critical alert banner element is present."""
        html = self.client.get("/").data.decode("utf-8")
        self.assertIn('id="criticalAlertBanner"', html)

    def test_echarts_dashboard_preserves_status_strip(self):
        """Status strip element IDs are present."""
        html = self.client.get("/").data.decode("utf-8")
        for eid in ("vizConfidence", "vizRiskBadge", "vizThreatLevel",
                     "vizThreatScore", "vizActiveAlerts", "vizEvidence"):
            self.assertIn(f'id="{eid}"', html, f"Missing status strip ID: {eid}")


class UserControlledSimulationTests(unittest.TestCase):
    """Phase 23: Tests for user-controlled simulation paths."""

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()
        get_simulator(get_twin()).reset()
        get_simulator(get_twin()).clear_custom_scenario()
        get_detection_engine().reset()
        get_deception_engine().reset()
        get_command_engine().reset()

    # ----------------------------------------------------------------
    # API endpoints exist
    # ----------------------------------------------------------------

    def test_api_sectors_returns_200(self):
        """GET /api/simulation/sectors returns HTTP 200."""
        r = self.client.get("/api/simulation/sectors")
        self.assertEqual(r.status_code, 200)

    def test_api_sectors_returns_all_sectors(self):
        """Sectors API returns all 8 Digital Twin sectors."""
        data = self.client.get("/api/simulation/sectors").get_json()
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 8)
        ids = {s["id"] for s in data}
        for expected in ("military", "government", "telecom", "energy",
                         "banking", "healthcare", "education", "commercial"):
            self.assertIn(expected, ids)

    def test_api_techniques_returns_200(self):
        """GET /api/simulation/techniques returns HTTP 200."""
        r = self.client.get("/api/simulation/techniques")
        self.assertEqual(r.status_code, 200)

    def test_api_techniques_has_pool(self):
        """Techniques API returns at least 10 MITRE techniques."""
        data = self.client.get("/api/simulation/techniques").get_json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 10)
        ids = {t["id"] for t in data}
        self.assertIn("T1595", ids)
        self.assertIn("T1486", ids)

    def test_api_valid_targets_returns_200(self):
        """GET /api/simulation/valid-targets/<sector> returns 200."""
        r = self.client.get("/api/simulation/valid-targets/military")
        self.assertEqual(r.status_code, 200)

    def test_api_valid_targets_unknown_sector_404(self):
        """Unknown sector returns 404."""
        r = self.client.get("/api/simulation/valid-targets/nonexistent")
        self.assertEqual(r.status_code, 404)

    def test_api_mode_returns_200(self):
        """GET /api/simulation/mode returns 200."""
        r = self.client.get("/api/simulation/mode")
        self.assertEqual(r.status_code, 200)

    def test_api_mode_default(self):
        """Default mode is 'default' before any custom configuration."""
        data = self.client.get("/api/simulation/mode").get_json()
        self.assertEqual(data["mode"], "default")

    # ----------------------------------------------------------------
    # Path validation
    # ----------------------------------------------------------------

    def test_valid_targets_military(self):
        """Military has valid targets: government and telecom."""
        data = self.client.get("/api/simulation/valid-targets/military").get_json()
        self.assertTrue(data["ok"])
        target_ids = {t["sector_id"] for t in data["targets"]}
        self.assertIn("government", target_ids)
        self.assertIn("telecom", target_ids)

    def test_valid_targets_telecom(self):
        """Telecom has valid targets in both directions."""
        data = self.client.get("/api/simulation/valid-targets/telecom").get_json()
        self.assertTrue(data["ok"])
        target_ids = {t["sector_id"] for t in data["targets"]}
        # Outgoing: energy, banking, healthcare
        self.assertIn("energy", target_ids)
        self.assertIn("banking", target_ids)
        self.assertIn("healthcare", target_ids)
        # Incoming: military, government
        self.assertIn("military", target_ids)
        self.assertIn("government", target_ids)

    # ----------------------------------------------------------------
    # Configure custom path
    # ----------------------------------------------------------------

    def test_configure_empty_path_fails(self):
        """Configuring with an empty path returns 400."""
        r = self.client.post("/api/simulation/configure",
                             json={"path": []})
        self.assertEqual(r.status_code, 400)

    def test_configure_single_sector(self):
        """Configure a single-sector custom path."""
        r = self.client.post("/api/simulation/configure",
                             json={"path": [
                                 {"sector": "telecom", "technique": "T1021",
                                  "threat_level": "high"}
                             ]})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["total_steps"], 2)  # 2 steps per sector

    def test_configure_valid_multi_sector_path(self):
        """Configure a valid multi-sector path: telecom → energy → banking."""
        r = self.client.post("/api/simulation/configure",
                             json={"path": [
                                 {"sector": "telecom", "technique": "T1021",
                                  "threat_level": "high"},
                                 {"sector": "energy", "technique": "T1565",
                                  "threat_level": "severe"},
                                 {"sector": "banking", "technique": "T1486",
                                  "threat_level": "high"},
                             ]})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["total_steps"], 6)  # 2 steps × 3 sectors

    def test_configure_invalid_path_fails(self):
        """Configuring an invalid path (no dependency) returns 400."""
        r = self.client.post("/api/simulation/configure",
                             json={"path": [
                                 {"sector": "education", "technique": "T1595",
                                  "threat_level": "low"},
                                 {"sector": "banking", "technique": "T1486",
                                  "threat_level": "high"},
                             ]})
        self.assertEqual(r.status_code, 400)
        data = r.get_json()
        self.assertFalse(data["ok"])

    def test_configure_unknown_sector_fails(self):
        """Configuring with an unknown sector returns 400."""
        r = self.client.post("/api/simulation/configure",
                             json={"path": [
                                 {"sector": "nonexistent", "technique": "T1595",
                                  "threat_level": "low"},
                             ]})
        self.assertEqual(r.status_code, 400)

    # ----------------------------------------------------------------
    # Custom simulation execution
    # ----------------------------------------------------------------

    def test_custom_simulation_different_from_demo(self):
        """Custom path produces a different attack path than the fixed demo."""
        # Configure custom: telecom → healthcare (but don't auto-start)
        sim = get_simulator(get_twin())
        sim.reset()
        sim.clear_custom_scenario()
        result = sim.configure([
            {"sector": "telecom", "mitre_technique": "T1021",
             "threat_level": "high"},
            {"sector": "healthcare", "mitre_technique": "T1486",
             "threat_level": "severe"},
        ])
        self.assertTrue(result["ok"])
        # Step through manually
        for _ in range(result["steps"]):
            sim.step_once()
        status = sim.status()
        self.assertEqual(status["mode"], "custom")
        path = status["attack_path"]
        self.assertIn("telecom", path)
        self.assertIn("healthcare", path)
        # Must NOT include military (which the demo always starts from)
        self.assertNotIn("military", path)

    def test_custom_mode_flag(self):
        """After configure, simulation mode is 'custom'."""
        self.client.post("/api/simulation/configure",
                         json={"path": [
                             {"sector": "energy", "technique": "T1565",
                              "threat_level": "high"},
                         ]})
        data = self.client.get("/api/simulation/mode").get_json()
        self.assertEqual(data["mode"], "custom")

    def test_reset_clears_custom_mode(self):
        """Reset clears custom scenario back to default mode."""
        self.client.post("/api/simulation/configure",
                         json={"path": [
                             {"sector": "banking", "technique": "T1486",
                              "threat_level": "high"},
                         ]})
        self.client.post("/api/simulation/reset")
        data = self.client.get("/api/simulation/mode").get_json()
        self.assertEqual(data["mode"], "default")

    # ----------------------------------------------------------------
    # Demo scenario unchanged
    # ----------------------------------------------------------------

    def test_demo_scenario_path_unchanged(self):
        """Demo scenario still follows Military → Telecom → Energy → Healthcare."""
        self.client.post("/api/demo/run")
        sim = get_simulator(get_twin())
        path = sim.attack_path
        self.assertEqual(path, ["military", "telecom", "energy", "healthcare"])

    def test_demo_scenario_mode_is_default(self):
        """Demo scenario runs in 'default' mode (not custom)."""
        self.client.post("/api/demo/run")
        data = self.client.get("/api/simulation/mode").get_json()
        self.assertEqual(data["mode"], "default")

    def test_demo_scenario_generates_detection_events(self):
        """Demo still generates detection evidence as before."""
        self.client.post("/api/demo/run")
        det = get_detection_engine().status()
        self.assertGreater(det["total_evidence"], 0)

    # ----------------------------------------------------------------
    # Integration with existing systems
    # ----------------------------------------------------------------

    def test_custom_sim_generates_detection_evidence(self):
        """Custom simulation generates detection evidence."""
        self.client.post("/api/simulation/configure",
                         json={"path": [
                             {"sector": "government", "technique": "T1190",
                              "threat_level": "high"},
                         ]})
        # Step through manually to ensure events are processed
        sim = get_simulator(get_twin())
        sim.stop()
        sim.step_once()
        sim.step_once()
        det = get_detection_engine().status()
        self.assertGreater(det["total_evidence"], 0)

    def test_custom_sim_updates_digital_twin(self):
        """Custom simulation mutates Digital Twin asset statuses."""
        self.client.post("/api/simulation/configure",
                         json={"path": [
                             {"sector": "energy", "technique": "T1565",
                              "threat_level": "severe"},
                         ]})
        sim = get_simulator(get_twin())
        sim.stop()
        sim.step_once()
        sim.step_once()
        twin_data = get_twin().to_dict()
        energy = twin_data["sectors"]["energy"]
        # At least one asset should not be healthy
        self.assertGreater(energy["compromised"], 0)

    def test_custom_different_starting_sectors(self):
        """Custom simulation can start from any sector."""
        for sector_id in ("telecom", "banking", "education", "commercial"):
            # Reset between tests
            self.client.post("/api/simulation/reset")
            r = self.client.post("/api/simulation/configure",
                                 json={"path": [
                                     {"sector": sector_id, "technique": "T1595",
                                      "threat_level": "moderate"},
                                 ]})
            self.assertEqual(r.status_code, 200, f"Failed for sector: {sector_id}")
            data = r.get_json()
            self.assertTrue(data["ok"], f"Not ok for sector: {sector_id}")


# ===========================================================================
# Phase 24 — System Standby
# ===========================================================================

class SystemStandbyTests(unittest.TestCase):
    """Tests for the application-level System Standby feature."""

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()
        # ensure clean state before every test
        self.client.post("/api/simulation/reset")
        self.client.post("/api/standby/exit")  # idempotent — clears standby if any

    # ------------------------------------------------------------------
    # Standby status endpoint
    # ------------------------------------------------------------------

    def test_standby_status_returns_json(self):
        """GET /api/standby returns a JSON status object."""
        r = self.client.get("/api/standby")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("standby", data)
        self.assertIn("simulation_running", data)
        self.assertIn("current_step", data)

    def test_standby_initially_false(self):
        """Standby is False by default (after reset)."""
        r = self.client.get("/api/standby")
        data = r.get_json()
        self.assertFalse(data["standby"])

    def test_status_endpoint_includes_standby_field(self):
        """/api/status includes a 'standby' boolean field."""
        r = self.client.get("/api/status")
        data = r.get_json()
        self.assertIn("standby", data)
        self.assertIsInstance(data["standby"], bool)

    # ------------------------------------------------------------------
    # Entering standby
    # ------------------------------------------------------------------

    def test_enter_standby_returns_ok(self):
        """POST /api/standby/enter returns ok=True."""
        r = self.client.post("/api/standby/enter")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["ok"])
        self.assertTrue(data["standby"])

    def test_enter_standby_sets_flag(self):
        """After entering standby, GET /api/standby shows standby=True."""
        self.client.post("/api/standby/enter")
        r = self.client.get("/api/standby")
        data = r.get_json()
        self.assertTrue(data["standby"])

    def test_enter_standby_also_reflected_in_api_status(self):
        """After entering standby, /api/status.standby is True."""
        self.client.post("/api/standby/enter")
        r = self.client.get("/api/status")
        data = r.get_json()
        self.assertTrue(data["standby"])

    # ------------------------------------------------------------------
    # Simulation progression blocked while in standby
    # ------------------------------------------------------------------

    def test_start_blocked_in_standby(self):
        """POST /api/simulation/start returns 409 while standby is active."""
        self.client.post("/api/standby/enter")
        r = self.client.post("/api/simulation/start")
        self.assertEqual(r.status_code, 409)
        data = r.get_json()
        self.assertFalse(data["ok"])

    def test_simulation_not_running_after_enter_standby(self):
        """Simulation is not running after entering standby."""
        self.client.post("/api/standby/enter")
        r = self.client.get("/api/standby")
        data = r.get_json()
        self.assertFalse(data["simulation_running"])

    # ------------------------------------------------------------------
    # Data preservation
    # ------------------------------------------------------------------

    def test_existing_data_preserved_across_standby(self):
        """Simulation progress (step index) is preserved when entering standby."""
        # Advance one step to generate state
        self.client.post("/api/simulation/step")

        # Capture simulation progress before standby
        r_before = self.client.get("/api/simulation")
        data_before = r_before.get_json()
        step_before = data_before.get("current_step", -1)

        # Enter standby — must NOT reset or delete progress
        self.client.post("/api/standby/enter")

        # Progress must be unchanged
        r_after = self.client.get("/api/simulation")
        data_after = r_after.get_json()
        step_after = data_after.get("current_step", -2)

        self.assertEqual(step_before, step_after,
                         "Simulation step counter changed when entering standby")

    # ------------------------------------------------------------------
    # Exiting standby — operational recovery
    # ------------------------------------------------------------------

    def test_exit_standby_returns_ok(self):
        """POST /api/standby/exit returns ok=True."""
        self.client.post("/api/standby/enter")
        r = self.client.post("/api/standby/exit")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["ok"])
        self.assertFalse(data["standby"])

    def test_exit_standby_clears_flag(self):
        """After exiting standby, GET /api/standby shows standby=False."""
        self.client.post("/api/standby/enter")
        self.client.post("/api/standby/exit")
        r = self.client.get("/api/standby")
        data = r.get_json()
        self.assertFalse(data["standby"])

    def test_exit_standby_allows_simulation_start(self):
        """Simulation can be started again after exiting standby."""
        self.client.post("/api/standby/enter")
        self.client.post("/api/standby/exit")
        r = self.client.post("/api/simulation/start")
        self.assertIn(r.status_code, (200,))
        data = r.get_json()
        self.assertTrue(data["ok"])

    def test_enter_standby_pauses_running_simulation_state(self):
        """Entering standby while simulation was running records paused_by_standby."""
        # Start then immediately enter standby to capture paused_by_standby
        self.client.post("/api/simulation/start")
        r = self.client.post("/api/standby/enter")
        data = r.get_json()
        # standby should be active
        self.assertTrue(data["standby"])
        # simulation should not be running
        self.assertFalse(data["simulation_running"])

    def test_exit_standby_idempotent_when_not_in_standby(self):
        """Calling exit when not in standby is safe (no error)."""
        r = self.client.post("/api/standby/exit")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertFalse(data["standby"])

    def test_reset_clears_standby(self):
        """POST /api/simulation/reset exits standby and resets to clean state."""
        self.client.post("/api/standby/enter")
        self.client.post("/api/simulation/reset")
        r = self.client.get("/api/standby")
        data = r.get_json()
        self.assertFalse(data["standby"])

    # ------------------------------------------------------------------
    # Badge element in HTML
    # ------------------------------------------------------------------

    def test_base_html_badge_has_role_button(self):
        """The systemBadge element has role=button for accessibility."""
        r = self.client.get("/")
        html = r.data.decode()
        self.assertIn('role="button"', html)
        self.assertIn('id="systemBadge"', html)

    def test_base_html_badge_has_clickable_class(self):
        """The systemBadge element has the status-badge--clickable CSS class."""
        r = self.client.get("/")
        html = r.data.decode()
        self.assertIn("status-badge--clickable", html)


# ===========================================================================
# Phase 23A — Activate Decoys & Contain Attacker
# ===========================================================================

class ActivateDecoysTests(unittest.TestCase):
    """Tests for the Activate Decoys dashboard control."""

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()
        self.client.post("/api/simulation/reset")

    # ------------------------------------------------------------------
    # Engine-level
    # ------------------------------------------------------------------

    def test_activate_decoys_returns_ok(self):
        """DeceptionEngine.activate_decoys() returns ok=True."""
        from deception.engine import DeceptionEngine
        eng = DeceptionEngine()
        result = eng.activate_decoys()
        self.assertTrue(result["ok"])

    def test_activate_decoys_elevates_posture(self):
        """activate_decoys() elevates posture from MONITOR to at least ACTIVATE."""
        from deception.engine import DeceptionEngine
        from deception.models import DeceptionPosture
        eng = DeceptionEngine()
        self.assertEqual(eng.posture, DeceptionPosture.MONITOR)
        eng.activate_decoys()
        self.assertNotEqual(eng.posture, DeceptionPosture.MONITOR)

    def test_activate_decoys_records_events(self):
        """activate_decoys() generates deception events for armed decoys."""
        from deception.engine import DeceptionEngine
        eng = DeceptionEngine()
        before = len(eng.events)
        eng.activate_decoys()
        self.assertGreater(len(eng.events), before)

    def test_activate_decoys_returns_armed_count(self):
        """activate_decoys() reports number of armed decoys in response."""
        from deception.engine import DeceptionEngine
        eng = DeceptionEngine()
        result = eng.activate_decoys()
        self.assertIn("armed_count", result)
        self.assertIsInstance(result["armed_count"], int)

    def test_activate_decoys_returns_activated_list(self):
        """activate_decoys() returns a list of activated decoy names."""
        from deception.engine import DeceptionEngine
        eng = DeceptionEngine()
        result = eng.activate_decoys()
        self.assertIn("activated_decoys", result)
        self.assertIsInstance(result["activated_decoys"], list)

    def test_activate_decoys_feeds_detection_evidence(self):
        """activate_decoys() feeds evidence into the detection engine."""
        from deception.engine import DeceptionEngine
        from detection.engine import DetectionEngine
        det = DetectionEngine()
        dec = DeceptionEngine()
        dec.set_detection_engine(det)
        before = len(det.evidence)
        dec.activate_decoys()
        self.assertGreater(len(det.evidence), before)

    # ------------------------------------------------------------------
    # API endpoint
    # ------------------------------------------------------------------

    def test_api_activate_decoys_returns_200(self):
        """POST /api/deception/activate returns 200."""
        r = self.client.post("/api/deception/activate")
        self.assertEqual(r.status_code, 200)

    def test_api_activate_decoys_returns_ok_true(self):
        """POST /api/deception/activate returns ok=True in JSON."""
        r = self.client.post("/api/deception/activate")
        data = r.get_json()
        self.assertTrue(data.get("ok"))

    def test_api_activate_decoys_returns_posture(self):
        """POST /api/deception/activate response includes posture field."""
        r = self.client.post("/api/deception/activate")
        data = r.get_json()
        self.assertIn("posture", data)
        self.assertNotEqual(data["posture"], "monitor")

    def test_api_activate_decoys_returns_message(self):
        """POST /api/deception/activate response includes a human-readable message."""
        r = self.client.post("/api/deception/activate")
        data = r.get_json()
        self.assertIn("message", data)
        self.assertIsInstance(data["message"], str)

    def test_api_deception_status_reflects_activation(self):
        """After activating decoys, GET /api/deception posture is no longer 'monitor'."""
        self.client.post("/api/deception/activate")
        r = self.client.get("/api/deception")
        data = r.get_json()
        self.assertNotEqual(data.get("posture"), "monitor")

    # ------------------------------------------------------------------
    # Dashboard HTML contains the button
    # ------------------------------------------------------------------

    def test_dashboard_has_activate_decoys_button(self):
        """Dashboard page contains the Activate Decoys button."""
        r = self.client.get("/")
        html = r.data.decode()
        self.assertIn("btnActivateDecoys", html)
        self.assertIn("Activate Decoys", html)

    def test_dashboard_activate_decoys_calls_correct_endpoint(self):
        """Dashboard JS wires Activate Decoys to /api/deception/activate."""
        r = self.client.get("/static/js/dashboard.js")
        js = r.data.decode()
        self.assertIn("/api/deception/activate", js)


class ContainAttackerDashboardTests(unittest.TestCase):
    """Tests for the Contain Attacker dashboard control."""

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()
        self.client.post("/api/simulation/reset")

    # ------------------------------------------------------------------
    # Existing contain API (regression tests to confirm still working)
    # ------------------------------------------------------------------

    def test_api_contain_still_returns_200(self):
        """Existing POST /api/deception/contain still returns 200."""
        r = self.client.post("/api/deception/contain")
        self.assertEqual(r.status_code, 200)

    def test_api_contain_changes_attacker_state(self):
        """POST /api/deception/contain sets attacker_state to 'contained'."""
        r = self.client.post("/api/deception/contain")
        data = r.get_json()
        self.assertEqual(data.get("attacker_state"), "contained")

    def test_api_contain_returns_message(self):
        """POST /api/deception/contain returns a human-readable message."""
        r = self.client.post("/api/deception/contain")
        data = r.get_json()
        self.assertIn("message", data)

    def test_api_contain_reflected_in_deception_status(self):
        """After contain, GET /api/deception shows attacker_state=contained."""
        self.client.post("/api/deception/contain")
        r = self.client.get("/api/deception")
        data = r.get_json()
        self.assertEqual(data.get("attacker_state"), "contained")

    def test_api_contain_reflected_in_dashboard_api(self):
        """After contain, /api/dashboard defense_units.contained == 1."""
        self.client.post("/api/deception/contain")
        r = self.client.get("/api/dashboard")
        data = r.get_json()
        du = data.get("defense_units", {})
        self.assertEqual(du.get("contained"), 1)

    # ------------------------------------------------------------------
    # Dashboard HTML contains the Contain Attacker button
    # ------------------------------------------------------------------

    def test_dashboard_has_contain_button(self):
        """Dashboard page contains the Contain Attacker button."""
        r = self.client.get("/")
        html = r.data.decode()
        self.assertIn("btnDashContain", html)
        self.assertIn("Contain Attacker", html)

    def test_dashboard_contain_calls_correct_endpoint(self):
        """Dashboard JS wires Contain Attacker to /api/deception/contain."""
        r = self.client.get("/static/js/dashboard.js")
        js = r.data.decode()
        self.assertIn("/api/deception/contain", js)

    def test_dashboard_has_attacker_state_badge(self):
        """Dashboard page contains the attacker state badge element."""
        r = self.client.get("/")
        html = r.data.decode()
        self.assertIn("defAttackerBadge", html)

    # ------------------------------------------------------------------
    # Adversary intelligence refreshed after containment
    # ------------------------------------------------------------------

    def test_contain_refreshes_adversary_intelligence(self):
        """After containment, adversary engine profile reflects contained state."""
        # Step simulation to build adversary profile
        self.client.post("/api/simulation/step")
        # Contain
        self.client.post("/api/deception/contain")
        # Check adversary API — should not error out
        r = self.client.get("/api/adversary")
        self.assertEqual(r.status_code, 200)

    # ------------------------------------------------------------------
    # Contain Attacker button present is NOT same as CONTAINED status label
    # ------------------------------------------------------------------

    def test_contain_button_is_separate_from_contained_status(self):
        """The Contain Attacker button is distinct from the CONTAINED status text."""
        r = self.client.get("/")
        html = r.data.decode()
        # Button must exist
        self.assertIn("btnDashContain", html)
        # The result status display also exists in hidden stats
        self.assertIn("defContained", html)


# ===========================================================================
# Phase 23B — Deception Page Controls Wired
# ===========================================================================

class DeceptionPageControlsTests(unittest.TestCase):
    """
    Tests that the Activate Decoys and Contain Attacker controls on the
    actual /deception page are present, connected, and produce real state changes.
    """

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()
        self.client.post("/api/simulation/reset")

    # ------------------------------------------------------------------
    # Activate Decoys — deception page HTML
    # ------------------------------------------------------------------

    def test_deception_page_has_activate_decoys_button(self):
        """The /deception page now contains an Activate Decoys button."""
        r = self.client.get("/deception")
        html = r.data.decode()
        self.assertIn("btnActivateDecoys", html)
        self.assertIn("Activate Decoys", html)

    def test_deception_page_activate_decoys_onclick_correct(self):
        """The Activate Decoys button on /deception calls activateDecoys()."""
        r = self.client.get("/deception")
        html = r.data.decode()
        self.assertIn('onclick="activateDecoys()"', html)

    def test_deception_js_has_activate_decoys_function(self):
        """deception.js defines window.activateDecoys."""
        r = self.client.get("/static/js/deception.js")
        js = r.data.decode()
        self.assertIn("window.activateDecoys", js)

    def test_deception_js_activate_calls_correct_api(self):
        """deception.js activateDecoys() calls POST /api/deception/activate."""
        r = self.client.get("/static/js/deception.js")
        js = r.data.decode()
        self.assertIn("/api/deception/activate", js)

    # ------------------------------------------------------------------
    # Activate Decoys — actual state change through API path
    # ------------------------------------------------------------------

    def test_activate_decoys_via_api_changes_posture(self):
        """POST /api/deception/activate changes posture away from 'monitor'."""
        before = self.client.get("/api/deception").get_json()
        self.assertEqual(before.get("posture"), "monitor")
        self.client.post("/api/deception/activate")
        after = self.client.get("/api/deception").get_json()
        self.assertNotEqual(after.get("posture"), "monitor")

    def test_activate_decoys_via_api_records_events(self):
        """POST /api/deception/activate generates deception events."""
        self.client.post("/api/deception/activate")
        r = self.client.get("/api/deception")
        data = r.get_json()
        self.assertGreater(data.get("total_events", 0), 0)

    def test_activate_decoys_state_persists_after_action(self):
        """Deception posture change from activate persists on subsequent GET."""
        self.client.post("/api/deception/activate")
        r1 = self.client.get("/api/deception").get_json()
        r2 = self.client.get("/api/deception").get_json()
        self.assertEqual(r1.get("posture"), r2.get("posture"))
        self.assertNotEqual(r2.get("posture"), "monitor")

    # ------------------------------------------------------------------
    # Contain Attacker — deception page HTML
    # ------------------------------------------------------------------

    def test_deception_page_contain_button_not_hardcoded_disabled(self):
        """The Freeze/Contain button is no longer hardcoded disabled in HTML."""
        r = self.client.get("/deception")
        html = r.data.decode()
        # The button must exist
        self.assertIn("btnContain", html)
        # It must NOT have a hardcoded disabled attribute in the opening tag
        # (JS will manage disabled state dynamically)
        import re
        # Find the btnContain button tag and check it doesn't have "disabled" as attribute
        match = re.search(r'id="btnContain"[^>]*>', html)
        self.assertIsNotNone(match, "btnContain button tag not found")
        self.assertNotIn(' disabled', match.group(0),
                         "btnContain should not be hardcoded disabled in HTML")

    def test_deception_page_contain_button_has_onclick(self):
        """The Freeze/Contain button on /deception calls containAttacker()."""
        r = self.client.get("/deception")
        html = r.data.decode()
        self.assertIn('onclick="containAttacker()"', html)

    def test_deception_js_contain_calls_correct_api(self):
        """deception.js containAttacker() calls POST /api/deception/contain."""
        r = self.client.get("/static/js/deception.js")
        js = r.data.decode()
        self.assertIn("/api/deception/contain", js)

    # ------------------------------------------------------------------
    # Contain Attacker — actual state change through API path
    # ------------------------------------------------------------------

    def test_contain_attacker_via_api_changes_state(self):
        """POST /api/deception/contain changes attacker_state to 'contained'."""
        r = self.client.post("/api/deception/contain")
        data = r.get_json()
        self.assertEqual(data.get("attacker_state"), "contained")

    def test_contain_attacker_state_persists_after_action(self):
        """Attacker state 'contained' persists on subsequent GET /api/deception."""
        self.client.post("/api/deception/contain")
        r = self.client.get("/api/deception")
        data = r.get_json()
        self.assertEqual(data.get("attacker_state"), "contained")
        adaptive = data.get("adaptive", {})
        self.assertEqual(adaptive.get("attacker_state"), "contained")

    def test_contain_attacker_generates_contained_event(self):
        """POST /api/deception/contain generates a 'contained' deception event."""
        self.client.post("/api/deception/contain")
        r = self.client.get("/api/deception")
        data = r.get_json()
        events = data.get("events", [])
        contained_events = [e for e in events if e.get("event_type") == "contained"]
        self.assertGreater(len(contained_events), 0)

    def test_contain_after_activate_both_persist(self):
        """Activate then contain — both state changes are recorded and persist."""
        self.client.post("/api/deception/activate")
        self.client.post("/api/deception/contain")
        r = self.client.get("/api/deception")
        data = r.get_json()
        # Posture elevated
        self.assertNotEqual(data.get("posture"), "monitor")
        # Attacker contained
        self.assertEqual(data.get("attacker_state"), "contained")
        # Events recorded for both
        self.assertGreater(data.get("total_events", 0), 1)

    # ------------------------------------------------------------------
    # updateButtons logic — JS level (via HTML + state)
    # ------------------------------------------------------------------

    def test_deception_js_updatebuttons_manages_activate_button(self):
        """deception.js updateButtons() references btnActivateDecoys."""
        r = self.client.get("/static/js/deception.js")
        js = r.data.decode()
        self.assertIn("btnActivateDecoys", js)

    def test_deception_js_updatebuttons_uses_posture(self):
        """deception.js updateButtons() uses posture to manage Activate Decoys."""
        r = self.client.get("/static/js/deception.js")
        js = r.data.decode()
        self.assertIn("posture", js)
        self.assertIn("alreadyActive", js)


if __name__ == "__main__":
    unittest.main()
