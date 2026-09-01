"""
AI Tactical Command And Deployment Simulator — Configuration

Centralized configuration for the Flask application.
Future phases will extend this with simulation, deception,
confidence, and database-specific settings.
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base configuration."""

    # Flask core
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "dev-secret-key-change-in-production"
    )
    DEBUG = False
    TESTING = False

    # Database
    DATABASE_DIR = os.path.join(BASE_DIR, "database")
    DATABASE_PATH = os.path.join(DATABASE_DIR, "cyber_arena.db")
    DATABASE_URI = f"sqlite:///{DATABASE_PATH}"

    # Application metadata
    APP_NAME = "AI Tactical Command And Deployment Simulator"
    APP_SHORT_NAME = "CYBER ARENA"
    APP_VERSION = "0.24.1"
    APP_PHASE = "Phase 23A — Activate Decoys &amp; Contain Attacker"

    # --- Placeholder sections for future phases ---

    # Simulation settings (Phase 2+)
    # SIMULATION_TICK_RATE = 1.0
    # SIMULATION_MAX_STEPS = 1000

    # Confidence settings (Phase 3+)
    # CONFIDENCE_DECAY_RATE = 0.95
    # CONFIDENCE_THRESHOLD = 0.7

    # Deception settings (Phase 4+)
    # DECEPTION_MAX_LURES = 10
    # DECEPTION_ROTATION_INTERVAL = 300

    # Defense settings (Phase 5+)
    # DEFENSE_UNIT_COUNT = 5
    # DEFENSE_PRIORITY_LEVELS = 3


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "test_cyber_arena.db")
    DATABASE_URI = f"sqlite:///{DATABASE_PATH}"


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False


# Configuration map for easy switching
config_map = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
