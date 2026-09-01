"""Adaptation module — adaptive adversary and deception evolution."""

from .models import AdaptationEvent
from .engine import AdaptationEngine, get_adaptation_engine

__all__ = [
    "AdaptationEngine",
    "AdaptationEvent",
    "get_adaptation_engine",
]
