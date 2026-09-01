"""Impact module — national security impact and dependency propagation."""

from .models import ImpactLevel, NationalImpactSummary, PropagationChain, RiskAssessment
from .engine import ImpactEngine, get_impact_engine

__all__ = [
    "ImpactEngine",
    "ImpactLevel",
    "NationalImpactSummary",
    "PropagationChain",
    "RiskAssessment",
    "get_impact_engine",
]
