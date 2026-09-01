"""
National Security Impact Engine

Analyses cascading risk propagation across the Digital Twin's
sector dependencies and produces a national security impact assessment.

Derives all data from existing simulation, detection, and Digital Twin state.
Does NOT modify infrastructure or interact with real systems.
"""

from collections import deque
from typing import Dict, List, Optional, Set

from impact.models import (
    ImpactLevel,
    NationalImpactSummary,
    PropagationChain,
    RiskAssessment,
)
from simulation.models import AssetCriticality, AssetStatus


# Criticality weight for asset-level risk
_CRITICALITY_WEIGHT = {
    AssetCriticality.CRITICAL: 1.0,
    AssetCriticality.HIGH: 0.7,
    AssetCriticality.MEDIUM: 0.4,
    AssetCriticality.LOW: 0.2,
}

# Decay factor per hop in the dependency chain
HOP_DECAY = 0.6


class ImpactEngine:
    """
    Calculates cascading national-security impact from compromised sectors
    through the Digital Twin dependency graph.
    """

    def __init__(self, twin=None, detection_engine=None):
        self._twin = twin
        self._detection = detection_engine

    def set_engines(self, twin, detection_engine=None):
        """Bind engine references."""
        self._twin = twin
        self._detection = detection_engine

    # ------------------------------------------------------------------
    # Core analysis
    # ------------------------------------------------------------------

    def assess(self) -> NationalImpactSummary:
        """
        Perform a full national-security impact assessment.

        Algorithm:
        1. Identify compromised/under-attack sectors
        2. BFS from each compromised sector through outgoing dependencies
        3. Calculate risk score per hop (decaying with distance)
        4. Aggregate into national impact score
        5. Identify priority sector for defensive attention
        """
        if not self._twin:
            return NationalImpactSummary()

        summary = NationalImpactSummary()
        compromised_sectors = self._find_compromised_sectors()
        summary.total_compromised = len(compromised_sectors)

        if not compromised_sectors:
            return summary

        # BFS propagation from each compromised sector
        all_at_risk: Set[str] = set()
        all_chains: List[PropagationChain] = []

        for sector_id in compromised_sectors:
            chain = self._propagate(sector_id)
            if chain.assessments:
                all_chains.append(chain)
                for assessment in chain.assessments:
                    all_at_risk.add(assessment.affected_sector)

        summary.propagation_chains = all_chains
        summary.affected_sectors = sorted(all_at_risk)
        summary.total_at_risk = len(all_at_risk)

        # Calculate national impact score
        summary.score = self._calculate_impact_score(compromised_sectors, all_at_risk)

        # Classify impact level
        summary.impact_level = self._classify_impact(summary.score)

        # Identify priority sector
        priority_id, priority_reason = self._find_priority(compromised_sectors, all_at_risk, all_chains)
        summary.priority_sector = priority_id
        summary.priority_reason = priority_reason

        return summary

    def to_dict(self) -> dict:
        """Return the current assessment as a dict."""
        return self.assess().to_dict()

    # ------------------------------------------------------------------
    # Internal: find compromised sectors
    # ------------------------------------------------------------------

    def _find_compromised_sectors(self) -> List[str]:
        """Return sector IDs that have any compromised or under-attack assets."""
        compromised = []
        for sid, sector in self._twin.sectors.items():
            if any(
                a.status in (AssetStatus.COMPROMISED, AssetStatus.UNDER_ATTACK)
                for a in sector.assets
            ):
                compromised.append(sid)
        return compromised

    # ------------------------------------------------------------------
    # Internal: BFS propagation
    # ------------------------------------------------------------------

    def _propagate(self, origin: str) -> PropagationChain:
        """
        BFS from origin sector through outgoing dependencies.
        Returns a PropagationChain with all risk assessments.
        """
        chain = PropagationChain(origin=origin)
        visited: Set[str] = {origin}
        queue: deque = deque()

        # Seed the queue with direct outgoing dependencies
        source_sector = self._twin.get_sector(origin)
        if not source_sector:
            return chain

        # Calculate base risk from the source sector's compromise level
        source_risk = self._sector_risk_score(origin)
        for dep in self._twin.outgoing_dependencies(origin):
            if dep.active and dep.target_id not in visited:
                queue.append((dep.target_id, origin, dep.label, source_risk, 1))

        while queue:
            target_id, src_id, label, parent_risk, depth = queue.popleft()
            if target_id in visited:
                continue
            visited.add(target_id)

            # Risk decays with each hop
            hop_risk = parent_risk * (HOP_DECAY ** depth)

            # Factor in the target sector's criticality
            target_sector = self._twin.get_sector(target_id)
            if not target_sector:
                continue

            critical_assets = []
            max_crit = 0.0
            for asset in target_sector.assets:
                w = _CRITICALITY_WEIGHT.get(asset.criticality, 0.2)
                max_crit = max(max_crit, w)
                if asset.criticality in (AssetCriticality.CRITICAL, AssetCriticality.HIGH):
                    critical_assets.append({
                        "asset_id": asset.asset_id,
                        "name": asset.name,
                        "criticality": asset.criticality.value,
                        "status": asset.status.value,
                    })

            risk_score = min(1.0, hop_risk * (0.5 + 0.5 * max_crit))

            assessment = RiskAssessment(
                source_sector=src_id,
                affected_sector=target_id,
                dependency_label=label,
                risk_score=risk_score,
                critical_assets=critical_assets,
            )
            chain.assessments.append(assessment)
            if target_id not in chain.path:
                chain.path.append(target_id)

            # Continue propagation from this sector
            for dep in self._twin.outgoing_dependencies(target_id):
                if dep.active and dep.target_id not in visited:
                    queue.append((dep.target_id, target_id, dep.label, risk_score, depth + 1))

        return chain

    # ------------------------------------------------------------------
    # Internal: scoring
    # ------------------------------------------------------------------

    def _sector_risk_score(self, sector_id: str) -> float:
        """Calculate a 0-1 risk score for a sector based on asset compromise."""
        sector = self._twin.get_sector(sector_id)
        if not sector or not sector.assets:
            return 0.0
        total_weight = 0.0
        compromised_weight = 0.0
        for asset in sector.assets:
            w = _CRITICALITY_WEIGHT.get(asset.criticality, 0.2)
            total_weight += w
            if asset.status in (AssetStatus.COMPROMISED, AssetStatus.UNDER_ATTACK):
                compromised_weight += w
        return compromised_weight / total_weight if total_weight > 0 else 0.0

    def _calculate_impact_score(self, compromised: List[str], at_risk: Set[str]) -> float:
        """
        Calculate overall national impact score (0.0 - 1.0).

        Factors:
        - Ratio of compromised sectors to total
        - Number of sectors at risk through propagation
        - Threat confidence from detection engine
        """
        total_sectors = len(self._twin.sectors)
        if total_sectors == 0:
            return 0.0

        # Factor 1: Compromise ratio
        compromise_ratio = len(compromised) / total_sectors

        # Factor 2: Propagation breadth
        propagation_ratio = len(at_risk) / total_sectors

        # Factor 3: Threat confidence (from detection engine)
        threat_confidence = 0.0
        if self._detection:
            threat_confidence = self._detection.threat_score()

        # Weighted combination
        score = (
            0.35 * compromise_ratio +
            0.35 * propagation_ratio +
            0.30 * threat_confidence
        )
        return round(min(1.0, score), 3)

    def _classify_impact(self, score: float) -> ImpactLevel:
        """Classify the impact level from the score."""
        if score >= 0.7:
            return ImpactLevel.CRITICAL
        elif score >= 0.4:
            return ImpactLevel.HIGH
        elif score >= 0.15:
            return ImpactLevel.MODERATE
        return ImpactLevel.LOW

    # ------------------------------------------------------------------
    # Internal: prioritization
    # ------------------------------------------------------------------

    def _find_priority(
        self,
        compromised: List[str],
        at_risk: Set[str],
        chains: List[PropagationChain],
    ) -> tuple:
        """
        Identify the most urgent sector requiring defensive attention.

        Priority = highest-risk sector that is NOT yet compromised but
        has critical assets and is reachable through propagation.
        Falls back to the most critical compromised sector.
        """
        # Among at-risk (not yet compromised) sectors, find the one with
        # highest aggregated risk score
        risk_scores: Dict[str, float] = {}
        for chain in chains:
            for assessment in chain.assessments:
                sid = assessment.affected_sector
                if sid not in compromised:
                    risk_scores[sid] = risk_scores.get(sid, 0.0) + assessment.risk_score

        if risk_scores:
            priority_id = max(risk_scores, key=risk_scores.get)
            sector = self._twin.get_sector(priority_id)
            crit_count = sum(
                1 for a in sector.assets
                if a.criticality in (AssetCriticality.CRITICAL, AssetCriticality.HIGH)
            ) if sector else 0
            reason = (
                f"Highest cascading risk score ({risk_scores[priority_id]:.3f}). "
                f"Reachable through {len([c for c in chains if priority_id in c.path])} "
                f"propagation chain(s) with {crit_count} high-criticality asset(s)."
            )
            return priority_id, reason

        # Fallback: most critical compromised sector
        if compromised:
            worst = max(compromised, key=lambda s: self._sector_risk_score(s))
            return worst, f"Already compromised with highest risk score ({self._sector_risk_score(worst):.3f})."

        return None, ""

    # ------------------------------------------------------------------
    # Reset
    # ------------------------------------------------------------------

    def reset(self):
        """No internal state to clear — assessment is always derived live."""
        pass


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[ImpactEngine] = None


def get_impact_engine() -> ImpactEngine:
    """Return the global ImpactEngine instance (create on first call)."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = ImpactEngine()
    return _engine_instance
