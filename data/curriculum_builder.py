"""Dynamic curriculum builder using data-driven difficulty clustering.

Replaces hardcoded 8-phase boundaries with:
1. Continuous difficulty spectrum from yusp48 metadata
2. Empirical success rates from gdsolver trajectories
3. Clustering to identify natural difficulty transitions
"""

from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
import numpy as np
from collections import defaultdict
from enum import Enum

from .unified_trajectory import UnifiedTrajectory


class DifficultyMetric(Enum):
    """How to measure level difficulty."""
    STARS = "stars"  # Official difficulty rating
    GDSOLVER_SUCCESS = "gdsolver_success"  # Empirical success rate
    PLAYER_WIN_RATE = "player_win_rate"  # From game-bot attempts
    CUSTOM_ESTIMATE = "custom_estimate"  # Learned difficulty


@dataclass
class DifficultyCluster:
    """Group of levels at similar difficulty."""

    cluster_id: int
    difficulty_range: Tuple[float, float]  # (min, max) difficulty
    level_names: List[str]  # Levels in this cluster
    mean_difficulty: float  # Average difficulty
    median_stars: int  # Median official stars
    estimated_win_rate: float  # Expected agent win rate on cluster

    # Progression parameters
    reward_scale: float = 1.0  # Reward multiplier for this cluster
    max_steps: int = 6000  # Max steps per episode (100s at 60Hz)
    required_win_rate: float = 0.85  # Gate threshold to advance

    def __len__(self) -> int:
        return len(self.level_names)


class CurriculumBuilder:
    """Build adaptive curriculum from real data.

    Process:
    1. Load level metadata from yusp48
    2. Collect gdsolver success rates
    3. Cluster levels by difficulty
    4. Estimate progression gates
    """

    def __init__(self, min_levels_per_cluster: int = 10):
        """Initialize curriculum builder.

        Args:
            min_levels_per_cluster: Minimum levels per difficulty cluster
        """
        self.min_levels_per_cluster = min_levels_per_cluster
        self.level_metadata: Dict[str, Dict] = {}
        self.gdsolver_results: Dict[str, bool] = {}  # level_name → success
        self.game_bot_results: Dict[str, List[bool]] = {}  # level_name → [attempts]
        self.clusters: List[DifficultyCluster] = []

    def add_level_metadata(self, level_name: str, metadata: Dict):
        """Add level metadata from yusp48.

        Args:
            level_name: Level name
            metadata: Dict with 'stars', 'downloads', 'likes', etc.
        """
        self.level_metadata[level_name] = metadata

    def add_gdsolver_result(self, level_name: str, success: bool):
        """Add gdsolver trajectory result.

        Args:
            level_name: Level name
            success: Whether gdsolver found solution
        """
        self.gdsolver_results[level_name] = success

    def add_game_bot_attempts(self, level_name: str, outcomes: List[bool]):
        """Add game-bot attempt outcomes.

        Args:
            level_name: Level name
            outcomes: List of booleans (success/failure per attempt)
        """
        if level_name not in self.game_bot_results:
            self.game_bot_results[level_name] = []
        self.game_bot_results[level_name].extend(outcomes)

    def compute_difficulty(
        self,
        level_name: str,
        metric: DifficultyMetric = DifficultyMetric.STARS
    ) -> float:
        """Compute difficulty estimate for a level.

        Args:
            level_name: Level name
            metric: Which metric to use

        Returns:
            Difficulty score (0.0-1.0)
        """
        if metric == DifficultyMetric.STARS:
            stars = self.level_metadata.get(level_name, {}).get('stars', 0)
            return min(stars / 22.0, 1.0)  # Normalize 0-22 to 0-1

        elif metric == DifficultyMetric.GDSOLVER_SUCCESS:
            # Inverse: harder levels are less likely to be solved
            success = self.gdsolver_results.get(level_name, False)
            return 0.0 if success else 1.0

        elif metric == DifficultyMetric.PLAYER_WIN_RATE:
            attempts = self.game_bot_results.get(level_name, [])
            if not attempts:
                return 0.5  # Unknown difficulty
            win_rate = sum(attempts) / len(attempts)
            # Inverse: harder levels have lower win rates
            return 1.0 - win_rate

        elif metric == DifficultyMetric.CUSTOM_ESTIMATE:
            return self.level_metadata.get(level_name, {}).get('custom_difficulty', 0.5)

        else:
            return 0.5

    def build_clusters(
        self,
        metric: DifficultyMetric = DifficultyMetric.STARS,
        num_clusters: Optional[int] = None
    ) -> List[DifficultyCluster]:
        """Build difficulty clusters using K-means.

        Args:
            metric: Difficulty metric to use
            num_clusters: Number of clusters (default: auto-determined)

        Returns:
            List of DifficultyCluster objects
        """
        # Compute difficulty for all levels
        levels = list(self.level_metadata.keys())
        difficulties = np.array([
            self.compute_difficulty(level, metric) for level in levels
        ])

        if len(levels) == 0:
            return []

        # Auto-determine optimal number of clusters
        if num_clusters is None:
            num_clusters = max(
                4,  # Minimum 4 clusters
                len(levels) // self.min_levels_per_cluster
            )
        num_clusters = min(num_clusters, 8)  # Cap at 8

        # K-means clustering
        from scipy.cluster.hierarchy import linkage, fcluster
        from scipy.spatial.distance import pdist

        if len(levels) == 1:
            cluster = DifficultyCluster(
                cluster_id=0,
                difficulty_range=(difficulties[0], difficulties[0]),
                level_names=levels,
                mean_difficulty=difficulties[0],
                median_stars=self.level_metadata[levels[0]].get('stars', 0),
                estimated_win_rate=0.5,
            )
            self.clusters = [cluster]
            return self.clusters

        # Use hierarchical clustering
        distances = pdist(difficulties.reshape(-1, 1))
        linkage_matrix = linkage(distances, method='ward')
        cluster_labels = fcluster(linkage_matrix, num_clusters, criterion='maxclust')

        # Build cluster objects
        clusters = []
        for cluster_id in range(1, num_clusters + 1):
            mask = cluster_labels == cluster_id
            cluster_levels = [levels[i] for i in range(len(levels)) if mask[i]]
            cluster_diffs = difficulties[mask]

            # Skip empty clusters
            if len(cluster_levels) == 0:
                continue

            # Compute cluster statistics
            mean_difficulty = float(np.mean(cluster_diffs))
            median_stars = int(np.median([
                self.level_metadata.get(l, {}).get('stars', 0)
                for l in cluster_levels
            ]))

            # Estimate win rate (inverse of difficulty)
            estimated_win_rate = 1.0 - mean_difficulty

            # Scale rewards based on difficulty
            reward_scale = max(0.5, 1.0 - 0.1 * (mean_difficulty - 0.5))

            # Scale gate threshold: easier clusters need higher win rate
            required_win_rate = 0.95 - (0.2 * (1.0 - mean_difficulty))
            required_win_rate = np.clip(required_win_rate, 0.70, 0.95)

            cluster = DifficultyCluster(
                cluster_id=len(clusters),
                difficulty_range=(float(np.min(cluster_diffs)), float(np.max(cluster_diffs))),
                level_names=cluster_levels,
                mean_difficulty=mean_difficulty,
                median_stars=median_stars,
                estimated_win_rate=estimated_win_rate,
                reward_scale=reward_scale,
                required_win_rate=required_win_rate,
            )
            clusters.append(cluster)

        # Sort by difficulty
        clusters.sort(key=lambda c: c.mean_difficulty)

        self.clusters = clusters
        return clusters

    def get_level_cluster(self, level_name: str) -> Optional[DifficultyCluster]:
        """Get cluster for a specific level.

        Args:
            level_name: Level name

        Returns:
            DifficultyCluster or None
        """
        for cluster in self.clusters:
            if level_name in cluster.level_names:
                return cluster
        return None

    def sample_level_from_cluster(
        self,
        cluster_id: int,
        random_state: Optional[np.random.RandomState] = None
    ) -> Optional[str]:
        """Sample a level from cluster.

        Args:
            cluster_id: Cluster ID
            random_state: RNG for reproducibility

        Returns:
            Level name or None
        """
        if cluster_id >= len(self.clusters):
            return None

        cluster = self.clusters[cluster_id]

        if random_state is None:
            random_state = np.random.RandomState()

        return random_state.choice(cluster.level_names)

    def get_curriculum_phases(self) -> List[Dict]:
        """Convert clusters to curriculum phases.

        Returns:
            List of phase dicts compatible with CurriculumScheduler
        """
        phases = []

        for cluster in self.clusters:
            phase = {
                'name': f"Cluster {cluster.cluster_id}: {cluster.median_stars}★",
                'difficulty_range': cluster.difficulty_range,
                'level_names': cluster.level_names,
                'gate_threshold': cluster.required_win_rate,
                'reward_scale': cluster.reward_scale,
                'max_steps': cluster.max_steps,
                'estimated_win_rate': cluster.estimated_win_rate,
            }
            phases.append(phase)

        return phases

    def summary(self) -> str:
        """Get human-readable summary of curriculum.

        Returns:
            Formatted string with curriculum breakdown
        """
        lines = [
            "=== Data-Driven Curriculum ===",
            f"Clusters: {len(self.clusters)}",
            f"Total Levels: {sum(len(c.level_names) for c in self.clusters)}",
            "",
        ]

        for cluster in self.clusters:
            lines.extend([
                f"Cluster {cluster.cluster_id}: {cluster.median_stars}★ ({len(cluster.level_names)} levels)",
                f"  Difficulty: {cluster.difficulty_range[0]:.2f}-{cluster.difficulty_range[1]:.2f}",
                f"  Est. Win Rate: {cluster.estimated_win_rate:.1%}",
                f"  Gate Threshold: {cluster.required_win_rate:.1%}",
                f"  Reward Scale: {cluster.reward_scale:.2f}x",
                "",
            ])

        return "\n".join(lines)
