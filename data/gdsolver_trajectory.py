"""gdsolver trajectory collector and collision analysis.

Collects 240-Hz transitions from gdsolver dumps into trajectories and pairs
them with static collision geometry for training data generation.
"""

from typing import Dict, List, Tuple
from data.transition import Transition
from data.collision_geometry import CollisionMesh


class GDSolverTrajectoryCollector:
    """
    Manages trajectories from gdsolver dumps and their associated collision geometry.

    Trajectories are organized by demonstration ID (e.g., "level_001_attempt_5").
    Each trajectory is a sequence of 240-Hz transitions capturing player state and input.
    """

    def __init__(self):
        """Initialize empty trajectory and collision registries."""
        self.trajectories: Dict[str, List[Transition]] = {}
        self.collision_meshes: Dict[str, CollisionMesh] = {}

    def add_transition(self, demo_id: str, transition: Transition) -> None:
        """
        Add a single transition to a trajectory.

        Args:
            demo_id: Unique demonstration identifier (e.g., "level_001_attempt_5")
            transition: Single 240-Hz transition to append
        """
        if demo_id not in self.trajectories:
            self.trajectories[demo_id] = []
        self.trajectories[demo_id].append(transition)

    def get_trajectory(self, demo_id: str) -> List[Transition]:
        """
        Retrieve a complete trajectory by ID.

        Args:
            demo_id: Demonstration identifier

        Returns:
            List of transitions, ordered by tick. Empty list if not found.
        """
        return self.trajectories.get(demo_id, [])

    def register_collision_mesh(self, geometry_id: str, mesh: CollisionMesh) -> None:
        """
        Register collision geometry for a static object.

        Args:
            geometry_id: Unique geometry identifier
            mesh: Collision mesh (collection of AABBs)
        """
        self.collision_meshes[geometry_id] = mesh

    def get_collision_mesh(self, geometry_id: str) -> CollisionMesh:
        """
        Retrieve collision geometry by ID.

        Args:
            geometry_id: Geometry identifier

        Returns:
            CollisionMesh, or None if not found
        """
        return self.collision_meshes.get(geometry_id)

    def get_collisions_for_trajectory(
        self,
        demo_id: str,
        geometry_id: str,
        player_radius: float = 10.0,
    ) -> List[Tuple[int, float]]:
        """
        Find all ticks where player collides with given geometry.

        Args:
            demo_id: Demonstration identifier
            geometry_id: Geometry identifier
            player_radius: Player collision radius (default 10.0)

        Returns:
            List of (tick, distance_to_geometry) tuples for collision ticks.
            Empty list if trajectory or geometry not found.
        """
        trajectory = self.get_trajectory(demo_id)
        mesh = self.get_collision_mesh(geometry_id)

        if not trajectory or not mesh:
            return []

        collisions = []
        for transition in trajectory:
            if mesh.circle_overlap(transition.x, transition.y, player_radius):
                # Calculate approximate distance to closest box
                closest_box_idx = mesh.closest_box(transition.x, transition.y)
                if closest_box_idx >= 0:
                    box = mesh.boxes[closest_box_idx]
                    closest_x = max(box.x, min(transition.x, box.x + box.width))
                    closest_y = max(box.y, min(transition.y, box.y + box.height))
                    dx = transition.x - closest_x
                    dy = transition.y - closest_y
                    distance = (dx * dx + dy * dy) ** 0.5
                    collisions.append((transition.tick, distance))

        return collisions

    def trajectory_stats(self, demo_id: str) -> dict:
        """
        Compute statistics for a trajectory.

        Args:
            demo_id: Demonstration identifier

        Returns:
            Dict with length, duration_ms, start/end positions, velocity stats
        """
        trajectory = self.get_trajectory(demo_id)

        if not trajectory:
            return {
                "length": 0,
                "duration_ms": 0,
                "start_pos": None,
                "end_pos": None,
            }

        # Tick to milliseconds (240 Hz = 4.17 ms per tick)
        tick_duration_ms = 4.17
        duration_ms = len(trajectory) * tick_duration_ms

        first = trajectory[0]
        last = trajectory[-1]

        # Velocity stats
        velocities = [
            (t.vx ** 2 + t.vy ** 2) ** 0.5
            for t in trajectory
        ]
        avg_velocity = sum(velocities) / len(velocities) if velocities else 0.0

        return {
            "length": len(trajectory),
            "duration_ms": duration_ms,
            "start_pos": (first.x, first.y),
            "end_pos": (last.x, last.y),
            "avg_velocity": avg_velocity,
            "max_velocity": max(velocities) if velocities else 0.0,
        }
