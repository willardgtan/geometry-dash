"""Collision geometry classes for gdsolver trajectories.

Represents static collision geometry from gdsolver dumps as meshes of axis-aligned
bounding boxes (AABBs). Supports circle-AABB collision testing for trajectory analysis.
"""

from typing import List
from dataclasses import dataclass


@dataclass
class CollisionBox:
    """Axis-aligned bounding box (AABB) collision primitive."""

    x: float  # Left edge
    y: float  # Top edge
    width: float
    height: float

    def circle_overlap(self, cx: float, cy: float, radius: float) -> bool:
        """
        Test circle-AABB overlap using closest-point-on-box method.

        Args:
            cx: Circle center x
            cy: Circle center y
            radius: Circle radius

        Returns:
            True if circle overlaps box, False otherwise
        """
        # Find closest point on box to circle center
        closest_x = max(self.x, min(cx, self.x + self.width))
        closest_y = max(self.y, min(cy, self.y + self.height))

        # Distance from circle center to closest point
        dx = cx - closest_x
        dy = cy - closest_y
        distance_sq = dx * dx + dy * dy

        return distance_sq < (radius * radius)


@dataclass
class CollisionMesh:
    """Collection of AABBs representing a single collision object (e.g., block, spike)."""

    geometry_id: str  # Unique ID for this collision object
    boxes: List[CollisionBox]  # Constituent AABBs

    def circle_overlap(self, cx: float, cy: float, radius: float) -> bool:
        """
        Test if circle overlaps any box in mesh.

        Args:
            cx: Circle center x
            cy: Circle center y
            radius: Circle radius

        Returns:
            True if circle overlaps any box in mesh
        """
        for box in self.boxes:
            if box.circle_overlap(cx, cy, radius):
                return True
        return False

    def closest_box(self, cx: float, cy: float) -> int:
        """
        Find index of closest box to circle center.

        Args:
            cx: Circle center x
            cy: Circle center y

        Returns:
            Index of closest box, or -1 if no boxes
        """
        if not self.boxes:
            return -1

        min_dist_sq = float('inf')
        closest_idx = -1

        for i, box in enumerate(self.boxes):
            # Closest point on box to circle center
            closest_x = max(box.x, min(cx, box.x + box.width))
            closest_y = max(box.y, min(cy, box.y + box.height))

            dx = cx - closest_x
            dy = cy - closest_y
            dist_sq = dx * dx + dy * dy

            if dist_sq < min_dist_sq:
                min_dist_sq = dist_sq
                closest_idx = i

        return closest_idx
