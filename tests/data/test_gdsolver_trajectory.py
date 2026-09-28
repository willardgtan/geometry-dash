"""Tests for gdsolver trajectory collector and collision geometry."""

import unittest
import sys
import json
import tempfile
import os
sys.path.insert(0, '/home/claude/geometry-dash')

from data.types import GameMode, ObstacleType, ContactType
from data.transition import Transition, TransitionBatch
from data.collision_geometry import CollisionBox, CollisionMesh
from data.gdsolver_trajectory import GDSolverTrajectoryCollector


class TestCollisionGeometry(unittest.TestCase):
    """Tests for collision geometry classes."""

    def test_collision_box_creation(self):
        """Test creating a collision box."""
        box = CollisionBox(x=100, y=50, width=20, height=40)
        self.assertEqual(box.x, 100)
        self.assertEqual(box.y, 50)
        self.assertEqual(box.width, 20)
        self.assertEqual(box.height, 40)

    def test_collision_box_circle_overlap(self):
        """Test circle-box collision detection."""
        box = CollisionBox(x=100, y=100, width=20, height=20)

        # Circle at box center - should collide
        overlaps = box.circle_overlap(cx=110, cy=110, radius=10)
        self.assertTrue(overlaps)

        # Circle far away - should not collide
        overlaps = box.circle_overlap(cx=200, cy=200, radius=10)
        self.assertFalse(overlaps)

    def test_collision_mesh_creation(self):
        """Test creating a collision mesh from geometry."""
        boxes = [
            CollisionBox(x=0, y=0, width=10, height=10),
            CollisionBox(x=20, y=0, width=10, height=10),
        ]
        mesh = CollisionMesh(geometry_id="block_001", boxes=boxes)
        self.assertEqual(mesh.geometry_id, "block_001")
        self.assertEqual(len(mesh.boxes), 2)

    def test_collision_mesh_circle_overlap(self):
        """Test circle overlap with mesh."""
        boxes = [
            CollisionBox(x=0, y=0, width=10, height=10),
            CollisionBox(x=20, y=0, width=10, height=10),
        ]
        mesh = CollisionMesh(geometry_id="block_001", boxes=boxes)

        # Circle near first box
        overlaps = mesh.circle_overlap(cx=5, cy=5, radius=3)
        self.assertTrue(overlaps)

        # Circle near second box
        overlaps = mesh.circle_overlap(cx=25, cy=5, radius=3)
        self.assertTrue(overlaps)

        # Circle in gap
        overlaps = mesh.circle_overlap(cx=15, cy=5, radius=2)
        self.assertFalse(overlaps)


class TestGDSolverTrajectoryCollector(unittest.TestCase):
    """Tests for trajectory collector."""

    def test_collector_initialization(self):
        """Test collector initialization."""
        collector = GDSolverTrajectoryCollector()
        self.assertIsNotNone(collector)
        self.assertEqual(len(collector.trajectories), 0)

    def test_add_transition_to_trajectory(self):
        """Test adding transitions to trajectory."""
        collector = GDSolverTrajectoryCollector()

        transition = Transition(
            tick=0,
            x=100.0, y=100.0,
            vx=10.389, vy=0.0,
            rotation=0.0,
            mode=GameMode.CUBE,
            grounded=True,
            contact_type=ContactType.PLATFORM,
            input_pressed=False,
            input_held=False,
            gravity_mod=1.0,
            size_mod=1.0,
            speed_scaling=1.0,
            death_state=False,
            level_id="level_001",
            attempt_id="attempt_001",
            source="gdsolver"
        )

        collector.add_transition("demo_001", transition)
        self.assertEqual(len(collector.trajectories), 1)
        self.assertIn("demo_001", collector.trajectories)
        self.assertEqual(len(collector.trajectories["demo_001"]), 1)

    def test_get_trajectory(self):
        """Test retrieving trajectory."""
        collector = GDSolverTrajectoryCollector()

        transitions = []
        for tick in range(5):
            transition = Transition(
                tick=tick,
                x=100.0 + tick, y=100.0,
                vx=10.389, vy=0.0,
                rotation=0.0,
                mode=GameMode.CUBE,
                grounded=True,
                contact_type=ContactType.PLATFORM,
                input_pressed=False,
                input_held=False,
                gravity_mod=1.0,
                size_mod=1.0,
                speed_scaling=1.0,
                death_state=False,
                level_id="level_001",
                attempt_id="attempt_001",
                source="gdsolver"
            )
            collector.add_transition("demo_001", transition)
            transitions.append(transition)

        traj = collector.get_trajectory("demo_001")
        self.assertEqual(len(traj), 5)
        self.assertEqual(traj[0].tick, 0)
        self.assertEqual(traj[4].tick, 4)

    def test_collision_registry(self):
        """Test registering collision geometry."""
        collector = GDSolverTrajectoryCollector()

        box = CollisionBox(x=100, y=100, width=20, height=20)
        mesh = CollisionMesh(geometry_id="block_001", boxes=[box])

        collector.register_collision_mesh("block_001", mesh)
        self.assertIn("block_001", collector.collision_meshes)

        retrieved = collector.get_collision_mesh("block_001")
        self.assertEqual(retrieved.geometry_id, "block_001")

    def test_trajectory_collision_query(self):
        """Test querying collisions along trajectory."""
        collector = GDSolverTrajectoryCollector()

        # Add trajectory with player position
        transitions = []
        for tick in range(10):
            transition = Transition(
                tick=tick,
                x=100.0 + tick * 2, y=100.0,  # Moving right
                vx=10.389, vy=0.0,
                rotation=0.0,
                mode=GameMode.CUBE,
                grounded=True,
                contact_type=ContactType.PLATFORM,
                input_pressed=False,
                input_held=False,
                gravity_mod=1.0,
                size_mod=1.0,
                speed_scaling=1.0,
                death_state=False,
                level_id="level_001",
                attempt_id="attempt_001",
                source="gdsolver"
            )
            collector.add_transition("demo_001", transition)
            transitions.append(transition)

        # Register obstacle in player's path
        box = CollisionBox(x=120, y=100, width=20, height=20)
        mesh = CollisionMesh(geometry_id="spike_001", boxes=[box])
        collector.register_collision_mesh("spike_001", mesh)

        # Query collisions
        collisions = collector.get_collisions_for_trajectory("demo_001", "spike_001", player_radius=10)
        self.assertGreater(len(collisions), 0)


if __name__ == '__main__':
    unittest.main()
