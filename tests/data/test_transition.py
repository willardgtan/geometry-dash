"""Tests for Transition and transition schema."""

import unittest
import sys
sys.path.insert(0, '/home/claude/geometry-dash')

from data.transition import Transition, TransitionBatch
from data.types import GameMode, ObstacleType, ContactType


class TestTransition(unittest.TestCase):
    """Tests for Transition class."""

    def test_transition_creation_cube_mode(self):
        """Test creating a Transition for cube mode at a specific tick."""
        t = Transition(
            tick=240,
            x=120.0,
            y=160.0,
            vx=10.389,
            vy=0.0,
            rotation=0.0,
            mode=GameMode.CUBE,
            grounded=True,
            contact_type=ContactType.PLATFORM,
            gravity_mod=1.0,
            size_mod=1.0,
            speed_scaling=1.0,
            death_state=False,
            input_held=False,
            input_pressed=False,
            primary_obstacle=None,
            nearby_obstacles=[],
        )

        self.assertEqual(t.tick, 240)
        self.assertEqual(t.x, 120.0)
        self.assertEqual(t.y, 160.0)
        self.assertEqual(t.mode, GameMode.CUBE)
        self.assertTrue(t.grounded)

    def test_transition_with_obstacle(self):
        """Test Transition with obstacle information."""
        t = Transition(
            tick=300,
            x=150.0,
            y=200.0,
            vx=10.0,
            vy=-15.0,
            rotation=0.0,
            mode=GameMode.CUBE,
            grounded=False,
            contact_type=ContactType.AIR,
            gravity_mod=1.0,
            size_mod=1.0,
            speed_scaling=1.0,
            death_state=False,
            input_held=False,
            input_pressed=False,
            primary_obstacle={"type": ObstacleType.SPIKE, "distance": 5.0},
            nearby_obstacles=[
                {"type": ObstacleType.SPIKE, "distance": 5.0},
                {"type": ObstacleType.BLOCK, "distance": 12.0},
            ],
        )

        self.assertIsNotNone(t.primary_obstacle)
        self.assertEqual(t.primary_obstacle["type"], ObstacleType.SPIKE)
        self.assertEqual(len(t.nearby_obstacles), 2)

    def test_transition_gravity_flip(self):
        """Test Transition with gravity inversion."""
        t = Transition(
            tick=100,
            x=100.0,
            y=100.0,
            vx=10.0,
            vy=-20.0,
            rotation=0.0,
            mode=GameMode.CUBE,
            grounded=True,
            contact_type=ContactType.PLATFORM,
            gravity_mod=-1.0,  # Gravity inverted
            size_mod=1.0,
            speed_scaling=1.0,
            death_state=False,
            input_held=False,
            input_pressed=False,
            primary_obstacle=None,
            nearby_obstacles=[],
        )

        self.assertEqual(t.gravity_mod, -1.0)
        self.assertEqual(t.vy, -20.0)

    def test_transition_batch_creation(self):
        """Test creating a batch of transitions."""
        transitions = []
        for tick in range(0, 120, 1):
            t = Transition(
                tick=tick,
                x=120.0 + tick * 0.1,
                y=160.0,
                vx=10.0,
                vy=0.0,
                rotation=0.0,
                mode=GameMode.CUBE,
                grounded=True,
                contact_type=ContactType.PLATFORM,
                gravity_mod=1.0,
                size_mod=1.0,
                speed_scaling=1.0,
                death_state=False,
                input_held=False,
                input_pressed=False,
                primary_obstacle=None,
                nearby_obstacles=[],
            )
            transitions.append(t)

        batch = TransitionBatch(transitions)
        self.assertEqual(len(batch.transitions), 120)
        self.assertEqual(batch.transitions[0].tick, 0)
        self.assertEqual(batch.transitions[-1].tick, 119)

    def test_enums_defined(self):
        """Test that all GameMode enums are defined."""
        modes = [
            GameMode.CUBE,
            GameMode.SHIP,
            GameMode.BALL,
            GameMode.UFO,
            GameMode.WAVE,
            GameMode.ROBOT,
            GameMode.SPIDER,
        ]
        self.assertEqual(len(modes), 7)

        contacts = [
            ContactType.PLATFORM,
            ContactType.SPIKE,
            ContactType.ORB,
            ContactType.PAD,
            ContactType.AIR,
        ]
        self.assertEqual(len(contacts), 5)


if __name__ == '__main__':
    unittest.main()
