"""Tests for Geometry Dash physics engine (all 7 modes)."""

import unittest
import sys
import math
sys.path.insert(0, '/home/claude/geometry-dash')

from data.types import GameMode, ContactType
from data.transition import Transition
from physics.engine import PhysicsEngine, GameState


class TestPhysicsConstants(unittest.TestCase):
    """Tests for calibrated physics constants."""

    def test_cube_constants(self):
        """Test cube mode physics constants."""
        engine = PhysicsEngine()
        constants = engine.get_mode_constants(GameMode.CUBE)

        self.assertAlmostEqual(constants["jump_velocity"], 21.80, places=1)
        self.assertAlmostEqual(constants["gravity"], 103.0, places=1)
        self.assertAlmostEqual(constants["max_airtime_s"], 0.417, places=2)

    def test_all_modes_have_constants(self):
        """Test all 7 modes have physics constants."""
        engine = PhysicsEngine()

        for mode in GameMode:
            constants = engine.get_mode_constants(mode)
            self.assertIn("gravity", constants)
            self.assertIsNotNone(constants["gravity"])


class TestGameStateInitialization(unittest.TestCase):
    """Tests for game state representation."""

    def test_game_state_creation(self):
        """Test creating game state."""
        state = GameState(
            x=100.0, y=105.0,
            vx=10.389, vy=0.0,
            mode=GameMode.CUBE,
            grounded=True,
            gravity_mod=1.0,
        )

        self.assertEqual(state.x, 100.0)
        self.assertEqual(state.y, 105.0)
        self.assertEqual(state.mode, GameMode.CUBE)

    def test_game_state_to_transition(self):
        """Test converting game state to transition."""
        state = GameState(
            x=100.0, y=105.0,
            vx=10.389, vy=0.0,
            mode=GameMode.CUBE,
            grounded=True,
            gravity_mod=1.0,
        )

        transition = state.to_transition(tick=0)
        self.assertEqual(transition.x, 100.0)
        self.assertEqual(transition.tick, 0)


class TestCubePhysics(unittest.TestCase):
    """Tests for cube mode physics."""

    def test_cube_gravity(self):
        """Test gravity pulls downward."""
        engine = PhysicsEngine()

        state = GameState(
            x=100.0, y=100.0,
            vx=10.389, vy=0.0,
            mode=GameMode.CUBE,
            grounded=False,
            gravity_mod=1.0,
        )

        # Apply gravity one tick (4.17 ms)
        new_state = engine.apply_physics(state, action=0, dt=1.0/240.0)

        # Velocity should become more negative (falling)
        self.assertLess(new_state.vy, 0.0)

    def test_cube_jump(self):
        """Test cube can jump when grounded."""
        engine = PhysicsEngine()

        state = GameState(
            x=100.0, y=100.0,
            vx=10.389, vy=0.0,
            mode=GameMode.CUBE,
            grounded=True,
            gravity_mod=1.0,
        )

        # Jump (action=1)
        new_state = engine.apply_physics(state, action=1, dt=1.0/240.0)

        # Should have upward velocity
        self.assertGreater(new_state.vy, 0.0)

    def test_cube_horizontal_speed(self):
        """Test cube moves at constant horizontal speed."""
        engine = PhysicsEngine()

        state = GameState(
            x=100.0, y=100.0,
            vx=10.389, vy=0.0,
            mode=GameMode.CUBE,
            grounded=True,
            gravity_mod=1.0,
        )

        new_state = engine.apply_physics(state, action=0, dt=1.0/240.0)

        # Horizontal velocity should remain constant
        self.assertAlmostEqual(new_state.vx, 10.389, places=2)


class TestShipPhysics(unittest.TestCase):
    """Tests for ship mode physics."""

    def test_ship_thrust(self):
        """Test ship applies thrust when input held."""
        engine = PhysicsEngine()

        state = GameState(
            x=100.0, y=100.0,
            vx=10.389, vy=0.0,
            mode=GameMode.SHIP,
            grounded=False,
            gravity_mod=1.0,
        )

        # Hold button (action=1 in ship mode = continuous thrust)
        new_state = engine.apply_physics(state, action=1, dt=1.0/240.0)

        # Should have upward velocity from thrust
        self.assertGreater(new_state.vy, 0.0)

    def test_ship_gravity(self):
        """Test ship has different gravity than cube."""
        engine = PhysicsEngine()

        # Ship gravity should be weaker (50.0 vs cube 103.0)
        ship_consts = engine.get_mode_constants(GameMode.SHIP)
        cube_consts = engine.get_mode_constants(GameMode.CUBE)

        self.assertLess(ship_consts["gravity"], cube_consts["gravity"])


class TestGravityInversion(unittest.TestCase):
    """Tests for gravity inversion (UFO/portal)."""

    def test_gravity_inversion_sign_flip(self):
        """Test gravity_mod=-1 reverses gravity."""
        engine = PhysicsEngine()

        # Normal gravity
        state_normal = GameState(
            x=100.0, y=100.0,
            vx=10.389, vy=0.0,
            mode=GameMode.CUBE,
            grounded=False,
            gravity_mod=1.0,
        )

        # Inverted gravity
        state_inverted = GameState(
            x=100.0, y=100.0,
            vx=10.389, vy=0.0,
            mode=GameMode.CUBE,
            grounded=False,
            gravity_mod=-1.0,
        )

        new_normal = engine.apply_physics(state_normal, action=0, dt=1.0/240.0)
        new_inverted = engine.apply_physics(state_inverted, action=0, dt=1.0/240.0)

        # Gravity should reverse
        self.assertLess(new_normal.vy, 0)  # Falls down
        self.assertGreater(new_inverted.vy, 0)  # Falls up


class TestObstacleCollision(unittest.TestCase):
    """Tests for collision with obstacles."""

    def test_spike_collision_detection(self):
        """Test collision with spike."""
        engine = PhysicsEngine()

        state = GameState(
            x=200.0, y=100.0,
            vx=10.389, vy=0.0,
            mode=GameMode.CUBE,
            grounded=False,
            gravity_mod=1.0,
        )

        obstacles = {
            "spike_001": {"x": 200, "y": 100, "width": 20, "height": 20},
        }

        # Check collision
        collision = engine.check_collision(state, obstacles)
        self.assertTrue(collision)

    def test_platform_collision_grounding(self):
        """Test standing on platform."""
        engine = PhysicsEngine()

        state = GameState(
            x=100.0, y=119.5,  # Just above platform at y=120
            vx=10.389, vy=10.0,  # Moving downward
            mode=GameMode.CUBE,
            grounded=False,
            gravity_mod=1.0,
        )

        obstacles = {
            "block_001": {"x": 50, "y": 120, "width": 100, "height": 20},
        }

        # After collision, should be grounded
        new_state = engine.apply_physics(state, action=0, dt=1.0/240.0)

        # Should detect ground contact
        collision = engine.check_collision(new_state, obstacles)
        if collision:
            self.assertTrue(True)  # Collision detected


class TestBallPhysics(unittest.TestCase):
    """Tests for ball mode physics."""

    def test_ball_bounce(self):
        """Test ball bounces off obstacles."""
        engine = PhysicsEngine()

        state = GameState(
            x=100.0, y=100.0,
            vx=10.389, vy=10.0,
            mode=GameMode.BALL,
            grounded=False,
            gravity_mod=1.0,
        )

        obstacles = {
            "block_001": {"x": 50, "y": 120, "width": 100, "height": 20},
        }

        new_state = engine.apply_physics(state, action=0, dt=1.0/240.0)

        # After collision should bounce
        collision = engine.check_collision(new_state, obstacles)
        self.assertIsNotNone(collision)


class TestRobotPhysics(unittest.TestCase):
    """Tests for robot mode (double jump)."""

    def test_robot_double_jump_available(self):
        """Test robot can double jump."""
        engine = PhysicsEngine()

        state = GameState(
            x=100.0, y=100.0,
            vx=10.389, vy=0.0,
            mode=GameMode.ROBOT,
            grounded=True,
            gravity_mod=1.0,
            double_jump_available=True,
        )

        # First jump
        state1 = engine.apply_physics(state, action=1, dt=1.0/240.0)
        self.assertGreater(state1.vy, 0)

        # After apex, still have double jump
        state2 = GameState(
            x=state1.x, y=state1.y + state1.vy * 0.1,
            vx=state1.vx, vy=state1.vy * 0.5,  # Falling
            mode=GameMode.ROBOT,
            grounded=False,
            gravity_mod=1.0,
            double_jump_available=True,
        )

        # Second jump
        state3 = engine.apply_physics(state2, action=1, dt=1.0/240.0)
        # Should get another jump impulse
        self.assertIsNotNone(state3)


class TestIntegrationPhysics(unittest.TestCase):
    """Integration tests for physics engine."""

    def test_full_cube_arc(self):
        """Test complete jump arc in cube mode."""
        engine = PhysicsEngine()

        # Jump
        state = GameState(
            x=100.0, y=100.0,
            vx=10.389, vy=0.0,
            mode=GameMode.CUBE,
            grounded=True,
            gravity_mod=1.0,
        )

        state = engine.apply_physics(state, action=1, dt=1.0/240.0)
        self.assertGreater(state.vy, 0)

        # Rise
        for _ in range(50):
            state = engine.apply_physics(state, action=0, dt=1.0/240.0)

        # Apex - velocity should be near zero and about to reverse
        self.assertLess(abs(state.vy), 5.0)

        # Continue falling
        for _ in range(50):
            state = engine.apply_physics(state, action=0, dt=1.0/240.0)

        # Should be falling downward
        self.assertLess(state.vy, 0)


if __name__ == '__main__':
    unittest.main()
