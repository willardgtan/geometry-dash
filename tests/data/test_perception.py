"""Tests for game-bot perception and control scheme decoding."""

import unittest
import sys
import numpy as np
sys.path.insert(0, '/home/claude/geometry-dash')

from data.types import GameMode, ContactType
from data.transition import Transition
from data.perception import ControlDecoder, StateEncoder, GameBotGrid


class TestControlDecoder(unittest.TestCase):
    """Tests for control scheme interpretation."""

    def test_decoder_initialization(self):
        """Test decoder creation."""
        decoder = ControlDecoder()
        self.assertIsNotNone(decoder)

    def test_cube_tap_control(self):
        """Test cube mode tap semantics."""
        decoder = ControlDecoder()

        # Cube: rising edge (not held before, held now) = tap
        action = decoder.decode(mode=GameMode.CUBE, input_pressed=True, input_held=True)
        self.assertEqual(action, 1)

        # Hold doesn't produce new jump
        action = decoder.decode(mode=GameMode.CUBE, input_pressed=False, input_held=True)
        self.assertEqual(action, 0)

        # Release
        action = decoder.decode(mode=GameMode.CUBE, input_pressed=False, input_held=False)
        self.assertEqual(action, 0)

    def test_ship_hold_control(self):
        """Test ship mode continuous hold semantics."""
        decoder = ControlDecoder()

        # Ship: held = continuous thrust
        action = decoder.decode(mode=GameMode.SHIP, input_pressed=True, input_held=True)
        self.assertEqual(action, 1)

        # Continue holding = still thrusting
        action = decoder.decode(mode=GameMode.SHIP, input_pressed=False, input_held=True)
        self.assertEqual(action, 1)

        # Release = stop thrust
        action = decoder.decode(mode=GameMode.SHIP, input_pressed=False, input_held=False)
        self.assertEqual(action, 0)

    def test_ufo_toggle_control(self):
        """Test UFO mode gravity toggle."""
        decoder = ControlDecoder()

        # UFO: tap = toggle gravity
        action = decoder.decode(mode=GameMode.UFO, input_pressed=True, input_held=True)
        self.assertEqual(action, 1)

        # Hold doesn't toggle again
        action = decoder.decode(mode=GameMode.UFO, input_pressed=False, input_held=True)
        self.assertEqual(action, 0)


class TestStateEncoder(unittest.TestCase):
    """Tests for state encoding into perception grid."""

    def test_encoder_initialization(self):
        """Test encoder creation."""
        encoder = StateEncoder()
        self.assertIsNotNone(encoder)
        self.assertEqual(encoder.grid_width, 24)
        self.assertEqual(encoder.grid_height, 16)

    def test_world_to_grid_conversion(self):
        """Test converting world coordinates to grid."""
        encoder = StateEncoder()

        # Center of level
        grid_x, grid_y = encoder.world_to_grid(x=300, y=210)
        self.assertGreaterEqual(grid_x, 0)
        self.assertLess(grid_x, 24)
        self.assertGreaterEqual(grid_y, 0)
        self.assertLess(grid_y, 16)

    def test_encode_player_state(self):
        """Test encoding player into grid."""
        encoder = StateEncoder()

        transition = Transition(
            tick=0,
            x=150, y=105,
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

        grid = encoder.encode_player(transition)
        self.assertEqual(grid.shape, (16, 24, 1))

    def test_encode_obstacles(self):
        """Test encoding obstacle layer."""
        encoder = StateEncoder()

        # Obstacle dict format: {geometry_id: {"x": ..., "y": ..., "width": ..., "height": ...}}
        obstacles = {
            "spike_001": {"x": 200, "y": 100, "width": 20, "height": 20},
            "block_001": {"x": 250, "y": 100, "width": 40, "height": 20},
        }

        grid = encoder.encode_obstacles(obstacles)
        self.assertEqual(grid.shape, (16, 24, 1))
        # Grid should have nonzero values where obstacles are
        self.assertGreater(np.sum(grid), 0)


class TestGameBotGrid(unittest.TestCase):
    """Tests for game-bot perception grid."""

    def test_grid_initialization(self):
        """Test grid creation."""
        grid = GameBotGrid()
        self.assertEqual(grid.width, 24)
        self.assertEqual(grid.height, 16)
        self.assertEqual(grid.channels, 4)

    def test_grid_shape(self):
        """Test grid has correct shape."""
        grid = GameBotGrid()
        full_grid = grid.stack_channels()
        self.assertEqual(full_grid.shape, (16, 24, 4))

    def test_set_channel(self):
        """Test setting grid channel."""
        grid = GameBotGrid()
        channel_data = np.ones((16, 24))

        grid.set_channel(0, channel_data)
        retrieved = grid.get_channel(0)
        np.testing.assert_array_equal(retrieved, channel_data)

    def test_full_perception_stack(self):
        """Test stacking all channels together."""
        grid = GameBotGrid()

        # Set each channel to a different value
        for ch in range(4):
            grid.set_channel(ch, np.full((16, 24), ch + 1.0))

        stacked = grid.stack_channels()
        self.assertEqual(stacked.shape, (16, 24, 4))

        # Check each channel is correct
        for ch in range(4):
            np.testing.assert_array_equal(stacked[:, :, ch], np.full((16, 24), ch + 1.0))


class TestPerceptionPipeline(unittest.TestCase):
    """Integration tests for full perception pipeline."""

    def test_encode_transition_to_grid(self):
        """Test encoding a transition into full perception grid."""
        encoder = StateEncoder()
        grid = GameBotGrid()

        transition = Transition(
            tick=0,
            x=150, y=105,
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

        obstacles = {
            "spike_001": {"x": 200, "y": 100, "width": 20, "height": 20},
        }

        # Encode into grid
        player_layer = encoder.encode_player(transition)
        obstacle_layer = encoder.encode_obstacles(obstacles)

        grid.set_channel(0, player_layer.squeeze())
        grid.set_channel(1, obstacle_layer.squeeze())

        # Get final stacked grid
        final_grid = grid.stack_channels()
        self.assertEqual(final_grid.shape, (16, 24, 4))


if __name__ == '__main__':
    unittest.main()
