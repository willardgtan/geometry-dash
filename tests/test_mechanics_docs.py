"""Tests for game mechanics documentation."""

import unittest
import json
import os
import sys
sys.path.insert(0, '/home/claude/geometry-dash')


class TestMechanicsDocumentation(unittest.TestCase):
    """Tests for mechanics reference files."""

    def test_mechanics_reference_json_exists(self):
        """Test that mechanics_reference.json exists."""
        path = "/home/claude/geometry-dash/data/mechanics_reference.json"
        self.assertTrue(os.path.exists(path))

    def test_mechanics_reference_json_valid(self):
        """Test that mechanics_reference.json is valid JSON."""
        path = "/home/claude/geometry-dash/data/mechanics_reference.json"
        with open(path, 'r') as f:
            data = json.load(f)

        # Should have top-level keys
        self.assertIn("game_modes", data)
        self.assertIn("obstacles", data)
        self.assertIn("physics_calibration", data)

    def test_game_modes_defined(self):
        """Test that all 7 game modes are defined."""
        path = "/home/claude/geometry-dash/data/mechanics_reference.json"
        with open(path, 'r') as f:
            data = json.load(f)

        modes = data["game_modes"]
        expected_modes = ["cube", "ship", "wave", "ball", "ufo", "robot", "spider"]
        for mode in expected_modes:
            self.assertIn(mode, modes)

    def test_obstacles_defined(self):
        """Test that all obstacle types are defined."""
        path = "/home/claude/geometry-dash/data/mechanics_reference.json"
        with open(path, 'r') as f:
            data = json.load(f)

        obstacles = data["obstacles"]
        expected = ["spike", "block", "orb", "pad", "portal", "moving_geometry"]
        for obs in expected:
            self.assertIn(obs, obstacles)

    def test_physics_calibration_present(self):
        """Test that physics calibration is documented."""
        path = "/home/claude/geometry-dash/data/mechanics_reference.json"
        with open(path, 'r') as f:
            data = json.load(f)

        cal = data["physics_calibration"]
        self.assertIn("jump_velocity", cal["fitted_constants"])
        self.assertIn("gravity", cal["fitted_constants"])

        # Check calibrated values
        self.assertEqual(cal["fitted_constants"]["jump_velocity"], 21.80)
        self.assertEqual(cal["fitted_constants"]["gravity"], 103.0)

    def test_state_representation_is_20d(self):
        """Test that state representation is 20-dimensional."""
        path = "/home/claude/geometry-dash/data/mechanics_reference.json"
        with open(path, 'r') as f:
            data = json.load(f)

        state_rep = data["state_representation"]
        self.assertEqual(state_rep["dimensions"], 21)
        self.assertEqual(len(state_rep["schema"]), 21)

    def test_game_mechanics_md_exists(self):
        """Test that GAME_MECHANICS.md exists."""
        path = "/home/claude/geometry-dash/docs/GAME_MECHANICS.md"
        self.assertTrue(os.path.exists(path))

    def test_game_mechanics_md_content(self):
        """Test that GAME_MECHANICS.md has expected sections."""
        path = "/home/claude/geometry-dash/docs/GAME_MECHANICS.md"
        with open(path, 'r') as f:
            content = f.read()

        # Should have main sections
        self.assertIn("Game Modes", content)
        self.assertIn("Obstacles", content)
        self.assertIn("Physics Constants", content)
        self.assertIn("Collision Detection", content)
        self.assertIn("240-Hz vs 60-Hz", content)


if __name__ == '__main__':
    unittest.main()
