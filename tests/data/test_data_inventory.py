"""Tests for data inventory and gdsolver loader."""

import unittest
import tempfile
import os
import sys
sys.path.insert(0, '/home/claude/geometry-dash')

from data.data_inventory import DataInventory
from data.gdsolver_loader import GDSolverLoader
from data.transition import TransitionBatch
from data.types import GameMode, ContactType


class TestDataInventory(unittest.TestCase):
    """Tests for DataInventory discovery."""

    def test_data_inventory_initialization(self):
        """Test that DataInventory initializes without errors."""
        inventory = DataInventory()
        self.assertIsNotNone(inventory.discovered)
        self.assertIn("gdsolver", inventory.discovered)
        self.assertIn("geometry_dash_rl", inventory.discovered)

    def test_inventory_summary_generation(self):
        """Test that summary can be generated."""
        inventory = DataInventory()
        summary = inventory.summary()
        self.assertIsNotNone(summary)
        self.assertIn("Data Inventory Summary", summary)
        self.assertIn("gdsolver", summary)
        self.assertIn("geometry-dash-rl", summary)

    def test_inventory_get_discovered(self):
        """Test retrieving discovered data dict."""
        inventory = DataInventory()
        discovered = inventory.get_discovered()
        self.assertIsInstance(discovered, dict)
        self.assertGreater(len(discovered), 0)


class TestGDSolverLoader(unittest.TestCase):
    """Tests for gdsolver dump loader."""

    def setUp(self):
        """Set up test fixtures."""
        self.loader = GDSolverLoader()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_loader_initialization(self):
        """Test loader initializes properly."""
        self.assertIsNotNone(self.loader)
        self.assertIsNotNone(self.loader.MODE_MAP)
        self.assertIsNotNone(self.loader.CONTACT_MAP)

    def test_create_and_load_test_dump(self):
        """Test creating and loading a test dump CSV."""
        dump_path = os.path.join(self.temp_dir, "test_dump.csv")

        # Create test dump
        GDSolverLoader.create_test_dump(dump_path, num_ticks=100)
        self.assertTrue(os.path.exists(dump_path))

        # Load it
        batch = self.loader.load_dump(dump_path, level_id="test_level")
        self.assertIsInstance(batch, TransitionBatch)
        self.assertEqual(len(batch), 100)

    def test_load_dump_transitions_properties(self):
        """Test that loaded transitions have correct properties."""
        dump_path = os.path.join(self.temp_dir, "test_dump.csv")
        GDSolverLoader.create_test_dump(dump_path, num_ticks=50)

        batch = self.loader.load_dump(dump_path)

        # Check first transition
        first = batch.transitions[0]
        self.assertEqual(first.tick, 0)
        self.assertEqual(first.x, 120.0)
        self.assertEqual(first.mode, GameMode.CUBE)
        self.assertEqual(first.source, "gdsolver")

        # Check last transition
        last = batch.transitions[-1]
        self.assertEqual(last.tick, 49)

    def test_load_dump_with_level_id(self):
        """Test that level_id is preserved when loading."""
        dump_path = os.path.join(self.temp_dir, "level_1.csv")
        GDSolverLoader.create_test_dump(dump_path, num_ticks=20)

        batch = self.loader.load_dump(dump_path, level_id="Stereo Madness")
        self.assertEqual(batch.transitions[0].level_id, "Stereo Madness")

    def test_load_dump_nonexistent_file(self):
        """Test that loading nonexistent file raises error."""
        with self.assertRaises(FileNotFoundError):
            self.loader.load_dump("/nonexistent/path/dump.csv")

    def test_parse_gravity_inversion(self):
        """Test parsing gravity_mod from dump."""
        # Create a dump with gravity inverted
        dump_path = os.path.join(self.temp_dir, "gravity_dump.csv")

        import csv
        with open(dump_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                "tick", "x", "y", "vx", "vy", "rotation",
                "mode", "gravity_mod", "size_mod", "speed_scaling",
                "grounded", "contact_type", "death", "input_held", "input_pressed"
            ])
            writer.writeheader()
            # Gravity inverted
            writer.writerow({
                "tick": 0,
                "x": 100.0,
                "y": 100.0,
                "vx": 10.0,
                "vy": -20.0,
                "rotation": 0.0,
                "mode": "cube",
                "gravity_mod": -1.0,
                "size_mod": 1.0,
                "speed_scaling": 1.0,
                "grounded": "true",
                "contact_type": "platform",
                "death": "false",
                "input_held": "false",
                "input_pressed": "false",
            })

        batch = self.loader.load_dump(dump_path)
        t = batch.transitions[0]
        self.assertEqual(t.gravity_mod, -1.0)

    def test_parse_different_modes(self):
        """Test parsing different game modes."""
        dump_path = os.path.join(self.temp_dir, "modes_dump.csv")

        import csv
        with open(dump_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                "tick", "x", "y", "vx", "vy", "rotation",
                "mode", "gravity_mod", "size_mod", "speed_scaling",
                "grounded", "contact_type", "death", "input_held", "input_pressed"
            ])
            writer.writeheader()
            for i, mode in enumerate(["cube", "ship", "ball", "ufo", "wave"]):
                writer.writerow({
                    "tick": i,
                    "x": 100.0 + i * 10,
                    "y": 100.0,
                    "vx": 10.0,
                    "vy": 0.0,
                    "rotation": 0.0,
                    "mode": mode,
                    "gravity_mod": 1.0,
                    "size_mod": 1.0,
                    "speed_scaling": 1.0,
                    "grounded": "false",
                    "contact_type": "air",
                    "death": "false",
                    "input_held": "false",
                    "input_pressed": "false",
                })

        batch = self.loader.load_dump(dump_path)
        modes_loaded = [t.mode for t in batch.transitions]
        expected = [GameMode.CUBE, GameMode.SHIP, GameMode.BALL, GameMode.UFO, GameMode.WAVE]
        self.assertEqual(modes_loaded, expected)


if __name__ == '__main__':
    unittest.main()
