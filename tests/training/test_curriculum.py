"""Tests for curriculum initialization."""

import unittest
import sys
sys.path.insert(0, '/home/claude/geometry-dash')

from training.curriculum_from_wiki import CurriculumInitializer


class TestCurriculumInitializer(unittest.TestCase):
    """Tests for CurriculumInitializer."""

    def setUp(self):
        """Set up test fixtures."""
        self.curriculum = CurriculumInitializer()

    def test_curriculum_loads(self):
        """Test that curriculum loads successfully."""
        self.assertIsNotNone(self.curriculum)
        self.assertIsNotNone(self.curriculum.curriculum)

    def test_eight_phases(self):
        """Test that curriculum has exactly 8 phases."""
        phases = self.curriculum.curriculum["phases"]
        self.assertEqual(len(phases), 8)

    def test_phase_names(self):
        """Test that phases have correct names."""
        expected_names = [
            "Reactive",
            "Ballistic",
            "Local Geometry",
            "State-Dependent",
            "Mode Transition",
            "Continuous Control",
            "Long Horizon",
            "Generalization",
        ]
        actual_names = [p["name"] for p in self.curriculum.curriculum["phases"]]
        self.assertEqual(actual_names, expected_names)

    def test_phase_gates(self):
        """Test that phase gates are properly set."""
        phases = self.curriculum.curriculum["phases"]

        # Gates should decrease as phases get harder
        gates = [p["gate_threshold"] for p in phases]
        self.assertEqual(gates[0], 0.95)  # Reactive (strictest)
        self.assertEqual(gates[7], 0.70)  # Generalization (most lenient)

        # Gates should be monotonically decreasing
        for i in range(len(gates) - 1):
            self.assertGreaterEqual(gates[i], gates[i+1])

    def test_all_22_levels_assigned(self):
        """Test that all 22 official levels are assigned to phases."""
        assigned_level_ids = set(self.curriculum.curriculum["level_assignments"].keys())
        expected_ids = set(range(1, 23))
        self.assertEqual(assigned_level_ids, expected_ids)

    def test_level_phase_mapping(self):
        """Test that specific levels map to expected phases."""
        # Stereo Madness (level 1) → Phase 0 (Reactive)
        level_1_phase = self.curriculum.get_level_phase(1)
        self.assertEqual(level_1_phase["phase"], 0)
        self.assertEqual(level_1_phase["level_name"], "Stereo Madness")

        # Can't Let Go (level 6) → Phase 3 (State-Dependent, orbs)
        level_6_phase = self.curriculum.get_level_phase(6)
        self.assertEqual(level_6_phase["phase"], 3)
        self.assertEqual(level_6_phase["level_name"], "Can't Let Go")

        # Clusterfuck (level 9) → Phase 4 (Mode Transition, portal)
        level_9_phase = self.curriculum.get_level_phase(9)
        self.assertEqual(level_9_phase["phase"], 4)
        self.assertEqual(level_9_phase["level_name"], "Clusterfuck")

    def test_get_phase_levels(self):
        """Test retrieving levels for a specific phase."""
        # Phase 0 (Reactive) should have level 1
        phase_0_levels = self.curriculum.get_phase_levels(0)
        level_ids = [l["id"] for l in phase_0_levels]
        self.assertIn(1, level_ids)

        # Phase 3 (State-Dependent) should have orb/pad levels
        phase_3_levels = self.curriculum.get_phase_levels(3)
        self.assertGreater(len(phase_3_levels), 0)

    def test_phase_definitions(self):
        """Test that phases have all required fields."""
        for phase_idx in range(8):
            phase = self.curriculum.get_phase(phase_idx)
            self.assertIsNotNone(phase)
            self.assertIn("phase", phase)
            self.assertIn("name", phase)
            self.assertIn("description", phase)
            self.assertIn("goal", phase)
            self.assertIn("mechanics", phase)
            self.assertIn("levels", phase)
            self.assertIn("gate_threshold", phase)

    def test_curriculum_summary(self):
        """Test that curriculum summary generates without error."""
        summary = self.curriculum.summary()
        self.assertIsNotNone(summary)
        self.assertIn("Empirical Curriculum", summary)
        self.assertIn("Reactive", summary)
        self.assertIn("Generalization", summary)

    def test_phase_mechanics_progression(self):
        """Test that mechanics progress logically across phases."""
        # Phase 0 should have simple spike/block mechanics
        phase_0 = self.curriculum.get_phase(0)
        self.assertIn("spikes", phase_0["mechanics"])
        self.assertIn("blocks", phase_0["mechanics"])

        # Phase 3 should include orb/pad mechanics
        phase_3 = self.curriculum.get_phase(3)
        self.assertIn("orb", phase_3["mechanics"])
        self.assertIn("pad", phase_3["mechanics"])

        # Phase 4 should include portal mechanics
        phase_4 = self.curriculum.get_phase(4)
        self.assertIn("portal", phase_4["mechanics"])
        self.assertIn("gravity_inversion", phase_4["mechanics"])

    def test_invalid_phase_returns_none(self):
        """Test that invalid phase indices return None."""
        self.assertIsNone(self.curriculum.get_phase(8))
        self.assertIsNone(self.curriculum.get_phase(-1))

    def test_invalid_level_returns_none(self):
        """Test that invalid level IDs return None."""
        self.assertIsNone(self.curriculum.get_level_phase(99))
        self.assertIsNone(self.curriculum.get_level_phase(0))


if __name__ == '__main__':
    unittest.main()
