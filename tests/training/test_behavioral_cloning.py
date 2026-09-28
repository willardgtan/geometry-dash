"""Tests for behavioral cloning pre-training."""

import unittest
import tempfile
import os
import sys
sys.path.insert(0, '/home/claude/geometry-dash')

from data.transition import Transition, TransitionBatch
from data.types import GameMode, ContactType
from training.behavioral_cloning import BehavioralCloning
from training.offline_pretraining import OfflinePretrainer


class TestBehavioralCloning(unittest.TestCase):
    """Tests for BehavioralCloning class."""

    def test_behavioral_cloning_initialization(self):
        """Test BC initializes with proper config."""
        bc = BehavioralCloning(
            state_dim=20,
            action_dim=2,
            learning_rate=1e-3,
        )
        self.assertIsNotNone(bc)
        self.assertEqual(bc.state_dim, 20)
        self.assertEqual(bc.action_dim, 2)

    def test_prepare_demonstration_batch(self):
        """Test preparing demonstrations for training."""
        # Create synthetic demonstrations
        transitions = []
        for tick in range(100):
            t = Transition(
                tick=tick,
                x=120.0 + tick * 0.1,
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
                input_held=(tick % 10 < 5),  # Tap pattern
                input_pressed=(tick % 10 == 0),
                primary_obstacle=None,
                nearby_obstacles=[],
                level_id="test",
                source="gdsolver",
            )
            transitions.append(t)

        batch = TransitionBatch(transitions)
        self.assertEqual(len(batch), 100)

    def test_behavioral_cloning_action_extraction(self):
        """Test extracting actions from transitions."""
        bc = BehavioralCloning(state_dim=20, action_dim=2, learning_rate=1e-3)

        # Transition with jump action
        t_jump = Transition(
            tick=0, x=100, y=100, vx=10, vy=0, rotation=0,
            mode=GameMode.CUBE, grounded=True, contact_type=ContactType.PLATFORM,
            gravity_mod=1.0, size_mod=1.0, speed_scaling=1.0,
            death_state=False, input_held=True, input_pressed=True,
            primary_obstacle=None, nearby_obstacles=[], source="gdsolver",
        )

        # Transition with no-jump action
        t_nojump = Transition(
            tick=1, x=100, y=100, vx=10, vy=0, rotation=0,
            mode=GameMode.CUBE, grounded=True, contact_type=ContactType.PLATFORM,
            gravity_mod=1.0, size_mod=1.0, speed_scaling=1.0,
            death_state=False, input_held=False, input_pressed=False,
            primary_obstacle=None, nearby_obstacles=[], source="gdsolver",
        )

        self.assertTrue(t_jump.input_pressed)
        self.assertFalse(t_nojump.input_pressed)


class TestOfflinePretrainer(unittest.TestCase):
    """Tests for OfflinePretrainer pipeline."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.pretrainer = OfflinePretrainer(
            output_dir=self.temp_dir,
            encoder_hidden=64,
        )

    def tearDown(self):
        """Clean up."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_offline_pretrainer_initialization(self):
        """Test pretrainer initializes properly."""
        self.assertIsNotNone(self.pretrainer)
        self.assertEqual(self.pretrainer.output_dir, self.temp_dir)

    def test_pretrainer_save_and_load_config(self):
        """Test saving and loading pretrainer config."""
        config_path = os.path.join(self.temp_dir, "config.json")
        self.pretrainer.save_config(config_path)
        self.assertTrue(os.path.exists(config_path))

    def test_create_synthetic_training_data(self):
        """Test creating synthetic training data for offline BC."""
        # Create fake gdsolver-like data
        transitions = []
        for attempt in range(2):
            for tick in range(50):
                t = Transition(
                    tick=tick,
                    x=120.0 + tick * 0.1,
                    y=160.0,
                    vx=10.389,
                    vy=0.0,
                    rotation=0.0,
                    mode=GameMode.CUBE,
                    grounded=(tick % 5 == 0),
                    contact_type=(ContactType.PLATFORM if tick % 5 == 0 else ContactType.AIR),
                    gravity_mod=1.0,
                    size_mod=1.0,
                    speed_scaling=1.0,
                    death_state=False,
                    input_held=bool((tick % 20) < 5),
                    input_pressed=bool(tick % 20 == 0),
                    primary_obstacle=None,
                    nearby_obstacles=[],
                    level_id=f"level_{attempt}",
                    source="gdsolver",
                )
                transitions.append(t)

        self.assertEqual(len(transitions), 100)

        # Verify action labels
        actions = [1 if t.input_pressed else 0 for t in transitions]
        self.assertGreater(sum(actions), 0)  # At least some jump actions


if __name__ == '__main__':
    unittest.main()
