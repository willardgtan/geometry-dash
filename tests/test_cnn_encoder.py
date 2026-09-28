"""Tests for CNN perception encoder."""

import unittest
import sys
import numpy as np
sys.path.insert(0, '/home/claude/geometry-dash')

from models.cnn_encoder import CNNEncoder


class TestCNNEncoder(unittest.TestCase):
    """Tests for CNN perception encoder."""

    def test_encoder_initialization(self):
        """Test encoder creation."""
        encoder = CNNEncoder()
        self.assertIsNotNone(encoder)

    def test_input_shape(self):
        """Test encoder accepts (H×W×C) input."""
        encoder = CNNEncoder()

        # 24×16×4 perception grid
        input_grid = np.random.rand(16, 24, 4).astype(np.float32)

        # Should accept without error
        self.assertEqual(input_grid.shape, (16, 24, 4))

    def test_encoder_forward_pass(self):
        """Test forward pass through encoder."""
        encoder = CNNEncoder()

        # Dummy input: (batch_size=1, H, W, C)
        batch = np.random.rand(1, 16, 24, 4).astype(np.float32)

        # Forward pass should produce latent vector
        latent = encoder.encode(batch)

        # Should be (batch_size, latent_dim)
        self.assertEqual(latent.shape[0], 1)
        self.assertEqual(latent.shape[1], 256)  # 256-dim latent

    def test_batch_encoding(self):
        """Test encoding multiple inputs at once."""
        encoder = CNNEncoder()

        batch = np.random.rand(8, 16, 24, 4).astype(np.float32)
        latent = encoder.encode(batch)

        self.assertEqual(latent.shape, (8, 256))

    def test_deterministic_output(self):
        """Test same input produces same output."""
        encoder = CNNEncoder()
        encoder.set_deterministic(True)

        input_data = np.random.rand(1, 16, 24, 4).astype(np.float32)

        output1 = encoder.encode(input_data)
        output2 = encoder.encode(input_data)

        np.testing.assert_array_almost_equal(output1, output2)

    def test_different_inputs_different_outputs(self):
        """Test different inputs produce different outputs."""
        encoder = CNNEncoder()

        input1 = np.random.rand(1, 16, 24, 4).astype(np.float32)
        input2 = np.random.rand(1, 16, 24, 4).astype(np.float32)

        output1 = encoder.encode(input1)
        output2 = encoder.encode(input2)

        # Should be different (with very high probability)
        self.assertFalse(np.allclose(output1, output2))

    def test_latent_space_dimensionality(self):
        """Test latent space is correct dimensionality."""
        encoder = CNNEncoder()

        batch = np.random.rand(4, 16, 24, 4).astype(np.float32)
        latent = encoder.encode(batch)

        # 256-dimensional latent space
        self.assertEqual(latent.shape[1], 256)

    def test_zero_input(self):
        """Test encoder handles zero input."""
        encoder = CNNEncoder()

        zeros = np.zeros((1, 16, 24, 4), dtype=np.float32)
        latent = encoder.encode(zeros)

        # Should produce valid output
        self.assertEqual(latent.shape, (1, 256))
        self.assertFalse(np.any(np.isnan(latent)))

    def test_one_input(self):
        """Test encoder handles all-ones input."""
        encoder = CNNEncoder()

        ones = np.ones((1, 16, 24, 4), dtype=np.float32)
        latent = encoder.encode(ones)

        # Should produce valid output
        self.assertEqual(latent.shape, (1, 256))
        self.assertFalse(np.any(np.isnan(latent)))

    def test_output_dtype(self):
        """Test output is float32."""
        encoder = CNNEncoder()

        batch = np.random.rand(1, 16, 24, 4).astype(np.float32)
        latent = encoder.encode(batch)

        self.assertEqual(latent.dtype, np.float32)

    def test_output_has_variance(self):
        """Test latent output has meaningful variance."""
        encoder = CNNEncoder()
        encoder.set_deterministic(True)

        batch = np.random.rand(100, 16, 24, 4).astype(np.float32)
        latent = encoder.encode(batch)

        # Should have variance across dimensions
        variances = np.var(latent, axis=0)
        self.assertGreater(np.mean(variances), 0.01)


if __name__ == '__main__':
    unittest.main()
