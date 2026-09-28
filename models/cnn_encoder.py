"""CNN encoder for visual state representation."""

import math


class SimpleConv2D:
    """Simple 2D convolution layer (for testing; use PyTorch/TensorFlow in practice)."""
    def __init__(self, in_channels, out_channels, kernel_size=3, stride=1):
        self.in_channels = in_channels
        self.out_channels = out_channels
        self.kernel_size = kernel_size
        self.stride = stride

    def __repr__(self):
        return (f"Conv2D({self.in_channels}, {self.out_channels}, "
                f"kernel={self.kernel_size}, stride={self.stride})")


class SimpleDense:
    """Simple dense layer (for testing)."""
    def __init__(self, in_features, out_features):
        self.in_features = in_features
        self.out_features = out_features

    def __repr__(self):
        return f"Dense({self.in_features}, {self.out_features})"


class CNNEncoder:
    """
    CNN encoder for game-bot perception grid (16×24×4) to latent representation.

    Architecture (adapted for 16×24×4 input):
    - Input: (batch, 16, 24, 4)
    - Conv2D(4, 32, kernel=3, stride=1) + ReLU → (16, 24, 32)
    - Conv2D(32, 64, kernel=3, stride=1) + ReLU → (16, 24, 64)
    - Flatten
    - Dense(16*24*64, 512) + ReLU
    - Dense(512, latent_dim) → latent vector

    Lighter architecture suitable for small perception grid.
    """

    def __init__(self, latent_dim=256, input_channels=4, input_height=16, input_width=24):
        """Initialize CNN encoder."""
        self.latent_dim = latent_dim
        self.input_channels = input_channels
        self.input_height = input_height
        self.input_width = input_width
        self.deterministic = False

        # Build model
        self.layers = self._build_model()
        self._print_architecture()

    def _build_model(self):
        """Build encoder architecture."""
        layers = []

        # Conv block 1: 16×24×4 -> 16×24×32
        layers.append(("conv1", SimpleConv2D(self.input_channels, 32, kernel_size=3, stride=1)))
        layers.append(("relu1", "ReLU"))

        # Conv block 2: 16×24×32 -> 16×24×64
        layers.append(("conv2", SimpleConv2D(32, 64, kernel_size=3, stride=1)))
        layers.append(("relu2", "ReLU"))

        # Flatten: 16*24*64 = 24576
        flat_size = self.input_height * self.input_width * 64
        layers.append(("flatten", f"Flatten({flat_size})"))

        # Dense block 1: flat_size -> 512
        layers.append(("dense1", SimpleDense(flat_size, 512)))
        layers.append(("relu3", "ReLU"))

        # Dense block 2: 512 -> latent_dim
        layers.append(("dense2", SimpleDense(512, self.latent_dim)))

        return layers

    def _print_architecture(self):
        """Print model architecture for verification."""
        pass  # In practice, would print layer shapes

    def __repr__(self):
        return f"CNNEncoder(latent_dim={self.latent_dim}, input={self.input_height}x{self.input_width}x{self.input_channels})"

    def set_deterministic(self, deterministic: bool = True):
        """Set deterministic mode (for testing)."""
        self.deterministic = deterministic

    def encode(self, batch):
        """
        Encode perception grid to latent vector.

        Args:
            batch: Input array of shape (batch_size, height, width, channels)
                   Expected: (batch_size, 16, 24, 4)

        Returns:
            Latent vectors of shape (batch_size, latent_dim)
        """
        import numpy as np

        # Simplified: just flatten and apply a linear transformation
        # In practice, would use PyTorch/TensorFlow for actual convolution
        batch_size = batch.shape[0]

        # Flatten: (batch, 16, 24, 4) -> (batch, 1536)
        flattened = batch.reshape(batch_size, -1)

        # Simple linear transformation to latent space
        # Use deterministic transformation for testing
        np.random.seed(42) if self.deterministic else None

        # Project to latent_dim with ReLU-like behavior
        # Simple projection matrix
        feature_dim = flattened.shape[1]

        # Use a simple projection: normalize and scale
        # This is deterministic and consistent
        normalized = (flattened - flattened.mean(axis=1, keepdims=True)) / (flattened.std(axis=1, keepdims=True) + 1e-7)

        # Simple linear projection to latent space
        # Use hash-based deterministic weights
        latent = np.zeros((batch_size, self.latent_dim), dtype=np.float32)

        for i in range(self.latent_dim):
            # Create deterministic weights based on layer index
            seed = 42 + i if self.deterministic else None
            if seed:
                np.random.seed(seed)
            weights = np.random.randn(feature_dim) * 0.01
            latent[:, i] = np.dot(normalized, weights)

        # Apply ReLU-like activation (clamp negative values)
        latent = np.maximum(latent, 0).astype(np.float32)

        # Normalize to have reasonable range
        latent = latent / (np.std(latent) + 1e-7)

        return latent.astype(np.float32)

    @staticmethod
    def calculate_conv_output_size(input_size, kernel_size, stride, padding=0):
        """Calculate output size after convolution."""
        return (input_size - kernel_size + 2 * padding) // stride + 1

    @staticmethod
    def count_parameters():
        """Estimate total parameters."""
        # Conv1: 4*3*3*32 + 32 = 1152 + 32
        # Conv2: 32*3*3*64 + 64 = 18432 + 64
        # Dense1: (16*24*64)*512 + 512 = 12582912 + 512
        # Dense2: 512*256 + 256 = 131072 + 256
        total = 1152 + 32 + 18432 + 64 + 12582912 + 512 + 131072 + 256
        return total

    def info(self):
        """Print model info."""
        print(f"Model: {self}")
        print(f"Total parameters: {self.count_parameters():,}")
        print("Layers:")
        for name, layer in self.layers:
            if layer != "ReLU" and not str(layer).startswith("Flatten"):
                print(f"  {name}: {layer}")
