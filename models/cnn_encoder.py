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
    CNN encoder for 84×84 RGB frames to latent state representation.

    Architecture:
    - Input: (batch_size, 84, 84, 3)
    - Conv2D(3, 32, kernel=8, stride=4) + ReLU
    - Conv2D(32, 64, kernel=4, stride=2) + ReLU
    - Conv2D(64, 64, kernel=3, stride=1) + ReLU
    - Flatten
    - Dense(7*7*64, 512) + ReLU
    - Dense(512, latent_dim) → latent state

    This is scaled-down from ResNet-18 (which would be overkill for 84×84 GD frames).
    """

    def __init__(self, latent_dim=256, input_channels=3, frame_size=84):
        """Initialize CNN encoder."""
        self.latent_dim = latent_dim
        self.input_channels = input_channels
        self.frame_size = frame_size

        # Build model
        self.layers = self._build_model()
        self._print_architecture()

    def _build_model(self):
        """Build encoder architecture."""
        layers = []

        # Conv block 1: 84x84x3 -> 20x20x32
        layers.append(("conv1", SimpleConv2D(self.input_channels, 32, kernel_size=8, stride=4)))
        layers.append(("relu1", "ReLU"))

        # Conv block 2: 20x20x32 -> 9x9x64
        layers.append(("conv2", SimpleConv2D(32, 64, kernel_size=4, stride=2)))
        layers.append(("relu2", "ReLU"))

        # Conv block 3: 9x9x64 -> 7x7x64
        layers.append(("conv3", SimpleConv2D(64, 64, kernel_size=3, stride=1)))
        layers.append(("relu3", "ReLU"))

        # Flatten: 7*7*64 = 3136
        layers.append(("flatten", "Flatten(3136)"))

        # Dense block 1: 3136 -> 512
        layers.append(("dense1", SimpleDense(3136, 512)))
        layers.append(("relu4", "ReLU"))

        # Dense block 2: 512 -> latent_dim
        layers.append(("dense2", SimpleDense(512, self.latent_dim)))

        return layers

    def _print_architecture(self):
        """Print model architecture for verification."""
        pass  # In practice, would print layer shapes

    def __repr__(self):
        return f"CNNEncoder(latent_dim={self.latent_dim}, input={self.frame_size}x{self.frame_size}x{self.input_channels})"

    @staticmethod
    def calculate_conv_output_size(input_size, kernel_size, stride, padding=0):
        """Calculate output size after convolution."""
        return (input_size - kernel_size + 2 * padding) // stride + 1

    @staticmethod
    def count_parameters():
        """Estimate total parameters."""
        # Conv1: 3*8*8*32 + 32 = 6144 + 32
        # Conv2: 32*4*4*64 + 64 = 32768 + 64
        # Conv3: 64*3*3*64 + 64 = 36864 + 64
        # Dense1: 3136*512 + 512 = 1605632 + 512
        # Dense2: 512*256 + 256 = 131072 + 256
        total = 6144 + 32 + 32768 + 64 + 36864 + 64 + 1605632 + 512 + 131072 + 256
        return total

    def info(self):
        """Print model info."""
        print(f"Model: {self}")
        print(f"Total parameters: {self.count_parameters():,}")
        print("Layers:")
        for name, layer in self.layers:
            if layer != "ReLU" and layer != "Flatten(3136)":
                print(f"  {name}: {layer}")
