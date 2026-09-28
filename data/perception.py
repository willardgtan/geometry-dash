"""game-bot perception grid and control scheme decoding.

Encodes game state into 24×16×4 perception grid for CNN input.
Decodes control inputs according to mode-specific semantics.
"""

import numpy as np
from typing import Dict, Any, Tuple, Optional
from data.types import GameMode


class ControlDecoder:
    """
    Interprets raw button input according to game mode control semantics.

    Different modes have different input interpretations:
    - Cube: Tap (rising edge = jump)
    - Ship: Hold (held = thrust)
    - Wave: Tap at timing
    - Ball: Tap (multiple taps = chain bounces)
    - UFO: Toggle (tap = reverse gravity)
    - Robot: Tap (double tap = double jump)
    - Spider: Hold (hold = climb)
    """

    def decode(
        self,
        mode: GameMode,
        input_pressed: bool,
        input_held: bool,
    ) -> int:
        """
        Decode control input for given mode.

        Args:
            mode: Current game mode
            input_pressed: Rising edge (not held before, held now)
            input_held: Button physically held

        Returns:
            0 = no action, 1 = action (jump/thrust/toggle)
        """
        if mode == GameMode.CUBE:
            # Tap: only rising edge produces action
            return 1 if input_pressed else 0

        elif mode == GameMode.SHIP:
            # Hold: continuous input produces continuous action
            return 1 if input_held else 0

        elif mode == GameMode.WAVE:
            # Tap with timing requirement
            return 1 if input_pressed else 0

        elif mode == GameMode.BALL:
            # Tap: can chain bounces
            return 1 if input_pressed else 0

        elif mode == GameMode.UFO:
            # Toggle: tap = reverse gravity once
            return 1 if input_pressed else 0

        elif mode == GameMode.ROBOT:
            # Tap double: two taps required for double jump
            # Simplified: treat as tap for now
            return 1 if input_pressed else 0

        elif mode == GameMode.SPIDER:
            # Hold: held = climb wall
            return 1 if input_held else 0

        else:
            # Unknown mode: default to tap
            return 1 if input_pressed else 0


class StateEncoder:
    """
    Encodes game state and obstacles into 24×16 perception grids.

    Each grid represents a birds-eye 2D view of the level with player or
    obstacles occupying grid cells based on world coordinates.
    """

    # Grid dimensions match game-bot perception
    GRID_WIDTH = 24
    GRID_HEIGHT = 16

    # World coordinates (rough level dimensions)
    LEVEL_WIDTH = 600  # Approximate level width in game units
    LEVEL_HEIGHT = 360  # Approximate level height in game units

    def __init__(self):
        """Initialize encoder."""
        self.grid_width = self.GRID_WIDTH
        self.grid_height = self.GRID_HEIGHT

    def world_to_grid(self, x: float, y: float) -> Tuple[int, int]:
        """
        Convert world coordinates to grid coordinates.

        Args:
            x: World x coordinate
            y: World y coordinate

        Returns:
            (grid_x, grid_y) clamped to [0, width) and [0, height)
        """
        # Normalize to 0-1 range
        norm_x = x / self.LEVEL_WIDTH
        norm_y = y / self.LEVEL_HEIGHT

        # Clamp to [0, 1]
        norm_x = max(0.0, min(1.0, norm_x))
        norm_y = max(0.0, min(1.0, norm_y))

        # Convert to grid
        grid_x = int(norm_x * (self.grid_width - 1))
        grid_y = int(norm_y * (self.grid_height - 1))

        return grid_x, grid_y

    def encode_player(self, transition) -> np.ndarray:
        """
        Encode player position into grid.

        Args:
            transition: Single transition with player state

        Returns:
            Grid array (H×W×1) with player marked
        """
        grid = np.zeros((self.grid_height, self.grid_width, 1), dtype=np.float32)

        grid_x, grid_y = self.world_to_grid(transition.x, transition.y)
        grid[grid_y, grid_x, 0] = 1.0

        return grid

    def encode_obstacles(self, obstacles: Dict[str, Dict[str, Any]]) -> np.ndarray:
        """
        Encode obstacle positions into grid.

        Args:
            obstacles: Dict mapping geometry_id to obstacle dict
                      {geometry_id: {"x": ..., "y": ..., "width": ..., "height": ...}}

        Returns:
            Grid array (H×W×1) with obstacles marked
        """
        grid = np.zeros((self.grid_height, self.grid_width, 1), dtype=np.float32)

        for geom_id, obstacle in obstacles.items():
            x = obstacle.get("x", 0)
            y = obstacle.get("y", 0)
            width = obstacle.get("width", 20)
            height = obstacle.get("height", 20)

            # Mark all cells that overlap the obstacle
            x1, y1 = self.world_to_grid(x, y)
            x2, y2 = self.world_to_grid(x + width, y + height)

            # Clamp to grid
            x1 = max(0, min(self.grid_width - 1, x1))
            x2 = max(0, min(self.grid_width - 1, x2))
            y1 = max(0, min(self.grid_height - 1, y1))
            y2 = max(0, min(self.grid_height - 1, y2))

            # Ensure x1 <= x2, y1 <= y2
            if x1 > x2:
                x1, x2 = x2, x1
            if y1 > y2:
                y1, y2 = y2, y1

            # Mark cells
            grid[y1:y2+1, x1:x2+1, 0] = 1.0

        return grid


class GameBotGrid:
    """
    24×16×4 perception grid used by game-bot.

    Channels:
    0: Player position
    1: Obstacles (spikes, blocks)
    2: Collectibles (orbs, pads)
    3: Portals and mode indicators
    """

    def __init__(self):
        """Initialize 4-channel perception grid."""
        self.width = 24
        self.height = 16
        self.channels = 4

        # Initialize all channels to zero
        self._channels = [
            np.zeros((self.height, self.width), dtype=np.float32)
            for _ in range(self.channels)
        ]

    def set_channel(self, channel_idx: int, data: np.ndarray) -> None:
        """
        Set one channel.

        Args:
            channel_idx: Channel index (0-3)
            data: 2D array (H×W)
        """
        if data.shape != (self.height, self.width):
            raise ValueError(f"Expected shape ({self.height}, {self.width}), got {data.shape}")
        self._channels[channel_idx] = data.astype(np.float32)

    def get_channel(self, channel_idx: int) -> np.ndarray:
        """
        Get one channel.

        Args:
            channel_idx: Channel index (0-3)

        Returns:
            2D array (H×W)
        """
        return self._channels[channel_idx].copy()

    def stack_channels(self) -> np.ndarray:
        """
        Stack all channels into single array.

        Returns:
            3D array (H×W×C)
        """
        return np.stack(self._channels, axis=-1)

    def reset(self) -> None:
        """Clear all channels."""
        for i in range(self.channels):
            self._channels[i] = np.zeros((self.height, self.width), dtype=np.float32)
