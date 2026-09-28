"""Core physics engine for all 7 Geometry Dash game modes.

Implements calibrated physics constants from geometry-dash-rl,
collision detection, and mode-specific mechanics.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Tuple
from data.types import GameMode, ContactType
from data.transition import Transition


@dataclass
class GameState:
    """Current game state (mutable, for simulation)."""

    # Position and velocity
    x: float
    y: float
    vx: float
    vy: float
    rotation: float = 0.0

    # Game mode and state
    mode: GameMode = GameMode.CUBE
    grounded: bool = True
    gravity_mod: float = 1.0
    size_mod: float = 1.0
    speed_scaling: float = 1.0

    # Mode-specific state
    double_jump_available: bool = False
    wall_attached: bool = False
    tilt_angle: float = 0.0  # Ship tilt

    # Metadata
    death_state: bool = False
    level_id: Optional[str] = None
    attempt_id: Optional[str] = None

    def to_transition(self, tick: int) -> Transition:
        """Convert to transition for storage/training."""
        return Transition(
            tick=tick,
            x=self.x,
            y=self.y,
            vx=self.vx,
            vy=self.vy,
            rotation=self.rotation,
            mode=self.mode,
            grounded=self.grounded,
            contact_type=ContactType.AIR,  # Would be filled by collision detection
            input_pressed=False,
            input_held=False,
            gravity_mod=self.gravity_mod,
            size_mod=self.size_mod,
            speed_scaling=self.speed_scaling,
            death_state=self.death_state,
            level_id=self.level_id,
            attempt_id=self.attempt_id,
            source="simulator",
        )


class PhysicsEngine:
    """Simulates physics for all 7 Geometry Dash game modes."""

    # Calibrated physics constants from geometry-dash-rl
    MODE_CONSTANTS = {
        GameMode.CUBE: {
            "jump_velocity": 21.80,
            "gravity": 103.0,
            "max_airtime_s": 0.417,
            "horizontal_speed": 10.389,
            "control_type": "tap",
        },
        GameMode.SHIP: {
            "thrust": 80.0,
            "gravity": 50.0,
            "max_tilt_degrees": 45,
            "control_type": "hold",
        },
        GameMode.WAVE: {
            "jump_velocity": 18.0,
            "gravity": 103.0,
            "frequency_frames": 30,
            "control_type": "tap_timing",
        },
        GameMode.BALL: {
            "jump_velocity": 20.0,
            "bounce_factor": 0.8,
            "gravity": 103.0,
            "control_type": "tap",
        },
        GameMode.UFO: {
            "vertical_speed": 25.0,
            "gravity": 0.0,  # No standard gravity; uses vertical_speed instead
            "gravity_reversible": True,
            "control_type": "toggle_gravity",
        },
        GameMode.ROBOT: {
            "jump_velocity": 21.80,
            "gravity": 103.0,
            "double_jump": True,
            "control_type": "tap_double",
        },
        GameMode.SPIDER: {
            "jump_velocity": 21.80,
            "gravity": 103.0,
            "wall_climb": True,
            "control_type": "jump_and_hold",
        },
    }

    def get_mode_constants(self, mode: GameMode) -> Dict[str, float]:
        """Get physics constants for a mode."""
        return self.MODE_CONSTANTS.get(mode, {})

    def apply_physics(
        self,
        state: GameState,
        action: int,
        dt: float = 1.0/240.0,
    ) -> GameState:
        """
        Apply one physics tick.

        Args:
            state: Current game state
            action: 0=no action, 1=action (mode-specific)
            dt: Time step in seconds (default 1/240 Hz)

        Returns:
            Updated game state
        """
        # Create copy to modify
        new_state = GameState(
            x=state.x,
            y=state.y,
            vx=state.vx,
            vy=state.vy,
            rotation=state.rotation,
            mode=state.mode,
            grounded=state.grounded,
            gravity_mod=state.gravity_mod,
            size_mod=state.size_mod,
            speed_scaling=state.speed_scaling,
            double_jump_available=state.double_jump_available,
            wall_attached=state.wall_attached,
            tilt_angle=state.tilt_angle,
            death_state=state.death_state,
        )

        # Apply mode-specific physics
        if state.mode == GameMode.CUBE:
            self._update_cube(new_state, action, dt)
        elif state.mode == GameMode.SHIP:
            self._update_ship(new_state, action, dt)
        elif state.mode == GameMode.WAVE:
            self._update_wave(new_state, action, dt)
        elif state.mode == GameMode.BALL:
            self._update_ball(new_state, action, dt)
        elif state.mode == GameMode.UFO:
            self._update_ufo(new_state, action, dt)
        elif state.mode == GameMode.ROBOT:
            self._update_robot(new_state, action, dt)
        elif state.mode == GameMode.SPIDER:
            self._update_spider(new_state, action, dt)

        return new_state

    def _update_cube(self, state: GameState, action: int, dt: float) -> None:
        """Update cube mode physics."""
        constants = self.MODE_CONSTANTS[GameMode.CUBE]

        # Jump on action (rising edge)
        if action == 1 and state.grounded:
            state.vy = constants["jump_velocity"]
            state.grounded = False

        # Gravity
        gravity = constants["gravity"] * state.gravity_mod
        state.vy -= gravity * dt

        # Horizontal motion (constant)
        state.vx = constants["horizontal_speed"] * state.speed_scaling
        state.x += state.vx * dt

        # Vertical motion
        state.y -= state.vy * dt  # Negative because vy is up

        # Clamping (don't go below ground)
        if state.y >= 105.0:
            state.y = 105.0
            state.vy = 0.0
            state.grounded = True

    def _update_ship(self, state: GameState, action: int, dt: float) -> None:
        """Update ship mode physics."""
        constants = self.MODE_CONSTANTS[GameMode.SHIP]

        # Thrust on action (held button)
        if action == 1:
            state.vy += constants["thrust"] * dt

        # Gravity (weaker than cube)
        gravity = constants["gravity"] * state.gravity_mod
        state.vy -= gravity * dt

        # Horizontal motion (constant)
        state.x += state.vx * dt

        # Vertical motion
        state.y -= state.vy * dt

        # Tilt based on input
        if action == 1:
            state.tilt_angle = min(state.tilt_angle + 5, 45)
        else:
            state.tilt_angle = max(state.tilt_angle - 5, -45)

        # Ground clamping
        if state.y >= 105.0:
            state.y = 105.0
            state.grounded = True

    def _update_wave(self, state: GameState, action: int, dt: float) -> None:
        """Update wave mode physics."""
        constants = self.MODE_CONSTANTS[GameMode.WAVE]

        # Jump on action
        if action == 1:
            state.vy = constants["jump_velocity"]

        # Gravity
        gravity = constants["gravity"] * state.gravity_mod
        state.vy -= gravity * dt

        # Horizontal motion
        state.x += state.vx * dt

        # Vertical motion
        state.y -= state.vy * dt

        # Ground clamping
        if state.y >= 105.0:
            state.y = 105.0
            state.grounded = True

    def _update_ball(self, state: GameState, action: int, dt: float) -> None:
        """Update ball mode physics."""
        constants = self.MODE_CONSTANTS[GameMode.BALL]

        # Jump on action (can bounce multiple times)
        if action == 1:
            state.vy = constants["jump_velocity"]

        # Gravity
        gravity = constants["gravity"] * state.gravity_mod
        state.vy -= gravity * dt

        # Horizontal motion
        state.x += state.vx * dt

        # Vertical motion
        state.y -= state.vy * dt

        # Ground clamping
        if state.y >= 105.0:
            state.y = 105.0
            state.grounded = True

    def _update_ufo(self, state: GameState, action: int, dt: float) -> None:
        """Update UFO mode physics."""
        constants = self.MODE_CONSTANTS[GameMode.UFO]

        # Vertical speed (constant rate up/down based on gravity)
        vertical_speed = constants["vertical_speed"]
        if state.gravity_mod > 0:
            state.vy = vertical_speed
        else:
            state.vy = -vertical_speed

        # Horizontal motion
        state.x += state.vx * dt

        # Vertical motion
        state.y -= state.vy * dt

        # No ground clamping in UFO mode - can go anywhere

    def _update_robot(self, state: GameState, action: int, dt: float) -> None:
        """Update robot mode physics (double jump)."""
        constants = self.MODE_CONSTANTS[GameMode.ROBOT]

        # First jump
        if action == 1 and state.grounded:
            state.vy = constants["jump_velocity"]
            state.grounded = False
            state.double_jump_available = True

        # Double jump
        elif action == 1 and state.double_jump_available:
            state.vy = constants["jump_velocity"]
            state.double_jump_available = False

        # Gravity
        gravity = constants["gravity"] * state.gravity_mod
        state.vy -= gravity * dt

        # Horizontal motion
        state.x += state.vx * dt

        # Vertical motion
        state.y -= state.vy * dt

        # Ground clamping
        if state.y >= 105.0:
            state.y = 105.0
            state.vy = 0.0
            state.grounded = True
            state.double_jump_available = False

    def _update_spider(self, state: GameState, action: int, dt: float) -> None:
        """Update spider mode physics (wall climb)."""
        constants = self.MODE_CONSTANTS[GameMode.SPIDER]

        # Jump or wall climb
        if action == 1:
            if state.wall_attached:
                # Climb on wall
                state.vy = constants["jump_velocity"]
                state.wall_attached = False
            elif state.grounded:
                # Jump from ground
                state.vy = constants["jump_velocity"]
                state.grounded = False

        # Gravity
        gravity = constants["gravity"] * state.gravity_mod
        if not state.wall_attached:
            state.vy -= gravity * dt

        # Horizontal motion
        state.x += state.vx * dt

        # Vertical motion
        state.y -= state.vy * dt

        # Ground clamping
        if state.y >= 105.0:
            state.y = 105.0
            state.vy = 0.0
            state.grounded = True

    def check_collision(
        self,
        state: GameState,
        obstacles: Dict[str, Dict[str, Any]],
        player_radius: float = 10.0,
    ) -> bool:
        """
        Check if player collides with any obstacle.

        Args:
            state: Current game state
            obstacles: Dict of {geometry_id: obstacle_data}
            player_radius: Player collision radius

        Returns:
            True if collision detected
        """
        for geom_id, obstacle in obstacles.items():
            x = obstacle.get("x", 0)
            y = obstacle.get("y", 0)
            width = obstacle.get("width", 20)
            height = obstacle.get("height", 20)

            # Circle-AABB collision
            closest_x = max(x, min(state.x, x + width))
            closest_y = max(y, min(state.y, y + height))

            dx = state.x - closest_x
            dy = state.y - closest_y
            distance_sq = dx * dx + dy * dy

            if distance_sq < (player_radius * player_radius):
                return True

        return False
