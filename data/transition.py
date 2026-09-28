"""Core transition data structure for 240-Hz game state."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from data.types import GameMode, ContactType


@dataclass
class Transition:
    """
    Represents a single 240-Hz physics tick from Geometry Dash.

    This is the canonical representation used throughout the pipeline:
    - gdsolver dumps → Transition objects
    - geometry-dash-rl simulator → Transition objects
    - Real game state → Transition objects

    All coordinates are in game world units.
    Tick is the 240-Hz physics tick (not 60-Hz frame).
    """

    # Core physics state (240-Hz tick basis)
    tick: int
    x: float
    y: float
    vx: float
    vy: float
    rotation: float

    # Game state
    mode: GameMode
    gravity_mod: float  # ±1.0
    size_mod: float    # typically 1.0 or 0.5
    speed_scaling: float  # typically 1.0, modified by speed portals

    # Contact and grounding
    grounded: bool
    contact_type: ContactType

    # Player state
    death_state: bool

    # Input (action at this tick)
    input_held: bool  # Button held
    input_pressed: bool  # Button pressed (rising edge)

    # Local geometry and obstacles
    primary_obstacle: Optional[Dict[str, Any]] = None  # Nearest obstacle
    nearby_obstacles: List[Dict[str, Any]] = field(default_factory=list)

    # Metadata
    level_id: Optional[str] = None
    attempt_id: Optional[str] = None
    source: str = "unknown"  # "gdsolver", "simulator", "real_game"


@dataclass
class TransitionBatch:
    """Batch of Transitions, typically from one level attempt."""

    transitions: List[Transition]

    def __post_init__(self):
        """Validate transitions are in tick order."""
        if len(self.transitions) > 1:
            ticks = [t.tick for t in self.transitions]
            assert ticks == sorted(ticks), "Transitions must be sorted by tick"

    def __len__(self):
        return len(self.transitions)

    def __getitem__(self, idx):
        return self.transitions[idx]
