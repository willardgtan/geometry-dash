"""Game state type definitions and enums."""

from enum import Enum


class GameMode(Enum):
    """Supported game modes in Geometry Dash."""
    CUBE = "cube"
    SHIP = "ship"
    BALL = "ball"
    UFO = "ufo"
    WAVE = "wave"
    ROBOT = "robot"
    SPIDER = "spider"


class ObstacleType(Enum):
    """Types of obstacles and interactive elements."""
    SPIKE = "spike"
    BLOCK = "block"
    ORB = "orb"
    PAD = "pad"
    PORTAL = "portal"
    MOVING_GEOMETRY = "moving_geometry"


class ContactType(Enum):
    """Types of contact with game elements."""
    PLATFORM = "platform"
    SPIKE = "spike"
    ORB = "orb"
    PAD = "pad"
    AIR = "air"
