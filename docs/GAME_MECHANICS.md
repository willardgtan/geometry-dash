# Geometry Dash Game Mechanics Reference

Complete technical reference for all game mechanics, physics, and controls.

## Game Modes (7 total)

### Cube (Default)
- **Jump Velocity**: 21.80 blocks/s (measured from 18 real jumps)
- **Gravity**: 103.0 blocks/s²
- **Max Airtime**: 0.417 seconds (25 × 60-Hz frames)
- **Horizontal Speed**: 10.389 blocks/s (constant)
- **Control**: Tap to jump (button press = one jump impulse)
- **Collision**: Circle-AABB (circular player, rectangular obstacles)

### Ship
- **Thrust**: 80.0 blocks/s² (up when button held)
- **Gravity**: 50.0 blocks/s²
- **Max Tilt**: 45 degrees
- **Control**: Hold button to climb (continuous input)
- **Notes**: Different physics than cube; requires continuous control

### Wave
- **Jump Velocity**: 18.0 blocks/s
- **Gravity**: 103.0 blocks/s²
- **Frequency**: 30-frame cycle (0.5 seconds)
- **Control**: Tap at specific timing in cycle
- **Notes**: Timing-sensitive; small error window

### Ball
- **Jump Velocity**: 20.0 blocks/s
- **Bounce Factor**: 0.8 (velocity multiplier on contact)
- **Gravity**: 103.0 blocks/s²
- **Control**: Tap to jump (multiple bounces possible)
- **Notes**: Can chain bounces off obstacles

### UFO
- **Vertical Speed**: 25.0 blocks/s
- **Gravity**: Reversible (toggle with button or portal)
- **Control**: Toggle gravity direction (button = reverse)
- **Notes**: No standard gravity; gravity_mod inverts coordinate system

### Robot
- **Double Jump**: Two sequential jump impulses (timing required)
- **Jump Velocity**: 21.80 blocks/s
- **Gravity**: 103.0 blocks/s²
- **Control**: Tap twice for double-jump
- **Notes**: Variant of cube with extra jump

### Spider
- **Wall Climb**: Can grip walls and climb vertically
- **Gravity**: 103.0 blocks/s² (except on walls)
- **Control**: Jump to walls, hold to climb
- **Notes**: Wall-attached state changes physics

## Obstacles & Interactive Elements

### Spike
- **Collision Type**: SPIKE
- **Effect**: Instant death on contact
- **Shape**: Triangular (circle-point collision)
- **Contact Type**: ContactType.SPIKE

### Block
- **Collision Type**: PLATFORM
- **Effect**: None (solid obstacle, no special effect)
- **Shape**: Rectangular (AABB)
- **Contact Type**: ContactType.PLATFORM

### Orb
- **Collision Type**: ORB
- **Effect**: Bounce with vy = -25.0 (upward impulse)
- **Radius**: ~15 blocks
- **Contact Type**: ContactType.ORB
- **Notes**: Can be yellow (normal) or red (inverse gravity)

### Pad
- **Collision Type**: PAD
- **Effect**: Bounce with vy = -30.0 (stronger than orb)
- **Shape**: Rectangular platform
- **Contact Type**: ContactType.PAD
- **Notes**: Yellow (normal) or blue (half-gravity)

### Portal
- **Collision Type**: PORTAL
- **Effects**:
  - gravity_mod: toggle ±1.0 (gravity inversion)
  - vy: negate (flip vertical velocity)
  - mode: change game mode
  - speed_scaling: modify horizontal speed
- **Shape**: Rectangular entry/exit
- **Types**: 
  - Gravity portal (yellow/blue)
  - Speed portal (orange, modifies speed_scaling)
  - Mode portal (white, changes mode)

### Moving Geometry
- **Collision Type**: MOVING_GEOMETRY
- **Movement**: Linear interpolation between key positions
- **Velocity**: Constant from start to end
- **Contact Type**: ContactType.PLATFORM
- **Notes**: gdsolver records separately; essential for accurate simulation

## Physics Constants (Calibrated)

Values measured from 18 real flat-ground cube jumps (geometry-dash-rl):
- Cube jump apex: 2.128 blocks
- Cube airtime: 0.417 seconds (25 × 60Hz frames = 240 physics ticks)
- Horizontal speed: 10.389 blocks/s
- Fitted jump_velocity: 21.80
- Fitted gravity: 103.0

**Precision**: High numerical precision essential for re-anchoring and contact tests. gdsolver uses 8+ decimal places to prevent rounding errors.

## Gravity Inversion (Portal/UFO)

When gravity_mod = -1.0:
- **y coordinate**: Flips (y_new = level_height - y_old)
- **vy (vertical velocity)**: Negates (vy_new = -vy_old)
- **Gravity direction**: Reverses (falls upward relative to inverted frame)
- **Coordinate system**: Effectively 180° rotation of the level

**Example**: 
- Normal: player at y=100, vy=-10 (falling down)
- Inverted: player at y=level_height-100, vy=10 (falling "down" in inverted frame = up in normal frame)

## Collision Detection

**Player Shape**: Circle (radius ~10 blocks)
**Obstacle Shapes**: 
- Blocks, spikes: AABB (axis-aligned bounding box)
- Orbs: Circle
- Platforms: AABB

**Contact Test**: Circle-AABB overlap
- Distance from circle center to nearest AABB point
- If distance < circle radius: collision

**Contact Type Resolution**:
- On platform: ContactType.PLATFORM (grounded = true, vy reset to 0)
- On spike: ContactType.SPIKE (death = true, level reset)
- On orb: ContactType.ORB (apply jump impulse)
- On pad: ContactType.PAD (apply stronger jump impulse)
- In air: ContactType.AIR (grounded = false)

## Game State Representation (20-D Vector)

Used in behavioral cloning and policy training:

```
[x, y, vx, vy, rotation,
 mode_onehot(7),
 grounded(1),
 contact_type_onehot(5),
 gravity_mod, size_mod, speed_scaling]
```

Total: 4 + 7 + 1 + 5 + 3 = 20 dimensions

## Input/Control Representation

**Binary Action**: Jump/No-Jump
- 0: Button not pressed (no-jump)
- 1: Button pressed or held (jump)

**Input State**:
- `input_held`: Button physically held down
- `input_pressed`: Rising edge (not held in previous frame, held now)

**Mode-Specific Control Semantics**:
- **Cube**: Tap (one press = one jump)
- **Ship**: Hold (continuous input = continuous thrust)
- **Wave**: Tap (tap at cycle peak)
- **Ball**: Tap (multiple taps = chain bounces)
- **UFO**: Toggle (tap = reverse gravity)
- **Robot**: Tap × 2 (two presses = double jump)
- **Spider**: Hold (hold = climb wall)

## 240-Hz vs 60-Hz Timing

- **Physics Ticks**: 240 Hz (4.17 ms per tick)
- **Rendering Frames**: 60 Hz (16.67 ms per frame)
- **Ticks per Frame**: 4
- **gdsolver Dumps**: One row per 240-Hz tick (per-physics-tick)
- **Real Game Capture**: One frame per 60-Hz render (may lose intermediate ticks)
- **Transition Tick**: Always 240-Hz basis (from gdsolver dumps)

## Official Level Difficulty Progression

22 official levels mapped to 8 curriculum phases:
- **Phase 0 (Reactive)**: Level 1 (1★) - Basic spikes and blocks
- **Phase 1 (Ballistic)**: Levels 2-3 (2-3★) - Jump timing and velocity control
- **Phase 2 (LocalGeometry)**: Levels 4-5 (4-5★) - Obstacle sequences and gaps
- **Phase 3 (StateDep)**: Levels 6-8 (6-8★) - Orbs, pads, gravity sensitivity
- **Phase 4 (ModeTransition)**: Levels 9-10 (9-10★) - Portals and mode changes
- **Phase 5 (ContinControl)**: Levels 11-12, 16, 18, 21 (11-12★, 16-18★, 21★) - Ship/Wave/Robot modes
- **Phase 6 (LongHorizon)**: Levels 13-15, 17 (13-15★, 17★) - Long sequences requiring planning
- **Phase 7 (Generalization)**: Levels 19-20, 22 (19-20★, 22★) - Extreme difficulty and length

## References

- gdsolver: https://github.com/gdsolver/gdsolver - Game-verified ground truth, 240Hz dumps
- geometry-dash-rl: https://github.com/abs768/geometry-dash-rl - Calibrated physics constants
- game-bot: https://github.com/HackMan617/game-bot - Perception grid (24×16×4), trained encoder
- GD Wiki: https://gd.fandom.com/ - Community level data and difficulty ratings
