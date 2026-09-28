"""Load and parse gdsolver dump CSV files into Transition objects."""

import csv
from pathlib import Path
from typing import Optional, List, Dict, Any
from data.transition import Transition, TransitionBatch
from data.types import GameMode, ContactType


class GDSolverLoader:
    """Load gdsolver dump.csv files into canonical Transition format."""

    # Mapping from gdsolver CSV columns to Transition fields
    CSV_COLUMNS = {
        "tick": "tick",
        "x": "x",
        "y": "y",
        "vx": "vx",
        "vy": "vy",
        "rotation": "rotation",
        "mode": "mode",
        "gravity_mod": "gravity_mod",
        "size_mod": "size_mod",
        "speed_scaling": "speed_scaling",
        "grounded": "grounded",
        "contact_type": "contact_type",
        "death": "death_state",
    }

    # Mode string → GameMode enum
    MODE_MAP = {
        "cube": GameMode.CUBE,
        "ship": GameMode.SHIP,
        "ball": GameMode.BALL,
        "ufo": GameMode.UFO,
        "wave": GameMode.WAVE,
        "robot": GameMode.ROBOT,
        "spider": GameMode.SPIDER,
    }

    # Contact string → ContactType enum
    CONTACT_MAP = {
        "platform": ContactType.PLATFORM,
        "spike": ContactType.SPIKE,
        "orb": ContactType.ORB,
        "pad": ContactType.PAD,
        "air": ContactType.AIR,
    }

    def load_dump(self, dump_path: str, level_id: Optional[str] = None) -> TransitionBatch:
        """
        Load a gdsolver dump CSV file and return TransitionBatch.

        Args:
            dump_path: Path to dump.csv file
            level_id: Optional level identifier

        Returns:
            TransitionBatch with all transitions from the dump
        """
        path = Path(dump_path)
        if not path.exists():
            raise FileNotFoundError(f"Dump file not found: {dump_path}")

        transitions = []
        with open(path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                t = self._parse_row(row, level_id)
                if t is not None:
                    transitions.append(t)

        return TransitionBatch(transitions)

    def _parse_row(self, row: Dict[str, str], level_id: Optional[str] = None) -> Optional[Transition]:
        """Parse a single CSV row into a Transition object."""
        try:
            # Convert numeric fields
            tick = int(float(row.get("tick", 0)))
            x = float(row.get("x", 0))
            y = float(row.get("y", 0))
            vx = float(row.get("vx", 0))
            vy = float(row.get("vy", 0))
            rotation = float(row.get("rotation", 0))
            gravity_mod = float(row.get("gravity_mod", 1.0))
            size_mod = float(row.get("size_mod", 1.0))
            speed_scaling = float(row.get("speed_scaling", 1.0))

            # Boolean fields
            grounded = row.get("grounded", "false").lower() in ("true", "1", "yes")
            death_state = row.get("death", "false").lower() in ("true", "1", "yes")
            input_held = row.get("input_held", "false").lower() in ("true", "1", "yes")
            input_pressed = row.get("input_pressed", "false").lower() in ("true", "1", "yes")

            # Enum fields
            mode_str = row.get("mode", "cube").lower()
            mode = self.MODE_MAP.get(mode_str, GameMode.CUBE)

            contact_str = row.get("contact_type", "air").lower()
            contact_type = self.CONTACT_MAP.get(contact_str, ContactType.AIR)

            # Create Transition
            t = Transition(
                tick=tick,
                x=x,
                y=y,
                vx=vx,
                vy=vy,
                rotation=rotation,
                mode=mode,
                gravity_mod=gravity_mod,
                size_mod=size_mod,
                speed_scaling=speed_scaling,
                grounded=grounded,
                contact_type=contact_type,
                death_state=death_state,
                input_held=input_held,
                input_pressed=input_pressed,
                primary_obstacle=None,  # TODO: Parse from dump if available
                nearby_obstacles=[],    # TODO: Parse from dump if available
                level_id=level_id,
                source="gdsolver",
            )
            return t
        except (ValueError, KeyError) as e:
            # Skip malformed rows
            return None

    @staticmethod
    def create_test_dump(output_path: str, num_ticks: int = 240):
        """Create a test dump CSV for testing purposes."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                "tick", "x", "y", "vx", "vy", "rotation",
                "mode", "gravity_mod", "size_mod", "speed_scaling",
                "grounded", "contact_type", "death", "input_held", "input_pressed"
            ])
            writer.writeheader()

            for tick in range(num_ticks):
                writer.writerow({
                    "tick": tick,
                    "x": 120.0 + tick * 0.1,
                    "y": 160.0,
                    "vx": 10.389,
                    "vy": 0.0,
                    "rotation": 0.0,
                    "mode": "cube",
                    "gravity_mod": 1.0,
                    "size_mod": 1.0,
                    "speed_scaling": 1.0,
                    "grounded": "true" if tick % 5 == 0 else "false",
                    "contact_type": "platform" if tick % 5 == 0 else "air",
                    "death": "false",
                    "input_held": "true" if 100 <= tick < 110 else "false",
                    "input_pressed": "true" if tick == 100 else "false",
                })
