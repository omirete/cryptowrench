"""Offline lookup of public puzzle addresses and mathematically derived ranges."""

import json
from pathlib import Path

from .scanner import Target, decode_target


# Keep runtime lookup offline; source attribution and snapshot details are in README.md.
CATALOG_PATH = Path(__file__).with_name("addresses.json")
MIN_PUZZLE = 1
MAX_PUZZLE = 160


def load_catalog(path: Path | None = None) -> dict[int, str]:
    """Require the complete catalog, including valid mainnet address checksums."""
    path = CATALOG_PATH if path is None else path
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError(f"Cannot read puzzle catalog {path}: {exc}") from exc
    # JSON object keys are strings. Reject partial catalogs before selecting a target.
    expected = {str(number) for number in range(MIN_PUZZLE, MAX_PUZZLE + 1)}
    if not isinstance(data, dict) or set(data) != expected:
        raise ValueError(f"Invalid puzzle catalog {path}: require exactly puzzles 1-160")
    for number, address in data.items():
        try:
            if not isinstance(address, str):
                raise ValueError("Address must be text")
            decode_target(address)
        except ValueError as exc:
            raise ValueError(f"Invalid puzzle catalog {path}: puzzle {number}: {exc}") from exc
    return {int(number): address for number, address in data.items()}


def puzzle_target(number: int, *, start: int | None = None,
                  end: int | None = None) -> Target:
    """Resolve a puzzle's address and optionally narrow its inclusive key interval."""
    if type(number) is not int or not MIN_PUZZLE <= number <= MAX_PUZZLE:
        raise ValueError("Puzzle number must be an integer from 1 to 160")
    # Puzzle N uses an N-bit scalar with its top bit set: [2**(N-1), 2**N - 1].
    # Integer shifts preserve exact bounds even for ranges larger than 64 bits.
    lower = 1 << (number - 1)
    upper = (1 << number) - 1
    start = lower if start is None else start
    end = upper if end is None else end
    if not lower <= start <= end <= upper:
        raise ValueError(f"Require 0x{lower:x} <= start <= end <= 0x{upper:x} for puzzle {number}")
    return Target(load_catalog()[number], start, end)
