"""Run with uv run python -m bitcoin_puzzle from the repository root."""

import argparse

from .catalog import MAX_PUZZLE, MIN_PUZZLE, puzzle_target
from .scanner import estimates, scan


def hexadecimal(value):
    """Read key bounds as hexadecimal, with or without a 0x prefix."""
    try:
        return int(value, 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Expected a hexadecimal integer") from exc


def parser():
    root = argparse.ArgumentParser(description="Offline, bounded Bitcoin puzzle playground")
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("scan", "benchmark"):
        command = commands.add_parser(name)
        command.add_argument("--puzzle", type=puzzle_number, required=True,
                             help="Puzzle number, 1-160")
        command.add_argument("--start", type=hexadecimal, help="Inclusive hexadecimal scalar")
        command.add_argument("--end", type=hexadecimal, help="Inclusive hexadecimal scalar")
        if name == "scan":
            # The limit counts candidate keys, not seconds or the puzzle's bit size.
            command.add_argument("--limit", type=int, required=True)
        else:
            command.add_argument("--seconds", type=float, default=10.0)
    return root


def puzzle_number(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Puzzle number must be an integer from 1 to 160") from exc
    if not MIN_PUZZLE <= number <= MAX_PUZZLE:
        raise argparse.ArgumentTypeError("Puzzle number must be from 1 to 160")
    return number


def progress(checked, elapsed, next_scalar):
    next_text = f"0x{next_scalar:x}" if next_scalar is not None else "none"
    print(f"Checked {checked:,} | {checked / elapsed:,.0f} keys/s | next {next_text}", flush=True)


def main(argv=None):
    cli = parser()
    args = cli.parse_args(argv)
    try:
        target = puzzle_target(args.puzzle, start=args.start, end=args.end)
        # Both bounds are included, so a one-key interval has size 1, not 0.
        size = target.end - target.start + 1
        print(f"Puzzle: {args.puzzle}; address: {target.address}")
        print(f"Selected interval (inclusive): 0x{target.start:x} through 0x{target.end:x}", flush=True)
        # Benchmark the same loop, allowing the full selected interval but adding
        # a time limit. A short interval or a match can finish before that limit.
        result = scan(target, args.limit if args.command == "scan" else size,
                      seconds=args.seconds if args.command == "benchmark" else None,
                      progress=progress)
    except ValueError as exc:
        cli.error(str(exc))

    print(f"Status: {result.status}")
    print(f"Checked: {result.checked:,}; elapsed: {result.elapsed:.3f}s; rate: {result.rate:,.0f} keys/s")
    print(f"Next untested scalar: {hex(result.next_scalar) if result.next_scalar is not None else 'none (range exhausted)'}")
    if result.match is not None:
        print(f"Verified private key: {result.match:064x}")
        print(f"Address: {target.address}")
    if args.command == "benchmark":
        values = estimates(result, size)
        year = 365.25 * 86400
        print(f"Interval: {size:,} candidates")
        print(f"Full-range estimate: {values['full_seconds'] / year:,.2f} years")
        print(f"Uniform-key halfway estimate: {values['half_seconds'] / year:,.2f} years")
        print(f"One-day coverage: {values['day_fraction']:.6e} ({values['day_fraction'] * 100:.6e}%)")
        print("Estimates assume sustained measured throughput and a uniformly placed key.")
    # Conventional shell exit status for a command interrupted with Ctrl+C.
    return 130 if result.status == "interrupted" else 0


if __name__ == "__main__":
    raise SystemExit(main())
