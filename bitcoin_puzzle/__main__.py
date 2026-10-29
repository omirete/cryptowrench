"""Run with uv run python -m bitcoin_puzzle from the repository root."""

import argparse
from contextlib import ExitStack
from pathlib import Path
import sys

from .catalog import MAX_PUZZLE, MIN_PUZZLE, puzzle_target
from .cuda import CudaError, select_backend
from .scanner import estimates, scan, validate_scan


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
        command.add_argument("--backend", choices=("auto", "cpu", "cuda"), default="auto")
        command.add_argument("--device", type=int, default=0, help="CUDA device index (default: 0)")
        command.add_argument("--order", choices=("sequential", "random"), default="sequential")
        command.add_argument("--chunk-size", type=int, help="Keys per random chunk (default: 2**34 for a new search)")
        command.add_argument("--seed", type=seed_value, help="Hexadecimal 256-bit random-search seed")
        if name == "scan":
            # The limit counts candidate keys, not seconds or the puzzle's bit size.
            command.add_argument("--limit", type=int,
                                 help="Maximum candidate keys this run; omit to search the remaining interval")
            command.add_argument("--checkpoint", type=Path, help="Random-search checkpoint path")
        else:
            command.add_argument("--seconds", type=float, default=10.0)
            command.add_argument("--tune", action="store_true", help="Validate and measure eight CUDA configurations")
    return root


def seed_value(value):
    seed = hexadecimal(value)
    if not 0 <= seed < 2**256:
        raise argparse.ArgumentTypeError("Seed must be a nonnegative hexadecimal integer below 2**256")
    return seed


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


def random_progress(checked, elapsed, state):
    rate = checked / elapsed if elapsed > 0 else 0
    print(f"Checked {checked:,} | effective {rate:,.0f} keys/s | "
          f"chunk ordinal {state.ordinal}/{state.chunks}, offset {state.offset:,}", flush=True)


def main(argv=None):
    cli = parser()
    args = cli.parse_args(argv)
    worker = None
    resources = ExitStack()
    checkpoint = None
    state = None
    try:
        if args.order == "sequential" and (args.chunk_size is not None or args.seed is not None or getattr(args, "checkpoint", None) is not None):
            raise ValueError("--seed, --chunk-size and --checkpoint require --order random")
        if args.order == "random":
            from .checkpoint import Checkpoint, SEARCHES
            from .traversal import new_state
            if args.command == "scan":
                path = args.checkpoint if args.checkpoint is not None else SEARCHES / f"puzzle-{args.puzzle}-random.json"
                checkpoint = resources.enter_context(Checkpoint(path))
                state = checkpoint.load_or_create(args.puzzle, start=args.start, end=args.end,
                                                  seed=args.seed, chunk_size=args.chunk_size)
            else:
                # Benchmarks are intentionally independent of saved searches.
                state = new_state(args.puzzle, start=args.start, end=args.end,
                                  seed=args.seed, chunk_size=args.chunk_size)
            target = state.target
        else:
            target = puzzle_target(args.puzzle, start=args.start, end=args.end)
        # Both bounds are included, so a one-key interval has size 1, not 0.
        size = target.end - target.start + 1
        # Both backends still receive an exact finite cap. The interval itself
        # bounds an unlimited run; random traversal also stops at saved exhaustion.
        limit = args.limit if args.command == "scan" and args.limit is not None else size
        seconds = args.seconds if args.command == "benchmark" else None
        validate_scan(target, limit, seconds)
        if args.device < 0:
            raise ValueError("CUDA device must be nonnegative")
        print(f"Puzzle: {args.puzzle}; address: {target.address}")
        print(f"Selected interval (inclusive): 0x{target.start:x} through 0x{target.end:x}", flush=True)
        if state is not None:
            print(f"Random seed: {state.seed:064x}; chunk size: {state.chunk_size:,}; cumulative confirmed: {state.checked:,}", flush=True)
            print(f"Checkpoint: {checkpoint.path}" if checkpoint else "Benchmark uses temporary traversal state", flush=True)
        # A terminal checkpoint needs no backend initialization or further search.
        if state is None or state.status == "active":
            worker, message = select_backend(args.backend, args.device)
        else:
            message = "saved search already " + state.status
        print(f"Backend: {message}", flush=True)
        # Benchmark the same loop, allowing the full selected interval but adding
        # a time limit. A short interval or a match can finish before that limit.
        if worker is not None:
            from .tuning import configuration, tune
            config = tune(worker, target) if getattr(args, "tune", False) else configuration(worker)
            print(f"CUDA configuration: {config}", flush=True)
            backend = lambda current, cap, **kwargs: worker.scan(current, cap, configuration=config,
                                                                include_initialization=state is not None, **kwargs)
        else:
            if getattr(args, "tune", False):
                raise ValueError("--tune requires an available CUDA backend")
            backend = scan
        if state is not None:
            from .random_search import search
            startup = worker.startup if worker is not None and worker.first_scan else 0.0
            result = search(state, limit, backend, seconds=seconds, checkpoint=checkpoint,
                            progress=random_progress, startup=startup)
        else:
            result = backend(target, limit, seconds=seconds, progress=progress)
    except ValueError as exc:
        cli.error(str(exc))
    except CudaError as exc:
        print(f"CUDA error: {exc}", file=sys.stderr)
        if checkpoint:
            print(f"Resume random search with --order random --checkpoint \"{checkpoint.path}\"", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"Search error: {exc}", file=sys.stderr)
        if checkpoint:
            print(f"Checkpoint: {checkpoint.path}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted before benchmark completion; no tuning settings saved.")
        return 130
    finally:
        if worker is not None:
            worker.close()
        resources.close()

    print(f"Status: {result.status}")
    print(f"Checked: {result.checked:,}; elapsed: {result.elapsed:.3f}s; rate: {result.rate:,.0f} keys/s")
    total = result.elapsed if result.total_elapsed is None else result.total_elapsed
    print(f"Initialization: {result.initialization:.3f}s; end-to-end: {total:.3f}s; rate: {result.end_to_end_rate:,.0f} keys/s")
    if state is not None:
        print(f"Cumulative confirmed: {state.checked:,}/{state.size:,}; search state: {state.status}")
        if checkpoint:
            limit_option = f" --limit {args.limit}" if args.limit is not None else ""
            print(f'Resume: uv run python -m bitcoin_puzzle scan --puzzle {args.puzzle} --order random --checkpoint "{checkpoint.path}"{limit_option}')
    else:
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
