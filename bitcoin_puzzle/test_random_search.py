"""Coverage, persistence, and backend-independent resume guarantees."""

import json
import subprocess
import sys

import pytest

from bitcoin_puzzle import checkpoint as checkpoint_module
from bitcoin_puzzle.__main__ import main
from bitcoin_puzzle.checkpoint import Checkpoint, CheckpointError, decode, encode
from bitcoin_puzzle.cuda import CudaError
from bitcoin_puzzle.random_search import search
from bitcoin_puzzle.scanner import ScanResult, scan
from bitcoin_puzzle.traversal import ChunkPermutation, new_state


@pytest.mark.parametrize("count", [1, 2, 3, 4, 5, 7, 9, 15, 16, 17, 31, 32, 33, 65, 97, 1000])
@pytest.mark.parametrize("seed", [0, 1, 2**255])
def test_permutation_complete_and_invertible(count, seed):
    permutation = ChunkPermutation(count, seed)
    values = [permutation(index) for index in range(count)]
    assert sorted(values) == list(range(count))
    assert all(permutation.inverse(value) == index for index, value in enumerate(values))


def test_seed_changes_order_reproducibly():
    first = [ChunkPermutation(30, 1)(index) for index in range(30)]
    assert first == [ChunkPermutation(30, 1)(index) for index in range(30)]
    assert first != [ChunkPermutation(30, 2)(index) for index in range(30)]


def test_version_one_permutation_compatibility_vectors():
    # Changing these mappings requires an algorithm-version bump in checkpoints.
    assert [ChunkPermutation(7, 0)(i) for i in range(7)] == [3, 5, 4, 1, 2, 0, 6]
    assert [ChunkPermutation(10, 123)(i) for i in range(10)] == [6, 2, 0, 7, 3, 8, 5, 1, 9, 4]


@pytest.mark.parametrize("number", [71, 160])
def test_large_ranges_need_no_visited_list(number):
    state = new_state(number, seed=123)
    for ordinal in (0, 1, state.chunks // 2, state.chunks - 1):
        chunk = state.permutation(ordinal)
        assert 0 <= chunk < state.chunks
        assert state.permutation.inverse(chunk) == ordinal


def state_without_solution(**kwargs):
    # Puzzle 8's public key is scalar 224, outside this deliberately shortened range.
    return new_state(8, start=128, end=200, seed=42, chunk_size=7, **kwargs)


def recording_backend(seen, *, callbacks=True, stop=None):
    def backend(target, limit, *, seconds=None, progress=None):
        count = min(limit, target.end - target.start + 1)
        if stop is not None:
            count = min(count, stop)
        seen.extend(range(target.start, target.start + count))
        next_key = target.start + count
        next_key = next_key if next_key <= target.end else None
        if callbacks and progress:
            progress(count, 0.1, next_key)
        status = "interrupted" if stop is not None else "exhausted" if next_key is None else "limit"
        return ScanResult(status, count, 0.1, next_key, None)
    return backend


@pytest.mark.parametrize("seed", range(8))
def test_full_coverage_including_partial_last_chunk(seed):
    state = new_state(8, start=128, end=200, seed=seed, chunk_size=7)
    seen = []
    result = search(state, 1000, recording_backend(seen))
    assert result.status == state.status == "exhausted"
    assert sorted(seen) == list(range(128, 201))
    assert len(seen) == len(set(seen)) == state.checked == 73
    state.validate()


def test_cursor_count_validation_after_each_chunk():
    state = state_without_solution()
    while state.chunk() is not None:
        chunk = state.chunk()
        for _ in range(chunk.end - chunk.start + 1):
            state.advance(1)
            state.validate()
    assert state.checked == 73


def test_limited_resume_switches_backend_and_preserves_uniqueness(tmp_path):
    path = tmp_path / "search.json"
    seen = []
    with Checkpoint(path) as checkpoint:
        state = checkpoint.load_or_create(8, start=128, end=200, seed=42, chunk_size=7)
        first = search(state, 10, recording_backend(seen), checkpoint=checkpoint)
        assert first.checked == state.checked == 10
    with Checkpoint(path) as checkpoint:
        state = checkpoint.load_or_create(8)
        assert (state.start, state.end, state.seed, state.chunk_size) == (128, 200, 42, 7)
        second = search(state, 1000, recording_backend(seen, callbacks=False), checkpoint=checkpoint)
        assert second.checked == 63
    assert sorted(seen) == list(range(128, 201))
    assert len(seen) == len(set(seen))


def test_interruption_resumes_inside_chunk(tmp_path):
    seen = []
    path = tmp_path / "search.json"
    with Checkpoint(path) as checkpoint:
        state = checkpoint.load_or_create(8, start=128, end=200, seed=42, chunk_size=7)
        result = search(state, 100, recording_backend(seen, stop=3), checkpoint=checkpoint)
        assert result.status == "interrupted"
        assert (state.ordinal, state.offset, state.checked) == (0, 3, 3)
    with Checkpoint(path) as checkpoint:
        state = checkpoint.load_or_create(8)
        search(state, 100, recording_backend(seen), checkpoint=checkpoint)
    assert len(seen) == len(set(seen)) == 73


def test_backend_failure_preserves_only_acknowledged_prefix(tmp_path):
    with Checkpoint(tmp_path / "failure.json") as checkpoint:
        state = checkpoint.load_or_create(8, start=128, end=200, seed=42, chunk_size=7)

        def fail(target, limit, *, seconds, progress):
            progress(2, 1, target.start + 2)
            raise CudaError("native crash")

        with pytest.raises(CudaError):
            search(state, 10, fail, checkpoint=checkpoint)
        assert checkpoint.load_or_create(8).checked == 2


def test_match_and_coverage_are_saved_together():
    snapshots = []

    class MemoryCheckpoint:
        def save(self, state):
            snapshots.append(encode(state))

    state = new_state(2, seed=0, chunk_size=2)
    result = search(state, 10, scan, checkpoint=MemoryCheckpoint())
    assert result.match == 3 and state.status == "match"
    assert all(snapshot["status"] == "match" and snapshot["match"] == "3" for snapshot in snapshots)
    assert decode(snapshots[-1]).match == 3


def test_terminal_state_does_not_search_again():
    state = state_without_solution()
    search(state, 1000, recording_backend([]))

    def forbidden(*args, **kwargs):
        pytest.fail("Completed random search must not call a backend")

    result = search(state, 1000, forbidden)
    assert result.status == "exhausted" and result.checked == 0


def test_overall_budget_includes_chunk_transitions():
    state = state_without_solution()
    current = [0.0]
    budgets = []

    def backend(target, limit, *, seconds, progress):
        budgets.append(seconds)
        current[0] += 0.6  # Includes simulated initialization of each chunk.
        return ScanResult("exhausted", limit, 0.4, None, None, initialization=0.2)

    result = search(state, 100, backend, seconds=1, clock=lambda: current[0])
    assert budgets == pytest.approx([1, 0.4])
    assert result.status == "duration"
    assert result.elapsed == pytest.approx(1.2)
    assert result.rate == pytest.approx(result.checked / 1.2)


@pytest.mark.parametrize("content", ["{", "[]", "null", "{}"])
def test_corrupt_checkpoint_is_not_reset(tmp_path, content):
    path = tmp_path / "bad.json"
    path.write_text(content)
    with Checkpoint(path) as checkpoint:
        with pytest.raises(ValueError, match="Invalid checkpoint"):
            checkpoint.load_or_create(8)
    assert path.read_text() == content


@pytest.mark.parametrize("field,value", [
    ("algorithm", "unknown"), ("format_version", 2), ("format_version", True),
    ("seed", "xyz"), ("checked", "1"), ("offset", "999"), ("ordinal", "9999"),
    ("puzzle", True), ("address", "bad"), ("status", "match"), ("chunk_size", "0"),
    ("status", "exhausted"),
])
def test_inconsistent_checkpoint_rejected(field, value):
    data = encode(state_without_solution())
    data[field] = value
    with pytest.raises((ValueError, TypeError)):
        decode(data)


@pytest.mark.parametrize("argument", ["start", "end", "seed", "chunk_size", "puzzle"])
def test_conflicting_resume_arguments_rejected(tmp_path, argument):
    with Checkpoint(tmp_path / "resume.json") as checkpoint:
        state = checkpoint.load_or_create(8, start=128, end=200, seed=42, chunk_size=7)
        options = {argument: getattr(state, argument) + 1}
        number = options.pop("puzzle", 8)
        with pytest.raises(ValueError, match="conflicts"):
            checkpoint.load_or_create(number, **options)


def test_checkpoint_lock_is_exclusive_and_released(tmp_path):
    path = tmp_path / "locked.json"
    with Checkpoint(path):
        with pytest.raises(CheckpointError, match="lock"):
            with Checkpoint(path):
                pytest.fail("Concurrent checkpoint access was allowed")
    with Checkpoint(path):
        pass


def test_crashed_process_releases_os_lock(tmp_path):
    path = tmp_path / "child.json"
    script = "from bitcoin_puzzle.checkpoint import Checkpoint; import sys; c=Checkpoint(sys.argv[1]); c.__enter__(); print('locked',flush=True); sys.stdin.readline()"
    child = subprocess.Popen([sys.executable, "-c", script, str(path)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "locked"
        with pytest.raises(CheckpointError):
            with Checkpoint(path):
                pytest.fail("The child still owns this checkpoint")
    finally:
        child.kill()
        child.wait()
        child.stdin.close()
        child.stdout.close()
    with Checkpoint(path):
        pass


def test_duplicate_checkpoint_fields_are_rejected(tmp_path):
    path = tmp_path / "duplicate.json"
    data = json.dumps(encode(state_without_solution()))
    data = data.replace('"checked": "0"', '"checked": "0", "checked": "0"')
    path.write_text(data)
    with Checkpoint(path) as checkpoint:
        with pytest.raises(ValueError, match="Duplicate checkpoint field"):
            checkpoint.load_or_create(8)


def test_failed_atomic_replace_keeps_previous_checkpoint(tmp_path, monkeypatch):
    path = tmp_path / "atomic.json"
    with Checkpoint(path) as checkpoint:
        state = checkpoint.load_or_create(8, start=128, end=200, seed=42, chunk_size=7)
        original = path.read_bytes()
        state.advance(1)

        def fail(*args):
            raise OSError("simulated replace failure")

        monkeypatch.setattr(checkpoint_module.os, "replace", fail)
        with pytest.raises(CheckpointError):
            checkpoint.save(state)
        assert path.read_bytes() == original
        assert not list(tmp_path.glob("*.tmp"))


def test_cli_resume_and_checkpoint_output(tmp_path, capsys):
    path = tmp_path / "cli.json"
    base = ["scan", "--puzzle", "8", "--order", "random", "--backend", "cpu", "--checkpoint", str(path)]
    assert main([*base, "--start", "80", "--end", "c8", "--seed", "2a", "--chunk-size", "7", "--limit", "10"]) == 0
    assert main([*base, "--limit", "100"]) == 0
    output = capsys.readouterr().out
    assert "Resume:" in output and "--checkpoint" in output
    assert "Next untested scalar" not in output
    assert "search state: exhausted" in output
    assert decode(json.loads(path.read_text())).checked == 73


def test_random_benchmark_never_touches_saved_search(tmp_path, monkeypatch):
    monkeypatch.setattr(checkpoint_module, "SEARCHES", tmp_path)
    path = tmp_path / "puzzle-8-random.json"
    path.write_text("untouched")
    assert main(["benchmark", "--puzzle", "8", "--start", "80", "--end", "c8",
                 "--order", "random", "--seed", "1", "--chunk-size", "7", "--seconds", "0.001", "--backend", "cpu"]) == 0
    assert path.read_text() == "untouched"
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("extra", [
    ["--seed", "1"], ["--chunk-size", "2"], ["--checkpoint", "ignored.json"],
    ["--order", "random", "--chunk-size", "0"],
    ["--order", "random", "--seed", "-1"],
    ["--order", "random", "--seed", "1" + "0" * 64],
])
def test_invalid_cli_options(tmp_path, extra):
    arguments = ["scan", "--puzzle", "8", "--limit", "1", "--backend", "cpu", *extra]
    if "random" in extra:
        arguments += ["--checkpoint", str(tmp_path / "invalid.json")]
    with pytest.raises(SystemExit) as error:
        main(arguments)
    assert error.value.code == 2
