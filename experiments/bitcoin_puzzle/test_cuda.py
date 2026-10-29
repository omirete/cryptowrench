"""Protocol tests need no GPU; enable hardware cases with BITCOIN_PUZZLE_CUDA_TESTS=1."""

import json
import os
import sys

import pytest

from experiments.bitcoin_puzzle import cuda
from experiments.bitcoin_puzzle.catalog import puzzle_target
from experiments.bitcoin_puzzle.cuda import CudaError, CudaWorker
from experiments.bitcoin_puzzle.scanner import Target, scan
from experiments.bitcoin_puzzle.tuning import validate_configuration
from cryptowrench.wallet.helpers.adresses.bitcoin import address_P2PKH
from cryptowrench.wallet.helpers.keys import get_public_key


DEVICE = {"type": "device", "name": "Fake GPU", "uuid": "a" * 32,
          "sm": 1, "driver": 12080, "major": 8, "minor": 9, "protocol": 2}
READY = {"type": "ready", "initialization": 0.2}


def event(kind="done", checked="3", next_key="5", **fields):
    return {"type": kind, "checked": checked, "next": next_key, "elapsed": 1.0,
            **fields}


@pytest.fixture
def fake_worker(tmp_path):
    script = tmp_path / "fake.py"
    script.write_text('''
import sys, json
data = json.load(open(sys.argv[1]))
print(json.dumps(data['device']), flush=True)
for line in sys.stdin:
    for item in data['events']:
        if item == 'crash':
            print('native failure', file=sys.stderr, flush=True)
            sys.exit(7)
        print(item if isinstance(item, str) else json.dumps(item), flush=True)
''')

    def create(events):
        config = tmp_path / "events.json"
        config.write_text(json.dumps({"device": DEVICE, "events": events}))
        return CudaWorker(command=[sys.executable, str(script), str(config)])
    return create


def test_valid_protocol_and_persistent_process(fake_worker):
    target = Target(puzzle_target(1).address, 2, 10)
    with fake_worker([READY, event("progress"), event(status="limit")]) as worker:
        for _ in range(2):
            result = worker.scan(target, 3)
            assert (result.checked, result.next_scalar, result.match) == (3, 5, None)
            assert result.initialization >= 0.2
            assert result.elapsed == 1
    assert worker.process.poll() is not None


@pytest.mark.parametrize("events", [
    ["not JSON"], ["crash"], [{"type": "error", "message": "CUDA failure"}],
    [READY, event(checked="4", status="limit")],
    [READY, event(next_key="6", status="limit")],
    [READY, event(checked=3, status="limit")],
    [READY, event(status="exhausted")],
    [READY, event(status="duration")],
    [READY, event(status="other")],
    [READY, event(status="match", match="6")],
    [READY, event(status="match", match="3")],
    [READY, event(status="limit", elapsed=float("nan"))],
    [READY, READY], [event(status="limit")],
])
def test_invalid_native_results_fail_without_exhaustion(fake_worker, events):
    target = Target(puzzle_target(1).address, 2, 10)
    with fake_worker(events) as worker:
        with pytest.raises(CudaError):
            worker.scan(target, 3)
    assert worker.process.poll() is not None


def test_error_reports_last_confirmed_resume_point(fake_worker):
    with fake_worker([READY, event("progress"), "bad"]) as worker:
        with pytest.raises(CudaError, match="confirmed 3 keys; resume at 0x5"):
            worker.scan(Target(puzzle_target(1).address, 2, 10), 5)


def test_interrupt_replays_unacknowledged_work(fake_worker, monkeypatch):
    with fake_worker([]) as worker:
        events = iter([READY, event("progress")])

        def interrupted_event(*args, **kwargs):
            try:
                return next(events)
            except StopIteration:
                raise KeyboardInterrupt

        monkeypatch.setattr(worker, "event", interrupted_event)
        result = worker.scan(Target(puzzle_target(1).address, 2, 10), 5)
        assert (result.status, result.checked, result.next_scalar) == ("interrupted", 3, 5)
        assert worker.process.poll() is not None


def test_backend_unavailable_is_explicit(monkeypatch, tmp_path):
    monkeypatch.setattr(cuda, "EXECUTABLE", tmp_path / "missing.exe")
    worker, reason = cuda.select_backend("auto")
    assert worker is None and "fallback" in reason
    with pytest.raises(CudaError, match="unavailable"):
        cuda.select_backend("cuda")
    assert cuda.select_backend("cpu")[0] is None


HARDWARE = os.environ.get("BITCOIN_PUZZLE_CUDA_TESTS") == "1"


@pytest.fixture(scope="module")
def gpu():
    if not HARDWARE:
        pytest.skip("Set BITCOIN_PUZZLE_CUDA_TESTS=1 to run native CUDA validation")
    with CudaWorker() as worker:
        yield worker


SMALL = {"blocks": 1, "threads": 32, "points": 1}


@pytest.mark.integration
@pytest.mark.parametrize("number", [1, 2, 3, 4, 8])
def test_gpu_solved_puzzles(gpu, number):
    target = puzzle_target(number)
    reference = scan(target, target.end - target.start + 1)
    actual = gpu.scan(target, target.end - target.start + 1, configuration=SMALL)
    assert actual.match == reference.match
    assert target.start + actual.checked == (actual.next_scalar or target.end + 1)


@pytest.mark.integration
@pytest.mark.parametrize("bits", [1, 71, 160])
@pytest.mark.parametrize("offset", [0, 31, 32, 70])
def test_gpu_batch_boundaries_and_large_scalars(gpu, bits, offset):
    start = 2**(bits - 1)
    scalar = start + offset
    target = Target(address_P2PKH(get_public_key(scalar.to_bytes(32, "big"))), start, scalar)
    result = gpu.scan(target, offset + 1, configuration=SMALL)
    assert result.match == scalar
    assert result.checked == offset + 1
    assert result.next_scalar is None


@pytest.mark.integration
@pytest.mark.parametrize("limit", [1, 31, 32, 33, 65])
def test_gpu_exact_limit_and_masked_match(gpu, limit):
    start = 2**70
    scalar = start + limit  # Would match if the final batch accidentally overscans.
    target = Target(address_P2PKH(get_public_key(scalar.to_bytes(32, "big"))), start, start + 100)
    first = gpu.scan(target, limit, configuration=SMALL)
    assert first.status == "limit"
    assert first.checked == limit and first.match is None
    assert first.next_scalar == scalar
    resumed = gpu.scan(Target(target.address, first.next_scalar, target.end), 1, configuration=SMALL)
    assert resumed.match == scalar and resumed.checked == 1


@pytest.mark.integration
def test_gpu_configuration_self_test(gpu):
    validate_configuration(gpu, SMALL)


@pytest.mark.integration
def test_real_gpu_interrupt_and_resume(gpu):
    target = puzzle_target(71)

    def interrupt(*args):
        raise KeyboardInterrupt

    with CudaWorker() as worker:
        first = worker.scan(target, target.end - target.start + 1,
                            progress=interrupt, configuration=SMALL)
        assert first.status == "interrupted"
        assert first.checked > 0
        assert first.next_scalar == target.start + first.checked
        assert worker.process.poll() is not None
    resumed = Target(target.address, first.next_scalar, first.next_scalar + 31)
    actual = gpu.scan(resumed, 32, configuration=SMALL)
    reference = scan(resumed, 32)
    assert actual.status == reference.status == "exhausted"
    assert actual.checked == reference.checked == 32
    assert actual.match == reference.match


@pytest.mark.integration
def test_gpu_wall_budget_includes_initialization(gpu):
    result = gpu.scan(puzzle_target(71), 1000, seconds=1e-9,
                      include_initialization=True, configuration=SMALL)
    assert result.status == "duration"
    assert result.checked == 0
    assert result.initialization > 0


@pytest.mark.integration
def test_random_resume_from_cuda_to_cpu(gpu, tmp_path):
    from experiments.bitcoin_puzzle.checkpoint import Checkpoint
    from experiments.bitcoin_puzzle.random_search import search

    path = tmp_path / "gpu-random.json"
    seen = []

    def native(target, cap, **kwargs):
        result = gpu.scan(target, cap, configuration=SMALL, include_initialization=True, **kwargs)
        seen.extend(range(target.start, target.start + result.checked))
        return result

    def reference(target, cap, **kwargs):
        result = scan(target, cap, **kwargs)
        seen.extend(range(target.start, target.start + result.checked))
        return result

    with Checkpoint(path) as checkpoint:
        state = checkpoint.load_or_create(8, start=128, end=200, seed=123, chunk_size=7)
        first = search(state, 10, native, checkpoint=checkpoint)
        assert first.checked == 10
    with Checkpoint(path) as checkpoint:
        state = checkpoint.load_or_create(8)
        second = search(state, 100, reference, checkpoint=checkpoint)
        assert second.status == "exhausted" and second.checked == 63
    assert sorted(seen) == list(range(128, 201))
    assert len(seen) == len(set(seen))
