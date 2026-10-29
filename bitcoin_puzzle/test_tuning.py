"""Correctness failures must never produce trusted tuning settings."""

from types import SimpleNamespace

import pytest

from bitcoin_puzzle import tuning
from bitcoin_puzzle.catalog import puzzle_target
from bitcoin_puzzle.cuda import CudaError, default_configuration
from bitcoin_puzzle.scanner import ScanResult


@pytest.fixture
def environment(tmp_path, monkeypatch):
    monkeypatch.setattr(tuning, "LOCAL", tmp_path)
    monkeypatch.setattr(tuning, "identity", lambda worker: {"binary": "test-v1"})
    validations = []
    monkeypatch.setattr(tuning, "validate_configuration", lambda worker, config: validations.append(config))
    calls = []

    def scan(target, limit, *, seconds, configuration):
        calls.append(configuration)
        rate = configuration["blocks"] * configuration["threads"] * configuration["points"]
        return ScanResult("duration", rate * 2, 2, target.start + rate * 2, None)

    worker = SimpleNamespace(device={"uuid": "a" * 32, "sm": 24}, scan=scan)
    return worker, validations, calls


def test_tune_validates_all_trials_and_saves_fastest(environment):
    worker, validations, calls = environment
    selected = tuning.tune(worker, puzzle_target(71), report=lambda message: None)
    assert len(calls) == len(validations) == 8
    assert set(tuple(sorted(config.items())) for config in calls) == set(
        tuple(sorted(config.items())) for config in tuning.candidates(worker))
    assert selected == {"blocks": 96, "threads": 256, "points": 256}
    assert tuning.configuration(worker) == selected


def test_invalidated_binary_uses_defaults(environment, monkeypatch):
    worker, _, _ = environment
    tuning.tune(worker, puzzle_target(71), report=lambda message: None)
    monkeypatch.setattr(tuning, "identity", lambda worker: {"binary": "test-v2"})
    assert tuning.configuration(worker) == default_configuration(worker.device)


def test_failed_validation_saves_nothing(environment, monkeypatch):
    worker, _, calls = environment

    def fail(*args):
        raise CudaError("bad GPU result")

    monkeypatch.setattr(tuning, "validate_configuration", fail)
    with pytest.raises(CudaError):
        tuning.tune(worker, puzzle_target(71), report=lambda message: None)
    assert calls == []
    assert not tuning.settings_path(worker).exists()


def test_interrupted_tuning_saves_nothing(environment):
    worker, _, _ = environment
    worker.scan = lambda *args, **kwargs: ScanResult("interrupted", 1, 1, 2, None)
    with pytest.raises(KeyboardInterrupt):
        tuning.tune(worker, puzzle_target(71), report=lambda message: None)
    assert not tuning.settings_path(worker).exists()


def test_corrupt_settings_use_defaults(environment):
    worker, _, _ = environment
    path = tuning.settings_path(worker)
    path.parent.mkdir(parents=True)
    path.write_text("bad json")
    assert tuning.configuration(worker) == default_configuration(worker.device)
