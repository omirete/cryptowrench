"""Bounded, correctness-gated CUDA launch tuning and device-local settings."""

import hashlib
import itertools
import json

from cryptowrench.wallet.helpers.adresses.bitcoin import address_P2PKH
from cryptowrench.wallet.helpers.keys import get_public_key

from .cuda import CudaError, EXECUTABLE, LOCAL, default_configuration
from .scanner import Target


def identity(worker):
    return {"uuid": worker.device["uuid"], "driver": worker.device["driver"],
            "executable_sha256": hashlib.sha256(EXECUTABLE.read_bytes()).hexdigest()}


def settings_path(worker):
    uuid = worker.device.get("uuid", "")
    if not uuid or any(character not in "0123456789abcdef" for character in uuid):
        raise CudaError("Invalid device UUID for tuning settings")
    return LOCAL / "tuning" / f"{uuid}.json"


def configuration(worker):
    try:
        data = json.loads(settings_path(worker).read_text())
        if data["identity"] == identity(worker):
            config = data["configuration"]
            if config in candidates(worker):
                return config
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return default_configuration(worker.device)


def candidates(worker):
    return [{"blocks": factor * worker.device["sm"], "threads": threads, "points": points}
            for factor, threads, points in itertools.product((2, 4), (128, 256), (128, 256))]


def validate_configuration(worker, config):
    # Exercise doubling near G, a match at the masked final boundary, and a target
    # immediately beyond that boundary. The last case catches accidental overscan.
    for scalar, start, end, expected in ((1, 1, 1, True),
                                        (2**80 + 17, 2**80 + 12, 2**80 + 17, True),
                                        (2**80 + 18, 2**80 + 12, 2**80 + 17, False)):
        key = scalar.to_bytes(32, "big")
        target = Target(address_P2PKH(get_public_key(key)), start, end)
        result = worker.scan(target, end - start + 1, configuration=config)
        if result.status == "interrupted":
            raise KeyboardInterrupt
        if result.checked != end - start + 1 or result.match != (scalar if expected else None):
            raise CudaError(f"CUDA self-test failed for {config}")


def tune(worker, target, report=None):
    report = report or (lambda message: print(message, flush=True))
    trials = []
    for index, config in enumerate(candidates(worker), 1):
        report(f"Tuning {index}/8: {config}")
        validate_configuration(worker, config)
        result = worker.scan(target, target.end - target.start + 1,
                             seconds=2.0, configuration=config)
        if result.status == "interrupted":
            raise KeyboardInterrupt
        if result.status in ("match", "exhausted"):
            raise CudaError("Tuning interval ended early; select a larger interval without a known solution")
        report(f"  Validated; {result.rate:,.0f} keys/s")
        trials.append({"configuration": config, "keys_per_second": result.rate})
    best = max(trials, key=lambda trial: trial["keys_per_second"])
    data = {"identity": identity(worker), "configuration": best["configuration"], "trials": trials}
    path = settings_path(worker)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n")
    temporary.replace(path)
    report(f"Selected {best['configuration']}; saved {path}")
    return best["configuration"]
