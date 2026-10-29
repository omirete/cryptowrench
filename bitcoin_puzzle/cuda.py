"""Structured subprocess bridge; GPU progress is committed only at batch boundaries."""

from collections import deque
import json
import math
from pathlib import Path
import queue
import re
import subprocess
import threading
from time import perf_counter

from cryptowrench.wallet import Wallet
from cryptowrench.wallet.helpers.hashfuncs import get_hash160
from cryptowrench.wallet.helpers.keys import get_public_key

from .scanner import ScanResult, validate_scan

LOCAL = Path(__file__).resolve().parent / ".local"
EXECUTABLE = LOCAL / "build" / "puzzle_cuda.exe"


class CudaError(RuntimeError):
    """A native failure or invalid protocol event, never a search miss."""


def integer(event, name):
    value = event.get(name)
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{1,64}", value):
        raise CudaError(f"Invalid hexadecimal {name} in CUDA event")
    return int(value, 16)


def timing(event, name):
    value = event.get(name)
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise CudaError(f"Invalid {name} in CUDA event")
    return float(value)


class CudaWorker:
    """One native process can serve multiple scans and tuning trials."""

    def __init__(self, device=0, command=None):
        if type(device) is not int or device < 0:
            raise ValueError("CUDA device must be a nonnegative integer")
        self.process = None
        self.events = queue.Queue()
        self.diagnostics = deque(maxlen=30)
        self.threads = []
        started = perf_counter()
        try:
            self.process = subprocess.Popen(
                [*(command or [str(EXECUTABLE)]), str(device)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                encoding="utf-8", errors="replace", bufsize=1,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            for stream, stdout in ((self.process.stdout, True), (self.process.stderr, False)):
                thread = threading.Thread(target=self._read, args=(stream, stdout), daemon=True)
                thread.start()
                self.threads.append(thread)
            self.device = self.event(timeout=30)
            if self.device.get("type") != "device" or not isinstance(self.device.get("name"), str):
                raise CudaError("Expected CUDA device information")
            if self.device.get("protocol") != 2:
                raise CudaError("CUDA worker needs rebuilding: run python -m bitcoin_puzzle.setup_cuda")
            if type(self.device.get("sm")) is not int or self.device["sm"] <= 0:
                raise CudaError("Invalid CUDA multiprocessor count")
            major, minor = self.device.get("major"), self.device.get("minor")
            if type(major) is not int or type(minor) is not int or (major, minor) < (8, 9):
                raise CudaError("This native build requires CUDA compute capability 8.9 or newer")
            self.startup = perf_counter() - started
            self.first_scan = True
        except BaseException:
            self.close()
            raise

    def _read(self, stream, stdout):
        try:
            for line in stream:
                if stdout:
                    self.events.put(line)
                else:
                    self.diagnostics.append(line.rstrip())
        finally:
            if stdout:
                self.events.put(None)

    def event(self, timeout=120):
        try:
            line = self.events.get(timeout=timeout)
        except queue.Empty as exc:
            raise CudaError("CUDA worker timed out") from exc
        if line is None:
            raise CudaError("CUDA worker exited unexpectedly: " + " | ".join(self.diagnostics))
        try:
            event = json.loads(line)
        except ValueError as exc:
            raise CudaError("Malformed JSON from CUDA worker") from exc
        if not isinstance(event, dict):
            raise CudaError("Invalid CUDA event")
        if event.get("type") == "error":
            raise CudaError(str(event.get("message", "Native CUDA failure")))
        return event

    def scan(self, target, limit, *, seconds=None, progress=None, configuration=None,
             include_initialization=False):
        target_hash = validate_scan(target, limit, seconds)
        cap = min(limit, target.end - target.start + 1)
        config = configuration or default_configuration(self.device)
        blocks, threads, points = (config[name] for name in ("blocks", "threads", "points"))
        if any(type(value) is not int or value <= 0 for value in (blocks, threads, points)):
            raise ValueError("CUDA launch dimensions must be positive integers")
        if threads % 32 or threads > 1024:
            raise ValueError("CUDA threads must be a multiple of 32, at most 1024")
        if blocks > 4096 or points > 4096 or blocks * threads * points > 2**26:
            raise ValueError("CUDA configuration exceeds the supported memory budget")
        if self.process.poll() is not None or self.process.stdin.closed:
            raise CudaError("CUDA worker is closed")
        command = "scan_wall" if include_initialization else "scan"
        request = (f"{command} {target.start:x} {target.end:x} {cap:x} "
                   f"{seconds or 0:.17g} {blocks} {threads} {points} {target_hash.hex()}\n")
        checked = 0
        elapsed = 0.0
        initialization = 0.0
        native_initialization = 0.0
        started = perf_counter()
        startup = self.startup if self.first_scan else 0.0
        self.first_scan = False
        last_report = 0.0
        ready = False
        try:
            self.process.stdin.write(request)
            self.process.stdin.flush()
            while True:
                event = self.event()
                kind = event.get("type")
                if kind == "ready":
                    if ready:
                        raise CudaError("Duplicate CUDA ready event")
                    native_initialization = timing(event, "initialization")
                    initialization = native_initialization + startup
                    ready = True
                    continue
                if not ready or kind not in ("progress", "done"):
                    raise CudaError("Unexpected CUDA event sequence")
                count = integer(event, "checked")
                next_scalar = integer(event, "next")
                duration = timing(event, "elapsed")
                if not checked <= count <= cap or next_scalar != target.start + count or duration < elapsed:
                    raise CudaError("Inconsistent CUDA coverage or timing")
                checked, elapsed = count, duration
                if kind == "progress":
                    if progress and elapsed - last_report >= 1.0:
                        progress(checked, elapsed, next_scalar if next_scalar <= target.end else None)
                        last_report = elapsed
                    continue
                status = event.get("status")
                if status not in ("match", "limit", "exhausted", "duration"):
                    raise CudaError("Invalid CUDA completion status")
                if (status == "exhausted" and next_scalar != target.end + 1
                        or status == "limit" and count != cap
                        or status == "duration" and (seconds is None or
                            duration + (native_initialization if include_initialization else 0) + 0.000001 < seconds)):
                    raise CudaError("CUDA completion does not match confirmed coverage")
                match = None
                if status == "match":
                    match = integer(event, "match")
                    if not target.start <= match < next_scalar:
                        raise CudaError("CUDA match outside confirmed interval")
                    key = match.to_bytes(32, "big")
                    if (get_hash160(get_public_key(key, compressed=True)) != target_hash
                            or Wallet(private_key=key).address.bitcoin.P2PKH != target.address):
                        raise CudaError("CUDA match failed independent verification")
                return ScanResult(status, checked, elapsed,
                                  next_scalar if next_scalar <= target.end else None,
                                  match, initialization, perf_counter() - started + startup)
        except KeyboardInterrupt:
            # Never advance across an in-flight batch. Repeating keys is safe;
            # skipping unacknowledged work would leave a hole in the search.
            self.close()
            next_scalar = target.start + checked
            return ScanResult("interrupted", checked, elapsed,
                              next_scalar if next_scalar <= target.end else None,
                              None, initialization, perf_counter() - started + startup)
        except (OSError, CudaError) as exc:
            self.close()
            raise CudaError(f"{exc}; confirmed {checked} keys; resume at 0x{target.start + checked:x}") from exc

    def close(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                self.process.stdin.close()
                self.process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait()
        for thread in self.threads:
            thread.join(timeout=2)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream and not stream.closed:
                stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def default_configuration(device):
    return {"blocks": 2 * device["sm"], "threads": 128, "points": 128}


def select_backend(requested, device=0):
    if requested == "cpu":
        return None, "CPU selected explicitly"
    try:
        worker = CudaWorker(device)
        return worker, f"CUDA: {worker.device['name']}"
    except (OSError, CudaError) as exc:
        if requested == "cuda":
            raise CudaError(f"CUDA unavailable: {exc}. Run python -m bitcoin_puzzle.setup_cuda") from exc
        return None, f"CPU fallback: CUDA unavailable ({exc})"
