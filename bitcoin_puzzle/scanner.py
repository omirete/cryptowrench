"""Bounded reference scanner using Cryptowrench's existing key helpers."""

from dataclasses import dataclass
import math
from time import perf_counter

from base58 import b58decode_check

from cryptowrench.wallet import Wallet
from cryptowrench.wallet.helpers.elliptic_math import SECP256K1_Helpers
from cryptowrench.wallet.helpers.hashfuncs import get_hash160
from cryptowrench.wallet.helpers.keys import get_public_key


@dataclass(frozen=True)
class Target:
    """A Bitcoin address and inclusive bounds on private-key integers (scalars)."""

    address: str
    start: int
    end: int


def decode_target(address: str) -> bytes:
    """Accept only checksummed mainnet P2PKH addresses."""
    try:
        payload = b58decode_check(address)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError("Target must be a valid Base58Check mainnet P2PKH address") from exc
    # Base58Check decoding verifies and removes the checksum. What remains is
    # the mainnet version byte (0x00), followed by the 20-byte public-key hash.
    if len(payload) != 21 or payload[0] != 0:
        raise ValueError("Target must be a mainnet P2PKH address")
    return payload[1:]


@dataclass(frozen=True)
class ScanResult:
    """Run summary; next_scalar is the resume point, or None at the interval's end."""

    status: str
    checked: int
    elapsed: float
    next_scalar: int | None
    match: int | None

    @property
    def rate(self) -> float:
        return self.checked / self.elapsed if self.elapsed > 0 else 0.0


def scan(target: Target, limit: int, *, seconds: float | None = None,
         clock=perf_counter, progress=None) -> ScanResult:
    """Scan inclusive bounds, counting only fully checked candidates.

    Interrupting a candidate leaves it as the next untested scalar. A progress
    callback receives (checked, elapsed, next_scalar), at most once per second.
    """
    # Decode once: candidates can be compared as hashes without Base58 encoding
    # an address or constructing a full Wallet on every iteration.
    target_hash = decode_target(target.address)
    if not 1 <= target.start <= target.end < SECP256K1_Helpers.order:
        raise ValueError("Require 1 <= start <= end < secp256k1 order")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise ValueError("Candidate limit must be a positive integer")
    if seconds is not None and (not math.isfinite(seconds) or seconds <= 0):
        raise ValueError("Duration must be finite and positive")

    # perf_counter measures elapsed time without depending on wall-clock changes.
    # Accepting a clock also lets tests exercise duration limits deterministically.
    started = clock()
    last_progress = started
    checked = 0
    candidate = target.start
    match = None
    status = "limit"
    try:
        while candidate <= target.end and checked < limit:
            now = clock()
            if seconds is not None and now - started >= seconds:
                status = "duration"
                break
            # Key helpers require 32-byte, big-endian scalars, including leading zeros.
            # P2PKH hashes the serialized public key; compressed serialization matters.
            key = candidate.to_bytes(32, "big")
            if get_hash160(get_public_key(key, compressed=True)) == target_hash:
                # Verify through the higher-level address path before reporting.
                if Wallet(private_key=key).address.bitcoin.P2PKH != target.address:
                    raise RuntimeError("Candidate failed independent Wallet verification")
                match = candidate
                checked += 1
                candidate += 1
                status = "match"
                break
            candidate += 1
            checked += 1
            if progress is not None and now - last_progress >= 1:
                progress(checked, now - started, candidate if candidate <= target.end else None)
                last_progress = now
        else:
            status = "exhausted" if candidate > target.end else "limit"
    except KeyboardInterrupt:
        # Return progress instead of a traceback so the caller can resume manually.
        status = "interrupted"

    return ScanResult(status, checked, clock() - started,
                      candidate if candidate <= target.end else None, match)


def estimates(result: ScanResult, size: int) -> dict[str, float]:
    """Uniform-key estimates for a sustained measured rate, not predictions."""
    rate = result.rate
    # A uniformly placed target is found halfway through a distinct sequential
    # scan on average. One day's coverage cannot exceed the entire interval.
    return {
        "full_seconds": size / rate if rate else math.inf,
        "half_seconds": size / (2 * rate) if rate else math.inf,
        "day_fraction": min(rate * 86400 / size, 1.0),
    }
