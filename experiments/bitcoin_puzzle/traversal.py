"""Constant-space, reproducible permutations of disjoint key-range chunks."""

from dataclasses import dataclass, field
from hashlib import blake2b
import secrets

from .catalog import puzzle_target
from .scanner import Target

ALGORITHM = "feistel-blake2b-v1"
DEFAULT_CHUNK_SIZE = 2**34


class ChunkPermutation:
    """Eight-round balanced Feistel permutation, cycle-walked into [0, count).

    Both the forward and inverse mapping are bijections. Neither needs a list
    of already visited chunks, even for intervals larger than machine integers.
    """

    def __init__(self, count: int, seed: int):
        if type(count) is not int or not 1 <= count < 2**256:
            raise ValueError("Chunk count must be a positive integer below 2**256")
        if type(seed) is not int or not 0 <= seed < 2**256:
            raise ValueError("Seed must be a 256-bit nonnegative integer")
        self.count = count
        self.key = seed.to_bytes(32, "big")
        self.width = ((count - 1).bit_length() + 1) // 2
        self.mask = (1 << self.width) - 1
        self.bytes = (self.width + 7) // 8
        self.domain = count.to_bytes(32, "big") + self.width.to_bytes(2, "big")

    def _round(self, right, round_number):
        digest = blake2b(self.domain + bytes([round_number]) + right.to_bytes(self.bytes, "big"),
                         key=self.key, digest_size=32, person=b"cw-chunks-v1").digest()
        return int.from_bytes(digest, "big") & self.mask

    def _feistel(self, value, inverse):
        left, right = value >> self.width, value & self.mask
        for number in (range(7, -1, -1) if inverse else range(8)):
            if inverse:
                left, right = right ^ self._round(left, number), left
            else:
                left, right = right, left ^ self._round(right, number)
        return (left << self.width) | right

    def _walk(self, value, inverse=False):
        if type(value) is not int or not 0 <= value < self.count:
            raise ValueError("Chunk ordinal is outside the permutation")
        if self.count == 1:
            return 0
        # The enclosing domain is less than four times count. Walking the same
        # permutation until re-entering this subset preserves its bijection.
        value = self._feistel(value, inverse)
        while value >= self.count:
            value = self._feistel(value, inverse)
        return value

    def __call__(self, ordinal):
        return self._walk(ordinal)

    def inverse(self, chunk_index):
        return self._walk(chunk_index, inverse=True)


@dataclass(frozen=True)
class Position:
    """Replace the whole position atomically, including any verified match."""

    ordinal: int = 0
    offset: int = 0
    checked: int = 0
    status: str = "active"
    match: int | None = None


@dataclass
class RandomState:
    """The ordinal/offset cursor is independent of backend and GPU batch shape."""

    puzzle: int
    address: str
    start: int
    end: int
    chunk_size: int
    seed: int
    _position: Position = field(default_factory=Position, repr=False)

    @property
    def ordinal(self):
        return self._position.ordinal

    @property
    def offset(self):
        return self._position.offset

    @property
    def checked(self):
        return self._position.checked

    @property
    def status(self):
        return self._position.status

    @property
    def match(self):
        return self._position.match

    def __post_init__(self):
        if type(self.chunk_size) is not int or not 1 <= self.chunk_size < 2**256:
            raise ValueError("Chunk size must be a positive integer below 2**256")
        if self.end < self.start:
            raise ValueError("Random interval is reversed")
        self.size = self.end - self.start + 1
        self.chunks = (self.size + self.chunk_size - 1) // self.chunk_size
        self.permutation = ChunkPermutation(self.chunks, self.seed)
        # Only the final spatial chunk can be short. Its inverse ordinal lets
        # us validate cumulative coverage without walking all preceding chunks.
        self.short_ordinal = self.permutation.inverse(self.chunks - 1)

    @property
    def target(self):
        return Target(self.address, self.start, self.end)

    def chunk(self):
        if self.ordinal >= self.chunks:
            return None
        lower = self.start + self.permutation(self.ordinal) * self.chunk_size
        return Target(self.address, lower, min(lower + self.chunk_size - 1, self.end))

    def advance(self, count, *, match=None):
        if self.status != "active" and count:
            raise ValueError("Cannot advance a terminal random search")
        if count == 0 and match is None:
            return
        chunk = self.chunk()
        if type(count) is not int or count < 0 or (count and (chunk is None or count > chunk.end - chunk.start + 1 - self.offset)):
            raise ValueError("Invalid confirmed random-search coverage")
        ordinal, offset = self.ordinal, self.offset + count
        if chunk is not None and offset == chunk.end - chunk.start + 1:
            ordinal += 1
            offset = 0
        status = "match" if match is not None else "exhausted" if ordinal == self.chunks else "active"
        # Ctrl+C cannot leave counters half-updated: constructing a new immutable
        # position has no effects until this single attribute assignment.
        self._position = Position(ordinal, offset, self.checked + count, status, match)

    def validate(self):
        expected_target = puzzle_target(self.puzzle, start=self.start, end=self.end)
        if self.address != expected_target.address:
            raise ValueError("Checkpoint address does not match selected puzzle")
        if any(type(value) is not int or value < 0 for value in (self.ordinal, self.offset, self.checked)):
            raise ValueError("Invalid checkpoint cursor")
        if self.ordinal > self.chunks:
            raise ValueError("Checkpoint chunk ordinal exceeds interval")
        chunk = self.chunk()
        if chunk is None:
            if self.offset != 0:
                raise ValueError("Exhausted checkpoint has a nonzero offset")
        elif self.offset >= chunk.end - chunk.start + 1:
            raise ValueError("Checkpoint offset exceeds its chunk")
        shortfall = self.chunks * self.chunk_size - self.size
        expected = self.ordinal * self.chunk_size + self.offset
        if self.short_ordinal < self.ordinal:
            expected -= shortfall
        if self.checked != expected:
            raise ValueError("Checkpoint count does not match traversal position")
        if self.status not in ("active", "match", "exhausted"):
            raise ValueError("Invalid checkpoint terminal status")
        if self.status == "active" and (chunk is None or self.match is not None):
            raise ValueError("Active checkpoint is inconsistent")
        if self.status == "exhausted" and (chunk is not None or self.match is not None):
            raise ValueError("Exhausted checkpoint is inconsistent")
        if self.status == "match":
            if type(self.match) is not int or not self.start <= self.match <= self.end:
                raise ValueError("Checkpoint match is outside interval")
            index, offset = divmod(self.match - self.start, self.chunk_size)
            position = self.permutation.inverse(index)
            if position > self.ordinal or (position == self.ordinal and offset >= self.offset):
                raise ValueError("Checkpoint match is outside confirmed coverage")
            from cryptowrench.wallet import Wallet
            if Wallet(private_key=self.match.to_bytes(32, "big")).address.bitcoin.P2PKH != self.address:
                raise ValueError("Checkpoint match failed independent verification")


def new_state(puzzle, *, start=None, end=None, seed=None, chunk_size=None):
    target = puzzle_target(puzzle, start=start, end=end)
    return RandomState(puzzle, target.address, target.start, target.end,
                       DEFAULT_CHUNK_SIZE if chunk_size is None else chunk_size,
                       secrets.randbits(256) if seed is None else seed)
