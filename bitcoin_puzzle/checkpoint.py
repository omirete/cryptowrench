"""Exclusive, atomically replaced random-search checkpoints."""

from contextlib import AbstractContextManager
import json
import os
from pathlib import Path
import re
import tempfile

from .traversal import ALGORITHM, Position, RandomState, new_state

VERSION = 1
SEARCHES = Path(__file__).resolve().parent / ".local" / "searches"
FIELDS = ("puzzle", "address", "start", "end", "chunk_size", "seed", "ordinal", "offset", "checked", "status", "match")


class CheckpointError(RuntimeError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate checkpoint field: {key}")
        result[key] = value
    return result


def encode(state):
    data = {name: getattr(state, name) for name in FIELDS}
    for name in ("start", "end", "seed", "match"):
        data[name] = None if data[name] is None else format(data[name], "x")
    for name in ("chunk_size", "ordinal", "offset", "checked"):
        data[name] = str(data[name])
    return {"format_version": VERSION, "algorithm": ALGORITHM, **data}


def decode(data):
    expected = set(FIELDS) | {"format_version", "algorithm"}
    if not isinstance(data, dict) or set(data) != expected:
        raise ValueError("Checkpoint fields are missing or unknown")
    if type(data["format_version"]) is not int or data["format_version"] != VERSION or data["algorithm"] != ALGORITHM:
        raise ValueError("Incompatible checkpoint version or permutation algorithm")
    data = {key: value for key, value in data.items() if key not in ("format_version", "algorithm")}
    for name in ("start", "end", "seed", "match", "chunk_size", "ordinal", "offset", "checked"):
        if name == "match" and data[name] is None:
            continue
        pattern = r"[0-9a-f]{1,64}" if name in ("start", "end", "seed", "match") else r"[0-9]{1,78}"
        if not isinstance(data[name], str) or not re.fullmatch(pattern, data[name]):
            raise ValueError(f"Invalid checkpoint integer: {name}")
        data[name] = int(data[name], 16 if name in ("start", "end", "seed", "match") else 10)
    position = Position(**{name: data.pop(name) for name in ("ordinal", "offset", "checked", "status", "match")})
    state = RandomState(**data, _position=position)
    state.validate()
    return state


class Checkpoint(AbstractContextManager):
    """The OS releases this advisory lock even when the process crashes."""

    def __init__(self, path):
        self.path = Path(path).resolve()
        self.lock = None

    def __enter__(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.lock = self.path.with_name(self.path.name + ".lock").open("a+b")
            self.lock.seek(0, os.SEEK_END)
            if self.lock.tell() == 0:
                self.lock.write(b"\0")
                self.lock.flush()
            self.lock.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if self.lock:
                self.lock.close()
            self.lock = None
            raise CheckpointError(f"Cannot lock checkpoint {self.path}; another search may be using it: {exc}") from exc
        return self

    def __exit__(self, *args):
        if self.lock:
            self.lock.close()
            self.lock = None

    def load_or_create(self, puzzle, *, start=None, end=None, seed=None, chunk_size=None):
        if not self.path.exists():
            state = new_state(puzzle, start=start, end=end, seed=seed, chunk_size=chunk_size)
            self.save(state)
            return state
        try:
            state = decode(json.loads(self.path.read_text(encoding="utf-8"), object_pairs_hook=unique_object))
        except (OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
            raise ValueError(f"Invalid checkpoint {self.path}: {exc}") from exc
        for name, value in (("puzzle", puzzle), ("start", start), ("end", end),
                            ("seed", seed), ("chunk_size", chunk_size)):
            if value is not None and value != getattr(state, name):
                raise ValueError(f"Explicit {name} conflicts with checkpoint {self.path}; use a different checkpoint for a new search")
        return state

    def save(self, state):
        if self.lock is None:
            raise CheckpointError("Checkpoint must be locked before writing")
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.path.parent,
                                             prefix=self.path.name + ".", suffix=".tmp", delete=False) as output:
                temporary = Path(output.name)
                json.dump(encode(state), output, indent=2)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
        except OSError as exc:
            raise CheckpointError(f"Cannot save checkpoint {self.path}: {exc}") from exc
        finally:
            if temporary and temporary.exists():
                try:
                    temporary.unlink()
                except OSError:
                    pass  # Preserve the original save error if cleanup also fails.
