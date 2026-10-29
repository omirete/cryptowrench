"""Coordinate disjoint random chunks through either existing scanner backend."""

from time import perf_counter

from .scanner import ScanResult, Target, validate_scan


def search(state, limit, backend, *, seconds=None, checkpoint=None, progress=None,
           clock=perf_counter, startup=0.0):
    """Return per-invocation counts; state retains cumulative confirmed coverage.

    A backend callback reports a prefix inside just the current chunk. Commit
    deltas, never its absolute count, so resume cannot double-count a GPU batch.
    """
    validate_scan(state.target, limit, seconds)
    state.validate()
    initial_checked = state.checked
    began = clock() - startup
    deadline = began + seconds if seconds is not None else None
    initialization = 0.0
    last_saved = clock()
    last_report = clock()
    status = state.status if state.status != "active" else "limit"

    def save():
        if checkpoint:
            checkpoint.save(state)

    def report():
        nonlocal last_report
        if progress:
            progress(state.checked - initial_checked, clock() - began, state)
        last_report = clock()

    try:
        while state.status == "active" and state.checked - initial_checked < limit:
            remaining_seconds = None if deadline is None else deadline - clock()
            if remaining_seconds is not None and remaining_seconds <= 0:
                status = "duration"
                break
            chunk = state.chunk()
            target = Target(chunk.address, chunk.start + state.offset, chunk.end)
            cap = min(limit - (state.checked - initial_checked), target.end - target.start + 1)
            local_checked = 0

            def commit(checked, elapsed, next_scalar, *, persist=True, match=None):
                nonlocal local_checked, last_saved
                if type(checked) is not int or not local_checked <= checked <= cap:
                    raise RuntimeError("Invalid random-search backend coverage")
                expected_next = target.start + checked
                if next_scalar != (expected_next if expected_next <= target.end else None):
                    raise RuntimeError("Random-search backend returned an inconsistent resume point")
                if checked > local_checked or match is not None:
                    state.advance(checked - local_checked, match=match)
                local_checked = checked
                if persist and clock() - last_saved >= 1.0:
                    save()
                    last_saved = clock()
                if persist and clock() - last_report >= 1.0:
                    report()

            result = backend(target, cap, seconds=remaining_seconds, progress=commit)
            # A callback may already have acknowledged this final count.
            # A matching final batch and its key must be saved atomically; do
            # not checkpoint past that key before recording the verified match.
            commit(result.checked, result.elapsed, result.next_scalar, persist=False, match=result.match)
            initialization += result.initialization
            if result.match is not None:
                status = "match"
            elif result.status in ("interrupted", "duration"):
                status = result.status
            elif state.status == "exhausted":
                status = "exhausted"
            elif result.status not in ("limit", "exhausted") or result.checked == 0:
                raise RuntimeError("Random-search backend failed to make confirmed progress")
            save()
            last_saved = clock()
            if clock() - last_report >= 1.0:
                report()
            if state.status != "active" or status in ("interrupted", "duration"):
                break
    except KeyboardInterrupt:
        status = "interrupted"
    finally:
        # On native failure only callback-confirmed coverage is committed. Any
        # unacknowledged work can be safely replayed from this durable cursor.
        save()
    elapsed = clock() - began
    return ScanResult(status, state.checked - initial_checked, elapsed, None,
                      state.match, initialization, elapsed)
