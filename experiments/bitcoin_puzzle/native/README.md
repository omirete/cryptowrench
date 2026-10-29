# CUDA worker protocol

Launch `.local/build/puzzle_cuda.exe DEVICE_INDEX`. It immediately emits a JSON `device` event with protocol version (`protocol: 2`), name, UUID, multiprocessor count (`sm`), driver version, and compute capability (`major`, `minor`). CUDA diagnostics are written to stderr. The process remains alive for multiple scan requests on stdin.

Each request is one ASCII line:

```text scan START END CAP SECONDS BLOCKS THREADS POINTS HASH160 scan_wall START END CAP SECONDS BLOCKS THREADS POINTS HASH160 ```

START/END are inclusive hexadecimal scalars, CAP is the maximum number of candidate hashes to compare (hexadecimal), and HASH160 is 40 hexadecimal digits. SECONDS is a finite decimal duration, with zero meaning no duration limit. `scan` budgets steady-state time. `scan_wall` also budgets native initialization, allowing the random coordinator to pass the remaining overall wall-clock budget to each chunk. Event `elapsed` fields remain steady-state times in both modes; the coordinator measures effective throughput with its own overall clock. Launch dimensions are positive decimal integers; threads must be a multiple of 32. Python validates these inputs before submitting them; the worker validates them again. No shell is used to launch the worker.

The worker emits newline-delimited JSON:

- `ready`: allocation/point-generation time in `initialization` (seconds). - `progress`: synchronized completed-prefix `checked`, `next`, and `elapsed`. - `done`: the same coverage fields, plus `status` (`match`, `limit`, `exhausted`,   or `duration`); a match also has `match`. - `error`: a message; the process exits unsuccessfully.

All scalars and counts are hexadecimal **strings**, preserving precision across the protocol. Times are finite, nonnegative numbers in seconds. `next` always equals `start + checked`, even when it lies just past the inclusive end. Python converts that exhausted resume position to `None` for the existing result API. Counts use 256-bit native integers and arbitrary-precision Python integers.

Steady-state elapsed time starts after the `ready` event. Acknowledgments are emitted after each synchronized GPU batch, except that a matching batch is acknowledged only in the final `done` event. This lets Python verify and record the key together with its coverage before a durable checkpoint advances past it. Python validates event order, monotonic time/counts, exact caps, resume positions, and completion consistency. It independently derives and verifies every reported match. Human console text is never parsed as progress.

On interruption Python closes stdin, waits briefly, then kills and joins the process if it is still working. Only acknowledged prefixes count as confirmed; unacknowledged work may be repeated on resumption. An abnormal exit or malformed event is an error and reports the last confirmed position, not exhaustion.

The last batch masks hashes outside the requested prefix while retaining the point additions needed by batch inversion. Thus it can do auxiliary arithmetic outside the prefix, but compares exactly the permitted candidate hashes.

Random traversal itself stays above this protocol. The Python coordinator sends one consecutive subrange per chunk and reuses the process across chunks. Native per-request counts therefore remain consecutive prefixes, while checkpoint positions use a permutation ordinal and offset. Rebuild older workers with `python -m experiments.bitcoin_puzzle.setup_cuda` before using protocol version 2.
