# Bitcoin puzzle playground

Repository-only experiments. This folder is excluded from the published Cryptowrench distributions. Run commands from the repository root after `uv sync --group dev`. The CPU backend needs no additional dependencies. The optional CUDA backend uses a project-local native build.

## CUDA setup and backend selection

On Windows with Visual Studio 2022 C++ tools and an NVIDIA GPU with compute capability 8.9 or newer:

```sh uv run python -m bitcoin_puzzle.setup_cuda ```

This downloads checksum-verified official NVIDIA CUDA 12.8.1 redistributable components (nvcc 12.8.93, cudart/CCCL 12.8.90) and pinned BitCrack sources, then builds an optimized `sm_89` executable. Downloads, toolkit, sources, build output, manifest, and device settings stay inside ignored `bitcoin_puzzle/.local/`. No driver installation, global PATH changes, or administrator setup is needed. The script needs network access on its first run; scans and benchmarks stay offline.

`--backend auto` is the default: use the built CUDA worker when a compatible device is available, otherwise print the reason and use CPU. Choose explicitly:

```sh uv run python -m bitcoin_puzzle scan --puzzle 71 --limit 1000000000 --backend cuda --device 0 uv run python -m bitcoin_puzzle benchmark --puzzle 71 --backend cpu --seconds 5 ```

Explicit `--backend cuda` fails if CUDA is unavailable. A failure after a GPU scan begins is always an error, never an automatic CPU retry or a search miss. Other platforms can use `--backend cpu`; this build script targets Windows/MSVC.

## Try a known solution

Puzzle #1's public solution is scalar `1`. Never send funds to public test keys.

```sh uv run python -m bitcoin_puzzle scan --puzzle 1 --limit 1 ```

## Measure this computer

```sh uv run python -m bitcoin_puzzle benchmark --puzzle 71 uv run python -m bitcoin_puzzle benchmark --puzzle 140 --seconds 2 uv run python -m bitcoin_puzzle benchmark --puzzle 71 --backend cuda --tune --seconds 30 ```

Sequential benchmarks run for ten seconds by default over the selected interval, using the same search path as the scanner. GPU initialization is reported separately from steady-state time; end-to-end time and throughput include initialization. The CPU reference measures its existing loop directly. A duration is checked between candidates on CPU and synchronized batches on CUDA, so a run can exceed the requested duration by that unit of work. It stops early if a match is found.

`--tune` validates and measures exactly eight CUDA configurations: blocks at two/four times the device's multiprocessor count, 128/256 threads per block, and 128/256 points per thread. Each must pass known-key, high-bit-key, and masked boundary tests before its two-second timing trial. It then benchmarks the winner for `--seconds` (ten by default). Use a large interval such as puzzle 71; tuning fails if a trial finds a match or exhausts the interval too soon. Failed or interrupted tuning does not save new settings.

Settings are keyed by device UUID and include the driver version and executable SHA-256. Rebuilding the executable or changing the driver invalidates them; the next scan uses conservative launch dimensions until tuning is repeated.

It reports throughput, estimated full-range and halfway search times, and the fraction of the interval searchable in one day. These assume sustained speed and a uniformly placed key, not a promise of a solution. One-day coverage is capped at 100%; it is also the success probability under those assumptions when candidates are distinct and the target is still unclaimed.

## Make a bounded attempt

```sh uv run python -m bitcoin_puzzle scan --puzzle 71 --limit 10000 ```

Both commands require `--puzzle N`, with numbers 1–160 supported. The address comes from the bundled catalog; inclusive bounds are derived as `2**(N-1)` through `2**N - 1`. The program prints the resolved number, address, and selected interval before scanning. It uses compressed public keys for every puzzle, including those whose public keys have been revealed; there is no kangaroo solver.

Every scan requires a positive `--limit`. Bounds are hexadecimal, with or without `0x`; the limit is decimal. Optional `--start` and `--end` overrides select a subrange inside the puzzle's interval. Omitted bounds use that puzzle's endpoints. There is no `--address` option. Benchmark estimates use the selected subrange, so overriding the bounds also changes its coverage and time estimates.

Progress appears about once a second. On completion or Ctrl+C, the tool reports the next untested scalar. Resume using that value, for example:

```sh uv run python -m bitcoin_puzzle scan --puzzle 71 --start 0x400000000000002710 --limit 10000 ```

That example assumes the previous run checked exactly 10,000 candidates from the default start. Always use your own reported value. Overrides must stay inside the selected puzzle's interval. CPU interruptions retry an incomplete candidate; CUDA interruptions replay any unacknowledged batch from the last confirmed position. The native process is stopped and joined before returning. There are no sequential-search checkpoint files. Ctrl+C returns exit code 130. Match, limit, duration, and exhausted-range outcomes return 0; invalid input returns 2; CUDA errors return 1.

The CPU scanner derives compressed public keys and compares HASH160 directly. CUDA keeps public points, incremental point additions, SHA-256, RIPEMD-160, and target comparison on the GPU. Only progress and matches cross to Python. The last partial batch masks hash/comparison work beyond the exact cap and inclusive end; auxiliary point generation still uses full GPU batches. A GPU match counts the whole completed batch, whereas CPU stops at the matching candidate.

Every GPU match is independently checked against its confirmed interval, target hash, and Cryptowrench `Wallet` before its 64-digit key is printed. Native errors include the last confirmed resume position. Repeated runs from the same start repeat work; random starts do not improve probability per distinct candidate. There is no transaction creation, pool client, or kangaroo solver.

## Random chunk search

Sequential order remains the default. To visit chunks of the puzzle's range in a reproducible pseudorandom order:

```sh uv run python -m bitcoin_puzzle scan --puzzle 71 --order random --limit 1000000000 ```

Chunks do not overlap; keys inside each chunk are checked sequentially using the selected CPU or CUDA backend. The default chunk size is `2**34` (17,179,869,184 keys), amortizing GPU point initialization over a long scan. `--limit` still counts candidate keys in this invocation, across all chunks, and a limit can stop partway through a chunk.

The first run generates and prints a random 256-bit seed. An eight-round keyed BLAKE2b Feistel permutation visits each chunk exactly once without storing a visited-key set. Cycle walking supports non-power-of-two chunk counts; the last spatial chunk can be shorter. The permutation is versioned so an update cannot silently change the ordering of an existing saved search.

### Saved searches

Random scans automatically save to `bitcoin_puzzle/.local/searches/puzzle-N-random.json`. Repeat the command to continue the same search, using any positive `--limit`. Backend choice and CUDA launch settings can change between runs. The saved bounds, seed, and chunk size are restored when their flags are omitted.

```sh uv run python -m bitcoin_puzzle scan --puzzle 71 --order random --limit 1000000000 ```

To create a separate search with an explicit hexadecimal seed and a smaller decimal chunk size, use a different checkpoint:

```sh uv run python -m bitcoin_puzzle scan --puzzle 71 --order random --seed 2a --chunk-size 4294967296 --checkpoint bitcoin_puzzle/.local/searches/puzzle-71-small.json --limit 1000000000 ```

`--start` and `--end` define the original selected interval. They are not a random-mode resume cursor. Explicit flags that conflict with a saved search are rejected; choose a different checkpoint for a new search. Corrupt or incompatible files are also rejected rather than reset. Completed searches do not scan again.

Checkpoints record the chunk ordinal, confirmed offset, cumulative coverage, format/algorithm versions, and any verified match. They are saved approximately once per second, at chunk boundaries, and at completion/interruption, using flushed temporary files and atomic replacement. An exclusive OS lock prevents two processes from advancing the same checkpoint; a process crash releases it. A match and its coverage position are committed together.

Confirmed coverage is never revisited by a normally resumed saved search. An abrupt crash can replay work since the last durable save; replay prevents skipping unconfirmed keys. Separate checkpoint files or seeds can overlap, and previous sequential searches are not tracked. Random order does not improve the probability per distinct candidate.

### Random benchmarks

```sh uv run python -m bitcoin_puzzle benchmark --puzzle 71 --order random --seed 2a --seconds 30 ```

Benchmarks use independent temporary traversal state and never read or advance a saved search. Random-mode throughput includes chunk initialization and transitions. A single overall `--seconds` budget applies across chunks, with checks between GPU batches and after initialization. Non-preemptible initialization or a final batch can overrun a very short budget; actual elapsed time is always reported. `--tune` tunes the common sequential kernel first and then runs the random benchmark without changing any saved search.

## Address catalog

`addresses.json` maps puzzle numbers to mainnet P2PKH addresses. Every command validates that all 160 entries exist and have valid address checksums. Missing, malformed, or incomplete catalog data causes a clear error before scanning. The catalog contains no live balances or solved-status claims; the program does not query the chain or update this file at runtime.

Source: lotterypuzzle (2026), [Bitcoin Puzzle catalog](https://lotterypuzzle.org/data/), snapshot of 2026-10-02, downloaded on 2026-10-28 from [puzzles.json](https://lotterypuzzle.org/data/puzzles.json). The compilation is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). This copy extracts only `id` and `address`, converting the records into a mapping; all other source fields are omitted and ranges are calculated locally.

## Validation

```sh uv run pytest tests bitcoin_puzzle uv build ```

To include hardware tests in PowerShell:

```powershell $env:BITCOIN_PUZZLE_CUDA_TESTS = '1' uv run pytest tests bitcoin_puzzle ```

Tests and public-key fixtures live here, separate from the library tests. The existing default `uv run pytest` continues to run the library suite; include `bitcoin_puzzle` explicitly to test this playground as well.

## Local benchmark

Measured on 2026-10-27 with Python 3.11.14 on Windows in the Codex sandbox, using a ten-second benchmark over puzzle #71's complete interval, equivalent to:

```sh uv run python -m bitcoin_puzzle benchmark --puzzle 71 --backend cpu --seconds 10 ```

| Measurement | Result | | --- | --- | | Candidates checked | 11,813 | | Elapsed time | 10.000 seconds | | Average throughput | 1,181 keys/second | | Full puzzle #71 interval | About 31.7 billion years | | Uniform-key halfway estimate | About 15.8 billion years | | One-day coverage | About 8.65 × 10^-14 of the interval (8.65 × 10^-12%) |

Throughput varied during this historical CPU run; it is a reference measurement, not a hardware performance claim. See the CUDA measurements below for the current backend.

## Native implementation and license

The worker adapts [BitCrack](https://github.com/brichard19/BitCrack) revision `6bf8059ef075eb1622298395866b0bd02375e1d9`, copyright Ben Richard, under the [MIT license](native/LICENSE.BitCrack). `native/upstream.json` records the revision, archive checksum, CUDA release, and architecture. `native_build.py` applies checked adaptations for exact final-batch masking, 256-bit completed-key accounting, persistent-process mapped-memory cleanup, and modern CUDA setup. No cryptographic changes are made to the published Cryptowrench package.

The reproducible build uses nvcc `-O3 -std=c++17 -arch=sm_89 -rdc=true` with MSVC `/O2 /EHsc /MD`. `.local/build/manifest.json` records the actual compiler and flags; `.local/build/build.cmd` contains the complete generated compile/link commands. Native output uses a documented structured protocol: see [native/README.md](native/README.md).

## CUDA measurements

Measured on 2026-10-28 with Python 3.11.14, Windows, Visual Studio 2022 (MSVC 14.44.35207), nvcc 12.8.93, and an RTX 4060 Laptop GPU (24 multiprocessors). Both backends searched the same complete puzzle 71 interval. CPU was warmed up before its five-second baseline; GPU used the persistent worker after tuning. The winning launch configuration was 96 blocks, 128 threads, 256 points/thread.

| Measurement | Result | | --- | --- | | CPU baseline | 12,457 keys in 5.000 seconds; 2,491 keys/second | | GPU confirmed coverage | 10,547,625,984 keys in 30.004 seconds | | GPU steady-state throughput | 351,540,177 keys/second | | GPU initialization for this request | 0.771 seconds | | GPU end-to-end throughput | 342,731,967 keys/second over 30.775 seconds | | Steady-state speedup over CPU | About 141,107 times | | Temperature samples during the GPU run | 72–73°C | | Reported GPU power samples | 23.13–31.86 W |

End-to-end time includes this request's initialization and reporting, but not the preceding tuning run or already-paid persistent-process startup. A fresh CLI process includes its worker startup in the first request's initialization and end-to-end measurements. Laptop power, clocks, competing workloads, and thermal conditions affect these results. The full puzzle 71 interval would still take about 106,419 years at this measured sustained rate (halfway: 53,210 years).

The final validation run passed **726 tests**, including opt-in GPU tests for batch boundaries, exact limits, large scalars, independent match verification, and a real interrupted search followed by resumption. Wheel and source archive inspection confirmed the entire playground and its CUDA artifacts remain excluded.

## Random traversal measurements

Measured on 2026-10-29 on the same RTX 4060, after rebuilding protocol version 2 and retuning. The winning launch configuration remained 96 blocks, 128 threads, and 256 points/thread. These are same-session measurements; device clocks and workloads differ from the historical measurements above.

| Mode | Confirmed keys | Search wall time | Effective throughput | | --- | --- | --- | --- | | Sequential reference, 15 seconds of kernel scanning | 6,455,033,856 | 16.709 seconds | 386,322,961 keys/s | | Random, `--chunk-size 4294967296`, seed `2a` | 9,863,954,432 | 30.009 seconds | 328,697,345 keys/s | | Random, default `--chunk-size 17179869184`, seed `2a` | 23,008,903,168 | 60.010 seconds | 383,420,378 keys/s |

The smaller-chunk run completed two chunks and entered a third, with 6.873 seconds of total initialization. The default-size run completed one chunk and entered a second, with 5.594 seconds of initialization. Both include the transition costs in effective throughput. The sequential reference measured 430,291,901 keys/second while scanning, before charging its initialization. Larger chunks amortize the cost of generating new starting points.

The random benchmark commands are reproducible without touching checkpoints:

```sh uv run python -m bitcoin_puzzle benchmark --puzzle 71 --backend cuda --order random --seed 2a --chunk-size 4294967296 --seconds 30 uv run python -m bitcoin_puzzle benchmark --puzzle 71 --backend cuda --order random --seed 2a --seconds 60 ```

Final validation passed **828 tests**, including exhaustive small permutations, checkpoint corruption and locking, crash lock release, atomic replacement, GPU wall-clock budgets, and saved-search resumption from CUDA to CPU. 