# Bitcoin puzzle playground

Repository-only experiments. This folder is excluded from the published Cryptowrench distributions. Run commands from the repository root after `uv sync --group dev`. No additional dependencies are needed.

## Try a known solution

Puzzle #1's public solution is scalar `1`. Never send funds to public test keys.

```sh
uv run python -m bitcoin_puzzle scan --puzzle 1 --limit 1
```

## Measure this computer

```sh
uv run python -m bitcoin_puzzle benchmark --puzzle 71
uv run python -m bitcoin_puzzle benchmark --puzzle 140 --seconds 2
```

The benchmark runs for ten seconds by default over the selected interval, using the same candidate-checking loop as the scanner. Initialization is excluded; elapsed time includes loop and progress-reporting overhead. A duration is checked between candidates, so a run may exceed it by a candidate's processing time. It stops early if a match is found.

It reports throughput, estimated full-range and halfway search times, and the fraction of the interval searchable in one day. These assume sustained speed and a uniformly placed key, not a promise of a solution. One-day coverage is capped at 100%; it is also the success probability under those assumptions when candidates are distinct and the target is still unclaimed.

## Make a bounded attempt

```sh
uv run python -m bitcoin_puzzle scan --puzzle 71 --limit 10000
```

Both commands require `--puzzle N`, with numbers 1–160 supported. The address comes from the bundled catalog; inclusive bounds are derived as `2**(N-1)` through `2**N - 1`. The program prints the resolved number, address, and selected interval before scanning. It uses compressed public keys for every puzzle, including those whose public keys have been revealed; there is no kangaroo solver.

Every scan requires a positive `--limit`. Bounds are hexadecimal, with or without `0x`; the limit is decimal. Optional `--start` and `--end` overrides select a subrange inside the puzzle's interval. Omitted bounds use that puzzle's endpoints. There is no `--address` option. Benchmark estimates use the selected subrange, so overriding the bounds also changes its coverage and time estimates.

Progress appears about once a second. On completion or Ctrl+C, the tool reports the next untested scalar. Resume using that value, for example:

```sh
uv run python -m bitcoin_puzzle scan --puzzle 71 --start 0x400000000000002710 --limit 10000
```

That example assumes the previous run checked exactly 10,000 candidates from the default start. Always use your own reported value. Overrides must stay inside the selected puzzle's interval. An interrupted, incomplete candidate is retried; there are no checkpoint files. Ctrl+C returns exit code 130. Match, limit, duration, and exhausted-range outcomes return 0; invalid input returns 2.

The scanner derives compressed public keys and compares HASH160 directly. It uses `Wallet` only to verify a match before printing its 64-digit private key. There is no network access, transaction creation, GPU backend, or pool client. Repeated runs from the same start repeat work; random starts do not improve the probability per distinct candidate.

## Address catalog

`addresses.json` maps puzzle numbers to mainnet P2PKH addresses. Every command validates that all 160 entries exist and have valid address checksums. Missing, malformed, or incomplete catalog data causes a clear error before scanning. The catalog contains no live balances or solved-status claims; the program does not query the chain or update this file at runtime.

Source: lotterypuzzle (2026), [Bitcoin Puzzle catalog](https://lotterypuzzle.org/data/), snapshot of 2026-10-02, downloaded on 2026-10-28 from [puzzles.json](https://lotterypuzzle.org/data/puzzles.json). The compilation is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). This copy extracts only `id` and `address`, converting the records into a mapping; all other source fields are omitted and ranges are calculated locally.

## Validation

```sh
uv run pytest tests bitcoin_puzzle
uv build
```

Tests and public-key fixtures live here, separate from the library tests. The existing default `uv run pytest` continues to run the library suite; include `bitcoin_puzzle` explicitly to test this playground as well.

## Local benchmark

Measured on 2026-10-27 with Python 3.11.14 on Windows in the Codex sandbox, using a ten-second benchmark over puzzle #71's complete interval, equivalent to:

```sh
uv run python -m bitcoin_puzzle benchmark --puzzle 71 --seconds 10
```

| Measurement | Result |
| --- | --- |
| Candidates checked | 11,813 |
| Elapsed time | 10.000 seconds |
| Average throughput | 1,181 keys/second |
| Full puzzle #71 interval | About 31.7 billion years |
| Uniform-key halfway estimate | About 15.8 billion years |
| One-day coverage | About 8.65 × 10^-14 of the interval (8.65 × 10^-12%) |

Throughput varied during this run; this is a local reference measurement, not a hardware performance claim. Rerun on your own machine before considering a separate GPU search project.
