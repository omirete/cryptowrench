# Experiments

A home for fun, educational explorations of cryptography and blockchains. Each experiment lives in its own folder, with its own instructions, tests, and any optional dependencies or setup.

These experiments are kept separate from the `cryptowrench` library and excluded from published wheels and source distributions. The `examples/` folder contains short examples of using the library; larger explorations belong here.

## Try an experiment

- [Bitcoin puzzle playground](bitcoin_puzzle/README.md): explore bounded key searches, CPU and CUDA backends, benchmarks, and reproducible random traversal.

Run commands from the repository root after `uv sync --group dev`. For example:

```sh
uv run python -m experiments.bitcoin_puzzle scan --puzzle 1 --limit 1 --backend cpu
```

## Add an experiment

Create `experiments/<name>/` with a short README explaining what it explores, how to run it, and any setup it needs. Keep experiment-specific code, data, and tests together. Keep downloaded tools, build output, and generated results in an ignored `.local/` directory inside that experiment, using a local `.gitignore`.

Use the library where helpful, and document optional dependencies in the experiment's README. Experiments should not add dependencies to the published library.

## Run tests

The default `uv run pytest` runs the library tests. Include experiments explicitly:

```sh
uv run pytest experiments
uv run pytest tests experiments
```
