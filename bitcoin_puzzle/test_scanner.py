"""Public test keys only. Run: uv run pytest bitcoin_puzzle"""

from dataclasses import replace
import json

from base58 import b58encode_check
import pytest

from bitcoin_puzzle import catalog, scanner
from bitcoin_puzzle.__main__ import main
from bitcoin_puzzle.catalog import load_catalog, puzzle_target
from bitcoin_puzzle.scanner import Target, decode_target, estimates, scan
from cryptowrench.wallet import Wallet
from cryptowrench.wallet.helpers.elliptic_math import SECP256K1_Helpers


PUZZLE_1 = Target("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", 1, 1)


def test_solved_puzzle_one():
    result = scan(PUZZLE_1, 1)
    assert (result.status, result.match, result.checked, result.next_scalar) == (
        "match", 1, 1, None
    )


@pytest.mark.parametrize("scalar", [2, 4])
def test_inclusive_boundaries(scalar):
    address = Wallet(private_key=scalar.to_bytes(32, "big")).address.bitcoin.P2PKH
    result = scan(Target(address, 2, 4), 3)
    assert result.status == "match"
    assert result.match == scalar
    assert result.checked == scalar - 1


def test_limit_and_resume_without_overlap():
    target = replace(PUZZLE_1, start=2, end=5)
    first = scan(target, 2)
    assert (first.status, first.checked, first.next_scalar) == ("limit", 2, 4)
    second = scan(replace(target, start=first.next_scalar), 10)
    assert (second.status, second.checked, second.next_scalar) == ("exhausted", 2, None)


@pytest.mark.parametrize("address", [
    "", "0bad", PUZZLE_1.address[:-1] + "J", "é",
    b58encode_check(b"\x6f" + bytes(20)).decode(),
    b58encode_check(b"\x05" + bytes(20)).decode(),
    b58encode_check(b"\x00" + bytes(19)).decode(),
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
])
def test_invalid_addresses(address):
    with pytest.raises(ValueError):
        scan(replace(PUZZLE_1, address=address), 1)


@pytest.mark.parametrize("start,end", [(0, 1), (-1, 1), (2, 1),
                                            (1, SECP256K1_Helpers.order)])
def test_invalid_ranges(start, end):
    with pytest.raises(ValueError):
        scan(replace(PUZZLE_1, start=start, end=end), 1)


@pytest.mark.parametrize("limit", [0, -1, 1.5, True])
def test_invalid_limits(limit):
    with pytest.raises(ValueError):
        scan(PUZZLE_1, limit)


@pytest.mark.parametrize("seconds", [0, -1, float("nan"), float("inf")])
def test_invalid_duration(seconds):
    with pytest.raises(ValueError):
        scan(PUZZLE_1, 1, seconds=seconds)


def test_known_catalog_address():
    target = puzzle_target(71)
    assert decode_target(target.address).hex() == "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8"


@pytest.mark.parametrize("number", range(1, 161))
def test_catalog_and_derived_intervals(number):
    target = puzzle_target(number)
    assert len(decode_target(target.address)) == 20
    assert target.start == 2**(number - 1)
    assert target.end == 2**number - 1
    assert target.end - target.start + 1 == 2**(number - 1)


def test_catalog_completeness():
    addresses = load_catalog()
    assert set(addresses) == set(range(1, 161))
    assert len(set(addresses.values())) == 160


@pytest.mark.parametrize("content", ["{", "[]", "{}", '{"1": "bad"}'])
def test_malformed_or_incomplete_catalog(tmp_path, content):
    path = tmp_path / "addresses.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="catalog"):
        load_catalog(path)


@pytest.mark.parametrize("replacement", ["bad", PUZZLE_1.address[:-1] + "J", None, 123])
def test_invalid_catalog_address(tmp_path, replacement):
    data = {str(n): address for n, address in load_catalog().items()}
    data["160"] = replacement
    path = tmp_path / "addresses.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="puzzle 160"):
        load_catalog(path)


def test_missing_catalog_cli(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(catalog, "CATALOG_PATH", tmp_path / "missing.json")
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--puzzle", "1", "--limit", "1"])
    assert exc.value.code == 2
    assert "Cannot read puzzle catalog" in capsys.readouterr().err


def test_timed_loop_and_estimates():
    ticks = iter([0.0, 0.0, 0.5, 1.0, 1.0])
    result = scan(replace(PUZZLE_1, start=2, end=5), 4,
                  seconds=1, clock=lambda: next(ticks))
    assert (result.status, result.checked, result.next_scalar) == ("duration", 2, 4)
    assert result.rate == 2
    values = estimates(result, 1_000_000)
    assert values == {"full_seconds": 500_000, "half_seconds": 250_000,
                      "day_fraction": 0.1728}


def test_interruption_keeps_incomplete_candidate(monkeypatch):
    original = scanner.get_public_key

    def interrupt(key, compressed):
        if int.from_bytes(key, "big") == 3:
            raise KeyboardInterrupt
        return original(key, compressed=compressed)

    monkeypatch.setattr(scanner, "get_public_key", interrupt)
    result = scan(replace(PUZZLE_1, start=2, end=5), 4)
    assert (result.status, result.checked, result.next_scalar) == ("interrupted", 1, 3)


def test_match_requires_wallet_verification(monkeypatch):
    monkeypatch.setattr(scanner, "get_hash160", lambda _: decode_target(PUZZLE_1.address))
    with pytest.raises(RuntimeError, match="verification"):
        scan(replace(PUZZLE_1, start=2, end=2), 1)


def test_progress_callback():
    ticks = iter([0, 1, 2, 3])
    updates = []
    result = scan(replace(PUZZLE_1, start=2, end=3), 2,
                  clock=lambda: next(ticks), progress=lambda *args: updates.append(args))
    assert updates == [(1, 1, 3), (2, 2, None)]
    assert result.checked == 2


@pytest.mark.parametrize("number,scalar", [(1, 1), (2, 3), (3, 7), (4, 8)])
def test_cli_solved_puzzle(capsys, number, scalar):
    assert main(["scan", "--puzzle", str(number), "--limit", "16"]) == 0
    output = capsys.readouterr().out
    assert "Status: match" in output
    assert f"Verified private key: {scalar:064x}" in output
    assert f"Puzzle: {number}; address:" in output
    assert "Selected interval (inclusive):" in output


def test_cli_manual_resume(capsys):
    assert main(["scan", "--puzzle", "2", "--limit", "1"]) == 0
    first = capsys.readouterr().out
    assert "Status: limit" in first
    assert "Next untested scalar: 0x3" in first
    assert main(["scan", "--puzzle", "2", "--start", "0x3", "--end", "3", "--limit", "1"]) == 0
    second = capsys.readouterr().out
    assert "Status: match" in second
    assert "Checked: 1;" in second


def test_cli_largest_puzzle(capsys):
    assert main(["scan", "--puzzle", "160", "--limit", "1"]) == 0
    output = capsys.readouterr().out
    assert f"0x{2**159:x} through 0x{2**160 - 1:x}" in output
    assert f"Next untested scalar: 0x{2**159 + 1:x}" in output


@pytest.mark.parametrize("arguments", [
    ["scan", "--puzzle", "71"],
    ["scan", "--limit", "1"],
    ["scan", "--puzzle", "71", "--start", "1", "--limit", "1"],
    ["scan", "--puzzle", "71", "--address", PUZZLE_1.address, "--limit", "1"],
    ["scan", "--puzzle", "0", "--limit", "1"],
    ["scan", "--puzzle", "161", "--limit", "1"],
    ["scan", "--puzzle", "abc", "--limit", "1"],
    ["scan", "--puzzle", "2", "--start", "xyz", "--limit", "1"],
    ["scan", "--puzzle", "2", "--start", "3", "--end", "2", "--limit", "1"],
    ["scan", "--puzzle", "2", "--end", "4", "--limit", "1"],
    ["benchmark", "--seconds", "1"],
    ["benchmark", "--puzzle", "71", "--seconds", "nan"],
    ["benchmark", "--puzzle", "160", "--end", f"{2**160:x}"],
])
def test_cli_rejects_invalid_arguments(arguments):
    with pytest.raises(SystemExit) as exc:
        main(arguments)
    assert exc.value.code == 2


def test_benchmark_cli(capsys):
    assert main(["benchmark", "--puzzle", "140", "--seconds", "0.001"]) == 0
    output = capsys.readouterr().out
    assert "Full-range estimate:" in output
    assert "One-day coverage:" in output


def test_benchmark_estimates_selected_interval(capsys):
    lower = 2**70
    assert main(["benchmark", "--puzzle", "71", "--start", hex(lower),
                 "--end", hex(lower + 1)]) == 0
    output = capsys.readouterr().out
    assert "Status: exhausted" in output
    assert "Interval: 2 candidates" in output
