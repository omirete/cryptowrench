"""Explicit constructor examples using the random source."""

import pytest

from cryptowrench.wallet import Wallet

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("strength", [128, 256])
def test_random_creation_accepts_strength(strength):
    """Random creation accepts the strength option."""
    Wallet(strength=strength)


@pytest.mark.parametrize("language", ["english", "japanese"])
def test_random_creation_accepts_language(language):
    """Random creation accepts the language option."""
    Wallet(language=language)


@pytest.mark.parametrize("passphrase", ["", "secret"])
def test_random_creation_accepts_passphrase(passphrase):
    """Random creation accepts the passphrase option."""
    Wallet(passphrase=passphrase)


@pytest.mark.parametrize("main_net", [True, False])
def test_random_creation_accepts_main_net(main_net):
    """Random creation accepts the main_net option."""
    Wallet(main_net=main_net)


def test_random_creation_rejects_zero_bytes_chain_code():
    """A chain code is accepted only alongside a private key."""
    chain_code = bytes(32)
    with pytest.raises(ValueError) as error:
        Wallet(chain_code=chain_code)
    assert "chain_code" in str(error.value)
    assert "random" in str(error.value)


def test_random_creation_rejects_root_wallet_chain_code(root_wallet):
    """A chain code is accepted only alongside a private key."""
    chain_code = root_wallet.chain_code
    with pytest.raises(ValueError) as error:
        Wallet(chain_code=chain_code)
    assert "chain_code" in str(error.value)
    assert "random" in str(error.value)


def test_random_creation_none_options_match_omitted_options(deterministic_randomness):
    """Explicit None options must behave exactly like omitted options."""
    omitted_options_wallet = Wallet()
    none_options_wallet = Wallet(
        entropy=None,
        mnemonic=None,
        seed=None,
        private_key=None,
        wif=None,
        chain_code=None,
        strength=None,
        derivation_path=None,
        fingerprint_parent_key=None,
        language=None,
        passphrase=None,
        main_net=None,
    )
    assert none_options_wallet.__dict__ == omitted_options_wallet.__dict__


def test_random_creation_language_changes_words(deterministic_randomness):
    """The same entropy gives different words when the selected language changes."""
    default_wallet = Wallet()
    japanese_wallet = Wallet(language="japanese")
    assert japanese_wallet.words != default_wallet.words


def test_random_creation_passphrase_changes_seed(deterministic_randomness):
    """A passphrase changes the derived seed and is retained for recovery."""
    default_wallet = Wallet()
    protected_wallet = Wallet(passphrase="secret")
    assert protected_wallet.seed != default_wallet.seed
    assert protected_wallet.passphrase == "secret"


def test_random_creation_network_changes_address(deterministic_randomness):
    """Network selection changes the Bitcoin address while preserving the private key."""
    mainnet_wallet = Wallet(main_net=True)
    testnet_wallet = Wallet(main_net=False)
    assert mainnet_wallet.private_key == testnet_wallet.private_key
    assert mainnet_wallet.address.bitcoin.P2PKH != testnet_wallet.address.bitcoin.P2PKH


def test_random_creation_defaults(root_wallet, deterministic_randomness):
    """Default random creation uses the known entropy, an empty passphrase, and mainnet."""
    default_wallet = Wallet()
    assert default_wallet.seed == root_wallet.seed
    assert default_wallet.passphrase == ""
    assert default_wallet.main_net


def test_random_creation_with_256_bits_has_24_words():
    """256-bit random creation produces 24 mnemonic words."""
    stronger_wallet = Wallet(strength=256)
    assert len(stronger_wallet.words.split()) == 24


def test_random_default_strength_has_12_words():
    """Random creation defaults to a 12-word mnemonic."""
    default_wallet = Wallet()
    assert len(default_wallet.words.split()) == 12


def test_random_creation_rejects_strength_one():
    """A strength of one bit is rejected as unsupported."""
    with pytest.raises(ValueError):
        Wallet(strength=1)
