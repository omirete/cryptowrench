"""Explicit constructor examples using the entropy source."""

import pytest

from cryptowrench.wallet import Wallet

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("strength", [128, 256])
def test_entropy_creation_rejects_strength(entropy, strength):
    """Entropy creation rejects the strength option."""
    with pytest.raises(ValueError) as error:
        Wallet(entropy=entropy, strength=strength)
    assert "strength" in str(error.value)
    assert "entropy" in str(error.value)


@pytest.mark.parametrize("language", ["english", "japanese"])
def test_entropy_creation_accepts_language(entropy, language):
    """Entropy creation accepts the language option."""
    Wallet(entropy=entropy, language=language)


@pytest.mark.parametrize("passphrase", ["", "secret"])
def test_entropy_creation_accepts_passphrase(entropy, passphrase):
    """Entropy creation accepts the passphrase option."""
    Wallet(entropy=entropy, passphrase=passphrase)


@pytest.mark.parametrize("main_net", [True, False])
def test_entropy_creation_accepts_main_net(entropy, main_net):
    """Entropy creation accepts the main_net option."""
    Wallet(entropy=entropy, main_net=main_net)


def test_entropy_creation_rejects_zero_bytes_chain_code(entropy):
    """A chain code is accepted only alongside a private key."""
    chain_code = bytes(32)
    with pytest.raises(ValueError) as error:
        Wallet(entropy=entropy, chain_code=chain_code)
    assert "chain_code" in str(error.value)
    assert "entropy" in str(error.value)


def test_entropy_creation_rejects_root_wallet_chain_code(entropy, root_wallet):
    """A chain code is accepted only alongside a private key."""
    chain_code = root_wallet.chain_code
    with pytest.raises(ValueError) as error:
        Wallet(entropy=entropy, chain_code=chain_code)
    assert "chain_code" in str(error.value)
    assert "entropy" in str(error.value)


def test_entropy_creation_none_options_match_omitted_options(
    entropy, deterministic_randomness
):
    """Explicit None options must behave exactly like omitted options."""
    omitted_options_wallet = Wallet(entropy=entropy)
    none_options_wallet = Wallet(
        entropy=entropy,
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


def test_entropy_creation_language_changes_words(entropy, deterministic_randomness):
    """The same entropy gives different words when the selected language changes."""
    default_wallet = Wallet()
    japanese_wallet = Wallet(entropy=entropy, language="japanese")
    assert japanese_wallet.words != default_wallet.words


def test_entropy_creation_passphrase_changes_seed(entropy, deterministic_randomness):
    """A passphrase changes the derived seed and is retained for recovery."""
    default_wallet = Wallet()
    protected_wallet = Wallet(entropy=entropy, passphrase="secret")
    assert protected_wallet.seed != default_wallet.seed
    assert protected_wallet.passphrase == "secret"


def test_entropy_creation_network_changes_address(entropy, deterministic_randomness):
    """Network selection changes the Bitcoin address while preserving the private key."""
    mainnet_wallet = Wallet(entropy=entropy, main_net=True)
    testnet_wallet = Wallet(entropy=entropy, main_net=False)
    assert mainnet_wallet.private_key == testnet_wallet.private_key
    assert mainnet_wallet.address.bitcoin.P2PKH != testnet_wallet.address.bitcoin.P2PKH
