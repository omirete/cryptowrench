from .ethereum import address_ethereum
from .bitcoin import BitcoinAddressHandler
from .ripple import address_ripple_classic

class AddressHandler():
    def __init__(self, public_key: bytes, uncompressed_public_key: bytes, main_net: bool) -> None:
        self._public_key = public_key
        self._uncompressed_public_key = uncompressed_public_key
        self._main_net = main_net

    @property
    def ethereum(self):
        return address_ethereum(
            uncompressed_public_key=self._uncompressed_public_key
        )
    
    @property
    def bitcoin(self):
        return BitcoinAddressHandler(
            public_key=self._public_key,
            uncompressed_public_key=self._uncompressed_public_key,
            main_net=self._main_net
        )

    @property
    def ripple(self):
        # Default derivation path: "m/44'/144'/0'/0/0"
        return address_ripple_classic(
            public_key=self._public_key
            # public_key=self._uncompressed_public_key
        )
