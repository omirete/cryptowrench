from .ethereum import address_ethereum
from .bitcoin import BitcoinAddressHandler

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
