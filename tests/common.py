
import os
import codecs

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.utils import int_from_bytes

import oneid

BACKEND = default_backend()

_base_dir = os.path.dirname(os.path.dirname(__file__))

VALIDATION_DATA_PATH = os.path.join(_base_dir, 'sdk_validation_data')
VALIDATION_CURATED_FILES_PATH = os.path.join(VALIDATION_DATA_PATH, 'test_vectors', 'curated')


def hex2bytes(hex):
    return bytes(bytearray.fromhex(hex))


def bytes2hex(bytes):
    return codecs.getencoder('hex')(bytes)[0].decode('utf-8')


def keypair_from_nist_hex(x, y, d=None, otherinfo=None):
    ret = _TestKeypair() if otherinfo else oneid.keychain.Keypair()
    ret._otherinfo = otherinfo

    public_numbers = ec.EllipticCurvePublicNumbers(
        x=int_from_bytes(hex2bytes(x), 'big'),
        y=int_from_bytes(hex2bytes(y), 'big'),
        curve=ec.SECP256R1(),
    )
    ret._public_key = public_numbers.public_key(BACKEND)

    if d:
        private_numbers = ec.EllipticCurvePrivateNumbers(
            private_value=int_from_bytes(hex2bytes(d), 'big'),
            public_numbers=public_numbers,
        )
        ret._private_key = private_numbers.private_key(BACKEND)

    return ret


class _TestKeypair(oneid.keychain.Keypair):
    def _calc_otherinfo(self, algorithm, party_u_info, party_v_info):
        return self._otherinfo
