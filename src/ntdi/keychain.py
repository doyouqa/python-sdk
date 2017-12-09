
"""
A Keypair is used to sign and verify signatures

Keys should be kept in a secure storage enclave.
"""
from __future__ import division

import base64
import struct
import logging

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, \
    load_pem_public_key, load_der_private_key, load_der_public_key

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization \
    import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature,
)

from cryptography.utils import int_to_bytes, int_from_bytes

from . import symcrypt, utils, exceptions, file_adapter

KEYSIZE = 256
KEYSIZE_BYTES = (KEYSIZE // 8)

logger = logging.getLogger(__name__)

_BACKEND = default_backend()


class Credentials(object):
    """
    Container for User/Server/Device Encryption Key, Signing Key, Identity


    :ivar identity: UUID of the identity.
    :ivar keypair: :class:`~ntdi.keychain.BaseKeypair` instance.
    """
    def __init__(self, identity, keypair):
        """

        :param identity: uuid of the entity
        :param keypair: :py:class:`~ntdi.keychain.BaseKeypair` instance
        """
        self.id = identity

        if not isinstance(keypair, BaseKeypair):
            raise ValueError('keypair must be a ntdi.keychain.BaseKeypair instance')

        self.keypair = keypair


class FleetCredentials(Credentials):
    def __init__(self, fleet_id, keypair, encryption_key):
        """
        Adds an encryption key

        :param fleet_id: Fleet UUID
        :param keypair: :py:class:`~ntdi.keychain.BaseKeypair`
        :param encryption_key: AES key used to encrypt messages
        """
        super(FleetCredentials, self).__init__(fleet_id, keypair)
        self._encryption_key = encryption_key

    def encrypt(self, plain_text):
        """
        Encrypt plain text with the Fleet encryption key.

        :param plain_text: String or bytes to encrypt with Fleet encryption key.
        :returns: Dictionary with cipher text and encryption params.
        """
        return symcrypt.aes_encrypt(plain_text, self._encryption_key)

    def decrypt(self, cipher_text):
        """
        Decrypt cipher text that was encrypted with the Fleet encryption key

        :param cipher_text: Encrypted dict as returned by :py:encrypt:
        :returns: plain text
        :return_type: bytes
        """
        return symcrypt.aes_decrypt(cipher_text, self._encryption_key)


class BaseKeypair(object):
    """
    Generic :py:class:`~ntdi.keychain.Keypair` functionality.

    Callers can subclass this to mimic or proxy
    :py:class:`~ntdi.keychain.Keypair`\s
    """
    PUBLIC_KEY_USE_SIGNING = 'sig'
    PUBLIC_KEY_USE_ENCRYPTION = 'enc'

    def __init__(self, identity=None, use=PUBLIC_KEY_USE_SIGNING, **kwargs):
        self.identity = identity
        self.use = use

    @property
    def is_private(self):
        raise NotImplementedError

    @property
    def public_key_der(self):
        raise NotImplementedError

    @property
    def public_key_pem(self):
        template = '\n'.join([
            '-----BEGIN PUBLIC KEY-----',
            '{}',
            '-----END PUBLIC KEY-----',
            '',
        ])
        b64_key = base64.b64encode(self.public_key_der).decode('utf-8')

        pieces = [b64_key[i:i+64] for i in range(0, len(b64_key), 64)]

        return template.format('\n'.join(pieces)).encode('utf-8')

    @property
    def private_key_der(self):
        raise NotImplementedError

    @property
    def private_key_pem(self):
        raise NotImplementedError

    @property
    def jwk(self):
        raise NotImplementedError

    @property
    def jwk_private(self):
        raise NotImplementedError

    @property
    def jwk_public(self):
        raise NotImplementedError

    def verify(self, payload, r, s):
        raise NotImplementedError

    def sign(self, payload):
        raise NotImplementedError

    def raw_ecdh(self, peer_keypair):
        raise NotImplementedError

    def save(self, *args, **kwargs):
        """
        Save a key.
        Should be overridden and saved to secure storage

        :param args:
        :param kwargs:
        :return: Bool Success
        """
        raise NotImplementedError

    def ecdh(self, peer_keypair, algorithm='A256GCM', party_u_info=None, party_v_info=None):
        """
        Derive a shared symmetric key for encrypting data to a given recipient

        :param peer_keypair: Public key of the recipient
        :type peer_keypair: :py:class:`~ntdi.keychain.Keypair`
        :param algorithm: The algorithm associated with the operation (defaults to 'A256GCM')
        :type algorithm: str
        :param party_u_info: shared identifying information about the sender (optional)
        :type party_u_info: str or bytes
        :param party_v_info: shared identifying information about the recipient (optional)
        :type party_v_info: str or bytes
        :returns: a 256-bit encryption key, to be passed to ecdh_derive
        :return_type: bytes
        :raises InvalidFormatError: if self is not a private key
        """
        if not self.is_private:
            raise exceptions.InvalidFormatError
        raw_key = self.raw_ecdh(peer_keypair)
        otherinfo = self.calc_ecdh_otherinfo(algorithm, party_u_info, party_v_info)
        ret = self.ecdh_derive(raw_key, otherinfo)

        del raw_key

        return ret

    def calc_ecdh_otherinfo(self, algorithm, party_u_info, party_v_info):
        """
        Broken out so testing can override to inject CAVP vector data
        """
        return (
            _len_bytes(algorithm) +
            _len_bytes(party_u_info) +
            _len_bytes(party_v_info) +
            utils.to_bytes(struct.pack(">I", 256))
        )

    def ecdh_derive(self, raw_key, otherinfo):
        """
        Applies Standard KDF for ECDH, but some implementations may override,
        say to implement in hardware.
        """
        ckdf = ConcatKDFHash(
            algorithm=hashes.SHA256(),
            length=32,
            otherinfo=otherinfo,
            backend=_BACKEND,
        )
        return ckdf.derive(raw_key)


class Keypair(BaseKeypair):
    def __init__(self, *args, **kwargs):
        """
        :param kwargs: may include an `EllipticCurvePrivateKey` in 'ec_private_key'
        """
        super(Keypair, self).__init__(*args, **kwargs)

        self._private_key = None
        self._cached_public_key = None

        if kwargs.get('ec_private_key') and \
                isinstance(kwargs['ec_private_key'], ec.EllipticCurvePrivateKey):
            self._load_ec_private_key(kwargs['ec_private_key'])

    def _load_ec_private_key(self, ec_private_key):
        self._private_key = ec_private_key

    @property
    def _public_key(self):
        """
        If the private key is defined, generate the public key

        :return:
        """
        if not self._cached_public_key:
            self._cached_public_key = self._private_key.public_key()
        return self._cached_public_key

    @property
    def is_private(self):
        return self._private_key is not None

    @property
    def public_key_der(self):
        """
        DER-formatted public key

        :return: Public Key in DER format
        """
        return self._public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    @property
    def public_key_pem(self):
        """
        PEM-formatted public key

        :return: Public Key in PEM format
        """
        return self._public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    @property
    def private_key_der(self):
        """
        DER-formatted private key

        :return: Private Key in DER format
        """
        if not self.is_private:
            raise exceptions.InvalidFormatError
        private_der = self._private_key.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
        )

        return private_der

    @property
    def private_key_pem(self):
        """
        PEM-formatted private key

        :return: Private Key in PEM format
        """
        if not self.is_private:
            raise exceptions.InvalidFormatError
        return self._private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    @property
    def jwk(self):
        """
        The keys as a JSON Web Key (JWK)
        Private key will be included only if present

        :return: TDI-standard JWK
        """
        return self.get_jwk(True)

    @property
    def jwk_public(self):
        """
        The public key as a JSON Web Key (JWK)

        :return: TDI-standard JWK
        """
        return self.get_jwk(False)

    @property
    def jwk_private(self):
        """
        The private key as a JSON Web Key (JWK)

        :return: TDI-standard JWK
        :raises InvalidFormatError: if not a private key
        """
        if not self.is_private:
            raise exceptions.InvalidFormatError
        return self.get_jwk(True)

    @classmethod
    def from_private_pem(cls, key_bytes=None, path=None):
        """
        Create a :class:`~ntdi.keychain.Keypair` from a PEM-formatted private ECDSA key

        :return: :class:`~ntdi.keychain.Keypair` instance
        """
        if key_bytes:
            ec_private_key = load_pem_private_key(utils.to_bytes(key_bytes), None, _BACKEND)
            return cls(ec_private_key=ec_private_key)

        if file_adapter.file_exists(path):
            with file_adapter.read_file(path) as pem_data:
                ec_private_key = load_pem_private_key(pem_data, None, _BACKEND)
                return cls(ec_private_key=ec_private_key)

    @classmethod
    def from_public_pem(cls, key_bytes=None, path=None):
        """
        Create a :class:`~ntdi.keychain.Keypair` from a PEM-formatted public ECDSA key

        Note that this keypair will not be capable of signing, only verifying.

        :return: :class:`~ntdi.keychain.Keypair` instance
        """
        ret = None
        public_bytes = None

        if key_bytes:
            public_bytes = utils.to_bytes(key_bytes)
        elif file_adapter.file_exists(path):
            with file_adapter.read_file(path) as pem_data:
                public_bytes = pem_data

        if public_bytes:
            ret = cls()
            ret._cached_public_key = load_pem_public_key(public_bytes, _BACKEND)

        return ret

    @classmethod
    def from_private_der(cls, der_key):
        """
        Read a der_key, convert it a private key

        :param der_key: der formatted key
        :return:
        """
        ec_private_key = load_der_private_key(der_key, None, _BACKEND)
        return cls(ec_private_key=ec_private_key)

    @classmethod
    def from_public_der(cls, public_key):
        """
        Given a DER-format public key, convert it into a token to
        validate signatures

        :param public_key: der formatted key
        :return: :class:`~ntdi.keychain.Keypair` instance
        """
        pub = load_der_public_key(public_key, _BACKEND)

        new_token = cls()
        new_token._cached_public_key = pub

        return new_token

    @classmethod
    def from_jwk(cls, jwk):
        """
        Create a :py:class:`~ntdi.keychain.Keypair` from a JWK

        :param jwk: TDI-standard JWK
        :return: :py:class:`~ntdi.keychain.Keypair` instance
        :raises InvalidFormatError: if not a valid JWK
        """
        if jwk['kty'] != 'EC' or jwk['crv'] != 'P-256':
            raise exceptions.InvalidFormatError

        public_numbers = ec.EllipticCurvePublicNumbers(
            x=int_from_bytes(utils.base64url_decode(jwk['x']), 'big'),
            y=int_from_bytes(utils.base64url_decode(jwk['y']), 'big'),
            curve=ec.SECP256R1(),
        )

        ret = cls()
        ret._cached_public_key = public_numbers.public_key(_BACKEND)

        if 'd' in jwk:
            private_numbers = ec.EllipticCurvePrivateNumbers(
                private_value=int_from_bytes(utils.base64url_decode(jwk['d']), 'big'),
                public_numbers=public_numbers,
            )
            ret._private_key = private_numbers.private_key(_BACKEND)

        if 'kid' in jwk:
            ret.identity = jwk['kid']

        return ret

    def get_jwk(self, include_private):
        public_numbers = self._public_key.public_numbers()
        ret = {
          "kty": "EC",
          "alg": "ES256",
          "crv": "P-256",
          "use": self.use,
          "x": utils.to_string(utils.base64url_encode(int_to_bytes(public_numbers.x))),
          "y": utils.to_string(utils.base64url_encode(int_to_bytes(public_numbers.y))),
        }

        if self.identity:
            ret['kid'] = str(self.identity)

        if self.is_private and include_private:
            private_numbers = self._private_key.private_numbers()
            d = int_to_bytes(private_numbers.private_value)
            ret['d'] = utils.to_string(utils.base64url_encode(d))

        return ret

    def verify(self, payload, r, s):
        """
        Verify that the associated private key signed the data

        :type payload: String
        :param payload: message that was signed and needs verified
        :param r: R part of signature that can verify the sender\'s identity and payload
        :type r: int
        :param s: S part of signature
        :type s: int
        :raises InvalidSignatureError: if validation fails for any reason
        :return:
        """
        try:
            signature = encode_dss_signature(r, s)
            self._public_key.verify(signature, utils.to_bytes(payload), ec.ECDSA(hashes.SHA256()))
        except:  # noqa: E722
            logger.debug('invalid signature', exc_info=True)
            raise exceptions.InvalidSignatureError
        return True

    def sign(self, payload):
        """
        Sign a payload

        :param payload: String (usually jwt payload)
        :return: r, s signature values
        :return_type: tuple of 2 ints
        """
        if not self.is_private:
            raise exceptions.InvalidFormatError

        dss_sig = self._private_key.sign(utils.to_bytes(payload), ec.ECDSA(hashes.SHA256()))
        return decode_dss_signature(dss_sig)

    def raw_ecdh(self, peer_keypair):
        return self._private_key.exchange(ec.ECDH(), peer_keypair._public_key)


def create_private_keypair(output=None):
    """
    Create a private key and save it to a secure location

    :param output: Path to save the private key
    :return: ntdi.keychain.Keypair
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), _BACKEND)
    private_bytes = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    # Save the private key bytes to a secure file
    if output and file_adapter.file_directory_exists(output):
        file_adapter.write_file(output, private_bytes)

    return Keypair.from_private_pem(key_bytes=private_bytes)


def _len_bytes(data):
    if not data:
        return utils.to_bytes('')
    return utils.to_bytes(struct.pack(">I", len(data))) + utils.to_bytes(data)
