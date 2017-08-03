
"""
A Keypair is used to sign and verify signatures

Keys should be kept in a secure storage enclave.
"""
from __future__ import division

import struct
import logging

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, \
    load_pem_public_key, load_der_private_key, load_der_public_key

from cryptography.hazmat.primitives.asymmetric.utils \
    import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization \
    import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
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
    :ivar keypair: :class:`~oneid.keychain.BaseKeypair` instance.
    """
    def __init__(self, identity, keypair):
        """

        :param identity: uuid of the entity
        :param keypair: :py:class:`~oneid.keychain.BaseKeypair` instance
        """
        self.id = identity

        if not isinstance(keypair, BaseKeypair):
            raise ValueError('keypair must be a oneid.keychain.BaseKeypair instance')

        self.keypair = keypair


class ProjectCredentials(Credentials):
    def __init__(self, project_id, keypair, encryption_key):
        """
        Adds an encryption key

        :param project_id: oneID project UUID
        :param keypair: :py:class:`~oneid.keychain.BaseKeypair`
        :param encryption_key: AES key used to encrypt messages
        """
        super(ProjectCredentials, self).__init__(project_id, keypair)
        self._encryption_key = encryption_key

    def encrypt(self, plain_text):
        """
        Encrypt plain text with the project encryption key.

        :param plain_text: String or bytes to encrypt with project encryption key.
        :returns: Dictionary with cipher text and encryption params.
        """
        return symcrypt.aes_encrypt(plain_text, self._encryption_key)

    def decrypt(self, cipher_text):
        """
        Decrypt cipher text that was encrypted with the project encryption key

        :param cipher_text: Encrypted dict as returned by :py:encrypt:
        :returns: plain text
        :return_type: bytes
        """
        return symcrypt.aes_decrypt(cipher_text, self._encryption_key)


class BaseKeypair(object):
    """
    Generic :py:class:`~oneid.keychain.Keypair` functionality.

    Callers can subclass this to mimic or proxy
    :py:class:`~oneid.keychain.Keypair`\s
    """
    def __init__(self, *args, **kwargs):
        self.identity = kwargs.get('identity')

    @property
    def public_key_der(self):
        raise NotImplementedError

    @property
    def public_key_pem(self):
        raise NotImplementedError

    @property
    def secret_as_der(self):
        raise NotImplementedError

    @property
    def secret_as_pem(self):
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

    def verify(self, payload, signature):
        raise NotImplementedError

    def sign(self, payload):
        raise NotImplementedError

    def ecdh(self, peer_keypair, algorithm='A256GCM', party_u_info=None, party_v_info=None):
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

    def _calc_otherinfo(self, algorithm, party_u_info, party_v_info):
        """
        Broken out so testing can override to inject CAVP vector data
        """
        return (
            _len_bytes(algorithm) +
            _len_bytes(party_u_info) +
            _len_bytes(party_v_info) +
            utils.to_bytes(struct.pack(">I", 256))
        )

    def _derive_ecdh(self, raw_key, otherinfo):
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
        :param kwargs: Pass secret key bytes
        """
        super(Keypair, self).__init__(*args, **kwargs)

        self._private_key = None
        self._public_key = None

        if kwargs.get('secret_bytes') and \
                isinstance(kwargs['secret_bytes'], ec.EllipticCurvePrivateKey):
            self._load_secret_bytes(kwargs['secret_bytes'])

    def _load_secret_bytes(self, secret_bytes):
        self._private_key = secret_bytes

    @property
    def secret_as_der(self):
        """
        Write out the private key as a DER format

        :return: DER encoded private key
        """
        secret_der = self._private_key.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
        )

        return secret_der

    @property
    def secret_as_pem(self):
        """
        Write out the private key as a PEM format

        :return: Pem Encoded private key
        """
        return self._private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    @classmethod
    def from_secret_pem(cls, key_bytes=None, path=None):
        """
        Create a :class:`~oneid.keychain.Keypair` from a PEM-formatted private ECDSA key

        :return: :class:`~oneid.keychain.Keypair` instance
        """
        if key_bytes:
            secret_bytes = load_pem_private_key(utils.to_bytes(key_bytes), None, _BACKEND)
            return cls(secret_bytes=secret_bytes)

        if file_adapter.file_exists(path):
            with file_adapter.read_file(path) as pem_data:
                secret_bytes = load_pem_private_key(pem_data, None, _BACKEND)
                return cls(secret_bytes=secret_bytes)

    @classmethod
    def from_public_pem(cls, key_bytes=None, path=None):
        """
        Create a :class:`~oneid.keychain.Keypair` from a PEM-formatted public ECDSA key

        Note that this keypair will not be capable of signing, only verifying.

        :return: :class:`~oneid.keychain.Keypair` instance
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
            ret._public_key = load_pem_public_key(public_bytes, _BACKEND)

        return ret

    @classmethod
    def from_secret_der(cls, der_key):
        """
        Read a der_key, convert it a private key

        :param path: der formatted key
        :return:
        """
        secret_bytes = load_der_private_key(der_key, None, _BACKEND)
        return cls(secret_bytes=secret_bytes)

    @classmethod
    def from_public_der(cls, public_key):
        """
        Given a DER-format public key, convert it into a token to
        validate signatures

        :param public_key: der formatted key
        :return: :class:`~oneid.keychain.Keypair` instance
        """
        pub = load_der_public_key(public_key, _BACKEND)

        new_token = cls()
        new_token._public_key = pub

        return new_token

    @classmethod
    def from_jwk(cls, jwk):
        """
        Create a :py:class:`~oneid.keychain.Keypair` from a JWK

        :param jwk: oneID-standard JWK
        :return: :py:class:`~oneid.keychain.Keypair` instance
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
        ret._public_key = public_numbers.public_key(_BACKEND)

        if 'd' in jwk:
            private_numbers = ec.EllipticCurvePrivateNumbers(
                private_value=int_from_bytes(utils.base64url_decode(jwk['d']), 'big'),
                public_numbers=public_numbers,
            )
            ret._private_key = private_numbers.private_key(_BACKEND)

        if 'kid' in jwk:
            ret.identity = jwk['kid']

        return ret

    @property
    def jwk(self):
        """
        The keys as a JSON Web Key (JWK)
        Private key will be included only if present

        :return: oneID-standard JWK
        """
        return self.get_jwk(True)

    @property
    def jwk_public(self):
        """
        The public key as a JSON Web Key (JWK)

        :return: oneID-standard JWK
        """
        return self.get_jwk(False)

    @property
    def jwk_private(self):
        """
        The private key as a JSON Web Key (JWK)

        :return: oneID-standard JWK
        :raises InvalidFormatError: if not a private key
        """
        if not self._private_key:
            raise exceptions.InvalidFormatError
        return self.get_jwk(True)

    def get_jwk(self, include_secret):
        public_numbers = self.public_key.public_numbers()
        ret = {
          "kty": "EC",
          "crv": "P-256",
          "x": utils.to_string(utils.base64url_encode(int_to_bytes(public_numbers.x))),
          "y": utils.to_string(utils.base64url_encode(int_to_bytes(public_numbers.y))),
        }

        if self.identity:
            ret['kid'] = str(self.identity)

        if self._private_key and include_secret:
            private_numbers = self._private_key.private_numbers()
            d = int_to_bytes(private_numbers.private_value)
            ret['d'] = utils.to_string(utils.base64url_encode(d))

        return ret

    def verify(self, payload, signature):
        """
        Verify that the token signed the data

        :type payload: String
        :param payload: message that was signed and needs verified
        :type signature: Base64 URL Safe
        :param signature: Signature that can verify the sender\'s identity and payload
        :return:
        """
        raw_sig = utils.base64url_decode(signature)
        sig_r_bin = raw_sig[:len(raw_sig)//2]
        sig_s_bin = raw_sig[len(raw_sig)//2:]

        sig_r = int_from_bytes(sig_r_bin, 'big')
        sig_s = int_from_bytes(sig_s_bin, 'big')

        sig = encode_dss_signature(sig_r, sig_s)
        self.public_key.verify(sig, utils.to_bytes(payload), ec.ECDSA(hashes.SHA256()))
        return True

    def sign(self, payload):
        """
        Sign a payload

        :param payload: String (usually jwt payload)
        :return: URL safe base64 signature
        """
        signature = self._private_key.sign(utils.to_bytes(payload), ec.ECDSA(hashes.SHA256()))

        r, s = decode_dss_signature(signature)

        br = int_to_bytes(r, KEYSIZE_BYTES)
        bs = int_to_bytes(s, KEYSIZE_BYTES)
        str_sig = br + bs
        b64_signature = utils.base64url_encode(str_sig)
        return b64_signature

    def ecdh(self, peer_keypair, algorithm='A256GCM', party_u_info=None, party_v_info=None):
        """
        Derive a shared symmetric key for encrypting data to a given recipient

        :param peer_keypair: Public key of the recipient
        :type peer_keypair: :py:class:`~oneid.keychain.Keypair`
        :param algorithm: The algorithm associated with the operation (defaults to 'A256GCM')
        :type algorithm: str
        :param party_u_info: shared identifying information about the sender (optional)
        :type party_u_info: str or bytes
        :param party_v_info: shared identifying information about the recipient (optional)
        :type party_v_info: str or bytes
        :returns: a 256-bit encryption key
        :return_type: bytes
        :raises InvalidFormatError: if self is not a private key
        """
        if not self._private_key:
            raise exceptions.InvalidFormatError
        raw_key = self._raw_ecdh(peer_keypair)
        otherinfo = self._calc_otherinfo(algorithm, party_u_info, party_v_info)
        ret = self._derive_ecdh(raw_key, otherinfo)

        del raw_key

        return ret

    @property
    def public_key(self):
        """
        If the private key is defined, generate the public key

        :return:
        """
        if self._public_key:
            return self._public_key
        elif self._private_key:
            return self._private_key.public_key()

    @property
    def public_key_der(self):
        """
        DER formatted public key

        :return: Public Key in DER format
        """
        return self.public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    @property
    def public_key_pem(self):
        """
        PEM formatted public key

        :return: Public Key in PEM format
        """
        return self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    def _raw_ecdh(self, peer_keypair):
        return self._private_key.exchange(ec.ECDH(), peer_keypair.public_key)


def _len_bytes(data):
    if not data:
        return utils.to_bytes('')
    return utils.to_bytes(struct.pack(">I", len(data))) + utils.to_bytes(data)
