# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import re
import base64
import six
import logging

from ..message import Message
from .. import exceptions

from .base import BaseMessage

B64_URLSAFE_RE = '[0-9a-zA-Z-_]+'
COMPACT_JWS_RE = r'^{b64}\.{b64}\.{b64}$'.format(b64=B64_URLSAFE_RE)

logger = logging.getLogger(__name__)


class JOSEMessage(BaseMessage):
    """
    Renders messages in JWS (compact or JSON) and JWE formats
    """

    def __init__(self, config, platform, payload=None, kid=None):
        super(JOSEMessage, self).__init__(config, platform, payload, kid)
        self._config = config
        self._platform = platform

        self._claims = {}
        self._signatures = []

    # IMessage methods

    def from_representation(self, msg_repr, **kwargs):
        ret = Message(self._config, self._platform)

        if not msg_repr:
            raise ValueError('no representation given')

        if isinstance(msg_repr, six.string_types):

            if self._is_compact_jws(msg_repr):
                msg_repr = self._uncompact_jws(msg_repr)
            else:
                try:
                    msg_repr = self._platform.json.decode(msg_repr)
                except exceptions.NotJSONException:
                    self._payload = msg_repr
                    return

        if not isinstance(msg_repr, dict):
            self._payload = msg_repr
            return

        if self._is_jwe(msg_repr):
            msg_repr = self._jose.decrypt_jwe(msg_repr)

        if not self._is_jws(msg_repr):
            self._payload = msg_repr
        else:
            self._frozen_payload = msg_repr['payload']
            self._claims = self._jose.decode_claims(msg_repr['payload'])
            self._kid = self._claims.get('iss', self._kid)
            self._payload = self._claims.get('payload')
            self._signatures = [{
                self._jose.decode_header(sig['protected']),
                self._jose.decode_signature(sig['signature']),
            } for sig in msg_repr['signatures']]

        return ret

    def to_representation(self, msg, encrypt_to_kids=None, compact=False, **kwargs):
        raise NotImplementedError

    # BaseMessage methods

    # "private" methods

    def _is_compact_jws(self, jws):
        """
        Determine if a given message is a compact JWS (or JWT) or not.
        Does not necessarily mean that it is valid or authentic.

        :param jws: thing to inspect
        :type jws: str or bytes
        :returns: True if the message is a compact JWS, False otherwise
        :rtype: bool
        """
        if isinstance(jws, six.binary_type):
            jws = jws.decode('utf-8')

        return (isinstance(jws, six.string_types) and bool(re.match(COMPACT_JWS_RE, jws)))

    def _is_jws(self, jws):
        """
        Determine if a given message is a JWS or not (compact or otherwise).
        Does not necessarily mean that it is valid or authentic.

        :param jws: thing to inspect
        :type jws: str or dict

        :returns: True if the message is a JWS, False otherwise
        :rtype: bool
        """
        REQUIRED_FIELDS = ['payload', 'signatures']

        if isinstance(jws, (six.string_types, six.binary_type)):
            if self._is_compact_jws(jws):
                return True

            try:
                jws = self._platform.json.decode(jws)
            except exceptions.NotJSONException:
                return False

        if not isinstance(jws, dict):
            return False

        if not all([k in jws for k in REQUIRED_FIELDS]):
            return False

        return True

    def _is_jwe(self, jwe):
        """
        Determine if a given message is a JWE or not.
        Does not necessarily mean that it is valid or authentic.

        :param msg: message to inspect
        :type msg: str or dict

        :returns: True if the message is a JWE, False otherwise
        :rtype: bool
        """
        REQUIRED_FIELDS = ['iv', 'ciphertext', 'tag', 'recipients']

        if isinstance(jwe, (six.string_types, six.binary_type)):
            try:
                jwe = self._platform.json.decode(jwe)
            except exceptions.NotJSONException:
                return False

        if not isinstance(jwe, dict):
            return False

        if not all([k in jwe for k in REQUIRED_FIELDS]):
            return False

        return True

    def _compact_jws(self, frozen_payload, signature):
        """
        Build a compact JWS

        :param frozen_payload: encoded payload
        :type frozen_payload: base64jose str
        :param signature: single signature datum
        :type signature: dict
        :return: Compact JWS
        :return_type: str
        """

        sig = self.encode_signature(signature)

        return '.'.join([signature['frozen_header'], frozen_payload, sig])

    def _jws(self, frozen_payload, signatures, compact=False):
        """
        Build a JWS (compact or JSON)

        :param frozen_payload: encoded payload
        :type frozen_payload: base64jose str
        :param signatures: list of signatures
        :type signatures: iterable of dict
        :return: JWS
        :return_type: str
        """

        if not signatures:
            raise exceptions.MissingSignatures

        if isinstance(signatures, dict):
            signatures = [signatures]

        elif compact and len(signatures) > 1:
            raise exceptions.MultipleSignaturesNotSupported

        ret = {
            'payload': frozen_payload,
            'signatures': [self.encode_signature(signature) for signature in signatures]
        }

        if compact:
            sig_rec = ret['signatures'][0]
            protected = sig_rec['protected']
            return '.'.join([protected, frozen_payload, sig_rec['signature']])

        return ret

    def _jwe(self, issuer_kid, nonce, frozen_payload, recipient_kids):
        """
        Create a JWE with General JWE JSON Serialization syntax

        :param frozen_payload: encoded payload
        :type frozen_payload: base64jose str
        :param signatures: single signature datum
        :type signatures: dict

        :param recipient_keypairs: :py:class:`~ntdi.keychain.Keypair`\s to encrypt the claims for
        :type recipient_keypairs: list or :py:class:`~ntdi.keychain.Keypair`
        :return: JWE
        :return_type: str
        """

        # if isinstance(recipient_kids, six.string_types):
        #     recipient_kids = [recipient_kids]
        #
        # ephemeral = self._platform.crypto.create_private_keypair()
        # common_header = _make_header(frozen_payload, issuer_kid, ephemeral)
        # cek = self._platform.crypto.create_aes_key()
        # encrypted_payload = self._platform.crypto.aes_encrypt(frozen_payload, cek)
        #
        # ret = {
        #     "unprotected": common_header,
        #     "iv": utils.to_string(encrypted_payload['iv']),
        #     "ciphertext": utils.to_string(encrypted_payload['ciphertext']),
        #     "tag": utils.to_string(encrypted_payload['tag']),
        #     "recipients": [
        #         _encrypt_to_recipient(cek, issuer_kid, ephemeral, keypair, nonce)
        #         for keypair in recipient_keypairs
        #     ],
        # }
        #
        # del cek, ephemeral  # this wont wipe the memory, but is the best we can do in Python
        #
        # return self._platform.json.encode(ret)
        return None

    def _uncompact_jws(self, compact_jws):
        return None

    def _encode_header(self, protected):
        return None

    def _decode_header(self, protected):
        return None

    def _encode_claims(self, claims):
        return None

    def _decode_claims(self, claims):
        return None

    def _encode_signature(self, signature):
        if any(key not in signature for key in ['frozen_header', 'r', 's']):
            raise exceptions.MissingSignatureData
        return {
            "protected": signature['frozen_header'],
            "signature": self.base64jose()
        }

    def _decode_signature(self, sig):
        return None

    def _decrypt_jwe(self, jwe):
        return None

    def _base64jose_encode(self, data):
        """
        JOSE specs require base64url-encoded strings with no padding.
        Python base64 package returns bytes with padding. Conversion is done here.

        :param data:
        :type data: string or bytes
        :return: encoded data
        :rtype: str
        """
        if isinstance(data, six.string_types):
            data = data.encode('utf-8')
        return base64.urlsafe_b64encode(data).decode('utf-8').replace('=', '')

    def _base64jose_decode(self, b64str):
        """
        Decode strings encoded using base64jose

        :param data: URL safe base64 message
        :type b64str: string or bytes
        :return: decoded data
        :rtype: bytes
        """
        if isinstance(b64str, six.binary_type):
            b64str = b64str.decode('utf-8')
        pad = len(b64str) % 4
        if pad > 0:
            b64str += b'=' * (4 - pad)

        return base64.urlsafe_b64decode(b64str)
