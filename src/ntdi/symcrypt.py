# -*- coding: utf-8 -*-

"""
Provides useful functions for interacting with the TDI Core API, including creation of
keys, etc.
"""
from __future__ import unicode_literals, division

import os
import base64
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap

from . import utils

logger = logging.getLogger(__name__)


_BACKEND = default_backend()


def create_aes_key():
    """
    Create an AES256 key for symmetric encryption

    :return: Encryption key bytes
    """
    return os.urandom(32)


def aes_encrypt(plaintext, aes_key, legacy_support=True):
    """
    Encrypt using AES-GCM

    :param plaintext: (string or bytes) that you want encrypted
    :param aes_key: symmetric key to encrypt attribute value with
    :return: Dictionary (Flattened JWE) with base64-encoded ciphertext and base64-encoded iv
    """
    iv = os.urandom(12)
    cipher_alg = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=_BACKEND)
    encryptor = cipher_alg.encryptor()
    encr_value = encryptor.update(utils.to_bytes(plaintext)) + encryptor.finalize()
    ciphertext_b64 = utils.base64url_encode(encr_value)
    tag_b64 = utils.base64url_encode(encryptor.tag)
    iv_b64 = base64.b64encode(iv) if legacy_support else utils.base64url_encode(iv)
    ret = {
      "header": {
        "alg": "dir",
        "enc": "A256GCM"
      },
      "iv": iv_b64,
      "ciphertext": ciphertext_b64,
      "tag": tag_b64,
    }

    if legacy_support:
        ct_b64 = base64.b64encode(encr_value + encryptor.tag)
        ret.update({
          "cipher": "aes",
          "mode": "gcm",
          "ts": 128,
          "ct": ct_b64,
        })
    return ret


def aes_decrypt(attr_ct, aes_key):
    """
    Convenience method to decrypt attribute properties

    :param attr_ct: Dictionary (may be a Flattened JWE) with base64-encoded
        ciphertext and base64-encoded iv
    :param aes_key: symmetric key to decrypt attribute value with
    :return: plaintext bytes
    """
    if not isinstance(attr_ct, dict) or (
        attr_ct.get('cipher', 'aes') != 'aes' or
        attr_ct.get('mode', 'gcm') != 'gcm' or
        'iv' not in attr_ct or
        (
            'header' in attr_ct and (
                attr_ct['header'].get('alg', 'dir') != 'dir' or
                attr_ct['header'].get('env', 'A256GCM') != 'A256GCM'
            )
        )
    ):
        raise ValueError('invalid encrypted attribute')

    iv = None
    ciphertext = None

    if 'ciphertext' in attr_ct:
        # JWE included, prefer that
        ciphertext = utils.base64url_decode(attr_ct.get('ciphertext'))
        tag = utils.base64url_decode(attr_ct.get('tag'))

        if len(tag) != 16:  # 128 // 8
            raise ValueError('invalid tag size: {}'.format(len(tag)))

        if 'cipher' in attr_ct:
            # hybrid mode, iv is in legacy format
            iv = base64.b64decode(attr_ct['iv'])
        else:
            iv = utils.base64url_decode(attr_ct['iv'])
    else:
        # legacy only
        ts = attr_ct.get('ts', 128)

        if ts != 128:
            raise ValueError('invalid tag size: {}'.format(ts))

        iv = base64.b64decode(attr_ct['iv'])
        tag_ct = base64.b64decode(attr_ct['ct'])

        sp = ts // 8
        ciphertext = tag_ct[:-sp]
        tag = tag_ct[-sp:]

    cipher_alg = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag, min_tag_length=8),
        backend=_BACKEND
    )
    decryptor = cipher_alg.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def key_wrap(wrapping_key, key_to_wrap):
    return aes_key_wrap(wrapping_key, key_to_wrap, _BACKEND)


def key_unwrap(wrapping_key, wrapped_key):
    return aes_key_unwrap(wrapping_key, wrapped_key, _BACKEND)
