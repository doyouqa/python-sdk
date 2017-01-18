# -*- coding: utf-8 -*-

"""
Provides useful functions for dealing with JWEs

Based on the
`JSON Web Encryption (JWE) <https://tools.ietf.org/html/rfc7516/>`_, and
`JSON Web Algorithms (JWA) <https://tools.ietf.org/html/rfc7518/>`_,
IETF RFCs.

"""
from __future__ import unicode_literals

import collections
import json
import base64
import logging

from . import jose, service, keychain, utils, exceptions

logger = logging.getLogger(__name__)

NON_OVERRIDABLE_CLAIMS = ['enc', 'alg', 'epk', 'apu']


def make_jwe(raw_claims, sender_keypair, recipient_keypairs, jsonify=True, json_encoder=json.dumps):
    """
    Convert claims into a JWE with General JWE JSON Serialization syntax

    :param raw_claims: payload data that will be converted to json
    :type raw_claims: dict
    :param recipient_keypairs: :py:class:`~oneid.keychain.Keypair`\s to encrypt the claims for
    :type recipient_keypairs: list or :py:class:`~oneid.keychain.Keypair`
    :param jsonify: If True (default), return JSON, otherwise keep as dict
    :type jsonify: bool
    :param json_encoder: encodes a :py:class:`dict` into JSON. Defaults to `json.dumps`
    :type json_encoder: function
    :return: JWE
    :return_type: str or dict
    """

    if not sender_keypair.identity:
        raise exceptions.IdentityRequired

    if not isinstance(recipient_keypairs, collections.Iterable):
        recipient_keypairs = [recipient_keypairs]

    claims = jose.normalize_claims(raw_claims)
    plaintext = json_encoder(claims)
    nonce = claims['jti']

    ephemeral_keypair = service.create_secret_key()
    common_header = _make_header(claims, sender_keypair.identity, ephemeral_keypair)
    cek = service.create_aes_key()
    encrypted_claims = service.encrypt_attr_value(plaintext, cek, legacy_support=False)

    ret = {
        "unprotected": common_header,
        "iv": utils.to_string(encrypted_claims['iv']),
        "ciphertext": utils.to_string(encrypted_claims['ciphertext']),
        "tag": utils.to_string(encrypted_claims['tag']),
        "recipients": [
            _encrypt_to_recipient(cek, sender_keypair.identity, ephemeral_keypair, keypair, nonce)
            for keypair in recipient_keypairs
        ],
    }

    del cek, ephemeral_keypair  # this wont wipe the memory, but is the best we can do in Python

    if jsonify:
        ret = json_encoder(ret)

    return ret


def decrypt_jwe(jwe, recipient_keypair, json_decoder=json.loads):
    """
    Decrypt the claims in a JWE for a given recipient

    :param jwe: JWE to verify and convert
    :type jwe: str
    :param recipient_keypair: :py:class:`~oneid.keychain.Keypair` to use to decrypt.
    :type recipient_keypair: :py:class:`~oneid.keychain.Keypair`
    :param json_encoder: a function to encode a :py:class:`dict` into JSON. Defaults to `json.dumps`
    :returns: claims
    :rtype: dict
    :raises: :py:class:`~oneid.exceptions.InvalidFormatError`: if not a valid JWE
    """

    if not recipient_keypair.identity:
        raise exceptions.IdentityRequired

    jwe_dict = jose.as_dict(jwe, json_decoder)

    if not jose.is_jwe(jwe_dict):
        logger.debug('attempt to decrypt a non-jwe (type: %s): %s', type(jwe), jwe)
        raise exceptions.InvalidFormatError

    shared_header = jose.get_jwe_shared_header(jwe, json_decoder=json.loads)

    recipient = next((
        recipient for recipient in jwe_dict['recipients']
        if recipient['header']['kid'] == str(recipient_keypair.identity)
    ), None)

    if not recipient:
        logger.warning('attempt to decrypt for invalid recipient (%s)', recipient_keypair.identity)
        raise exceptions.InvalidRecipient

    jwk = shared_header.get('epk')
    sender_keypair = keychain.Keypair.from_jwk(jwk)
    apu = utils.base64url_decode(shared_header.get('apu'))
    apv = utils.base64url_decode(recipient['header']['apv'])

    kek = recipient_keypair.ecdh(sender_keypair, party_u_info=apu, party_v_info=apv)
    e_cek = utils.base64url_decode(recipient['encrypted_key'])

    try:
        cek = service.key_unwrap(kek, e_cek)
    except:
        logger.warning('invalid attempt to decrypt CEK, id=%s', recipient_keypair.identity)
        raise exceptions.DecryptionFailed

    # recast into form expected by decrypt_attr_value
    # TODO: have it be more flexible?
    #
    attr_value = {
        key: base64.b64encode(utils.base64url_decode(value))
        for key, value in jwe_dict.items()
        if key in ['iv', 'ciphertext', 'tag']
    }
    # 'cipher': 'aes', mode': 'gcm' are assumed, 'ts': 128 isn't needed

    try:
        claims = service.decrypt_attr_value(attr_value, cek)
    except:
        logger.warning('invalid attempt to decrypt claims, id=%s', recipient_keypair.identity)
        raise exceptions.DecryptionFailed

    return json_decoder(utils.to_string(claims))


def _make_header(claims, sender_identity, ephemeral_keypair):
    HEADER_EXTRACTED_CLAIMS = ['iss', 'jti', 'nbf', 'exp', 'aud']

    common = {k: v for k, v in claims.items() if k in HEADER_EXTRACTED_CLAIMS}
    nonce = claims['jti']
    epk = ephemeral_keypair.jwk_public

    if any([k in claims for k in NON_OVERRIDABLE_CLAIMS]):
        raise ValueError

    common.update({
        "enc": "A256GCM",
        "alg": "ECDH-ES+A256KW",
        "epk": epk,
        "apu": utils.to_string(utils.base64url_encode(str(sender_identity) + nonce)),
    })
    return common


def _encrypt_to_recipient(cek, sender_identity, ephemeral_keypair, recipient_keypair, nonce):
    apu = utils.to_bytes(str(sender_identity) + nonce)
    apv = utils.to_bytes(str(recipient_keypair.identity) + nonce)

    ret = {
      "header": {
        "kid": recipient_keypair.identity,
        "apv": utils.to_string(utils.base64url_encode(apv)),
      },
    }
    kek = ephemeral_keypair.ecdh(recipient_keypair, party_u_info=apu, party_v_info=apv)
    encrypted_key = service.key_wrap(kek, cek)
    ret['encrypted_key'] = utils.to_string(utils.base64url_encode(encrypted_key))

    del kek

    return ret
