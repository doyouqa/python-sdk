# -*- coding: utf-8 -*-

"""
Utility functions for dealing with JOSE objects generally.

Mostly used internally, but may be useful for external callers.
"""

import re
import json
import six
import time
import logging

from datetime import datetime
from dateutil import tz

from . import nonces, utils, exceptions

logger = logging.getLogger(__name__)


B64_URLSAFE_RE = '[0-9a-zA-Z-_]+'
COMPACT_JWS_RE = r'^{b64}\.{b64}\.{b64}$'.format(b64=B64_URLSAFE_RE)


TOKEN_EXPIRATION_TIME_SEC = nonces.DEFAULT_NONCE_EXPIRY_SECONDS


def is_compact_jws(msg):
    """
    Determine if a given message is a compact JWS (or JWT) or not.
    Does not necessarily mean that it is valid or authentic.

    :param msg: message to inspect
    :type msg: str
    :returns: True if the message is a compact JWS, False otherwise
    :rtype: bool
    """
    return bool(re.match(COMPACT_JWS_RE, msg))


def is_jws(msg, json_decoder=json.loads):
    """
    Determine if a given message is a JWS or not (compact or otherwise).
    Does not necessarily mean that it is valid or authentic.

    :param msg: message to inspect
    :type msg: str or dict
    :param json_decoder: a function to decode JSON into a :py:class:`dict`. Defaults to `json.loads`
    :returns: True if the message is a JWS, False otherwise
    :rtype: bool
    """
    REQUIRED_FIELDS = ['payload', 'signatures']

    if isinstance(msg, six.string_types):
        if is_compact_jws(msg):
            return True
        msg = json_decoder(msg)

    if not isinstance(msg, dict):
        return False

    if not all([k in msg for k in REQUIRED_FIELDS]):
        return False

    return True


def is_jwe(msg, json_decoder=json.loads):
    """
    Determine if a given message is a JWE or not.
    Does not necessarily mean that it is valid or authentic.

    :param msg: message to inspect
    :type msg: str or dict
    :param json_decoder: a function to decode JSON into a :py:class:`dict`. Defaults to `json.loads`
    :returns: True if the message is a JWS, False otherwise
    :rtype: bool
    """
    REQUIRED_FIELDS = ['iv', 'ciphertext', 'tag', 'recipients']

    if isinstance(msg, six.string_types):
        msg = json_decoder(msg)

    if not isinstance(msg, dict):
        return False

    if not all([k in msg for k in REQUIRED_FIELDS]):
        return False

    return True


def get_jwe_shared_header(jwe, json_decoder=json.loads):
    """
    Extract shared (non-encrypted) header values from a JWE

    :param jwe: JWE to extract header field values from
    :type jwe: str or dict
    :param json_decoder: a function to decode JSON into a :py:class:`dict`. Defaults to `json.loads`
    :returns: header fields and values
    :rtype: dict
    :raises: :py:class:`~oneid.exceptions.InvalidFormatError`: if not a valid JWE
    """
    jwe_dict = as_dict(jwe, json_decoder)

    if not is_jwe(jwe_dict):
        logger.debug('attempt to get header values from a non-jwe (type: %s): %s', type(jwe), jwe)
        raise exceptions.InvalidFormatError

    shared_header = jwe_dict.get('unprotected', {})

    if 'protected' in jwe_dict:
        protected_b64 = jwe_dict['protected']
        protected_dict = json.loads(utils.to_string(utils.base64url_decode(protected_b64)))
        shared_header.update(protected_dict)

    return shared_header


def normalize_claims(raw_claims, issuer=None):
    """
    Return a set of claims based on the provided claim set that includes reasonable defaults
    for required claims.

    Note that the claims may be in the form of a valid JWE, in which case the inner values
    may be inspected.

    :param raw_claims: Initial set of claims, may or may not include required claims
    :type raw_claims: dict
    :param issuer: (optional) identifier of the identity creating the message
    :type str:
    :returns: filled-out claims
    :rtype: dict
    """
    exp = None
    nbf = None
    nonce = None

    if is_jwe(raw_claims):
        headers = get_jwe_shared_header(raw_claims)
        exp = headers.get('exp', exp)
        nbf = headers.get('nbf', nbf)
        nonce = headers.get('jti', nonce)
        if not issuer:
            issuer = headers.get('iss')
    else:
        exp = raw_claims.get('exp', exp)
        nbf = raw_claims.get('nbf', nbf)
        nonce = raw_claims.get('jti', nonce)
        if not issuer:
            issuer = raw_claims.get('iss')

    if exp and not nonce:
        # use message expiration for nonce expiration
        exp_dt = datetime.fromtimestamp(exp, tz.tzutc())
        nonce = nonces.make_nonce(exp_dt)
    elif nonce and (nonce[:3] == '002') and not exp:
        # use >v1 nonce expiration for message expiration
        try:
            exp = utils.to_timestamp(nonce[3:-6])
        except:
            logger.warning('unable to parse jti for nonce exp, using default, jti=%s', nonce)

    now = int(time.time())
    default_exp_ts = (now + TOKEN_EXPIRATION_TIME_SEC)
    default_exp_dt = datetime.fromtimestamp(default_exp_ts, tz.tzutc())

    claims = {
        'jti': nonce or nonces.make_nonce(default_exp_dt),
        'nbf': nbf or now,
        'exp': exp or default_exp_ts,
    }
    if issuer:
        claims['iss'] = issuer

    claims.update(raw_claims)

    return claims


def as_dict(msg, json_decoder=json.loads):
    """
    Unpack a message (if necessary) into its dictionary form.

    :param msg: message to convert
    :type msg: str or dict
    :param json_decoder: a function to decode JSON into a :py:class:`dict`. Defaults to `json.loads`
    :returns: the message in dictionary form
    :rtype: dict
    """

    if not isinstance(msg, dict):
        msg = json_decoder(utils.to_string(msg))

    return msg
