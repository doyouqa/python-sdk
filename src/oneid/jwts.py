# -*- coding: utf-8 -*-

"""
Provides useful functions for dealing with JWTs

Based on the `JWT <https://tools.ietf.org/html/rfc7519/>`_ IETF RFC.

"""
from __future__ import unicode_literals

import json
import re
import time
import logging

from . import utils, exceptions

logger = logging.getLogger(__name__)


B64_URLSAFE_RE = '[0-9a-zA-Z-_]+'
JWT_RE = r'^{b64}\.{b64}\.{b64}$'.format(b64=B64_URLSAFE_RE)

MINIMAL_JWT_HEADER = {
    'typ': 'JWT',
    'alg': 'ES256',
}
MINIMAL_JWT_HEADER_JSON = json.dumps(MINIMAL_JWT_HEADER)
MINIMAL_JWT_HEADER_B64 = utils.to_string(utils.base64url_encode(MINIMAL_JWT_HEADER_JSON))

TOKEN_EXPIRATION_TIME_SEC = (1*60*60)  # one hour
TOKEN_NOT_BEFORE_LEEWAY_SEC = (2*60)   # two minutes
TOKEN_EXPIRATION_LEEWAY_SEC = (3)      # three seconds


def make_jwt(raw_claims, keypair):
    """
    Convert claims into JWT

    :param raw_claims: payload data that will be converted to json
    :type raw_claims: dict
    :param keypair: :py:class:`~oneid.keychain.Keypair` to sign the request
    :return: JWT
    """
    if not isinstance(raw_claims, dict):
        raise TypeError('dict required for claims, type=' + str(type(raw_claims)))

    claims = _normalize_claims(raw_claims, keypair.identity)
    claims_serialized = json.dumps(claims)
    claims_b64 = utils.to_string(utils.base64url_encode(claims_serialized))

    payload = '{header}.{claims}'.format(header=MINIMAL_JWT_HEADER_B64, claims=claims_b64)

    signature = utils.to_string(keypair.sign(payload))

    return '{payload}.{sig}'.format(payload=payload, sig=signature)


def verify_jwt(jwt, keypair=None):
    """
    Convert a JWT back to it's claims, if validated by the :py:class:`~oneid.keychain.Keypair`

    :param jwt: JWT to verify and convert
    :type jwt: str or bytes
    :param keypair: :py:class:`~oneid.keychain.Keypair` to verify the JWT
    :type keypair: :py:class:`~oneid.keychain.Keypair`
    :returns: claims
    :rtype: dict
    :raises :py:class:`InvalidFormatError`: if not a valid JWT
    :raises :py:class:`InvalidAlgorithmError`: if unsupported algorithm specified
    :raises :py:class:`InvalidClaimsError`: if missing or invalid claims, including expiration,
        re-used nonce, etc.
    :raises :py:class:`InvalidSignatureError`: if signature is not valid
    """
    jwt = utils.to_string(jwt)
    if not re.match(JWT_RE, jwt):
        logger.debug('Given JWT doesnt match pattern: %s', jwt)
        raise exceptions.InvalidFormatError

    try:
        header_json, claims_json, signature = [utils.base64url_decode(p) for p in jwt.split('.')]
    except:
        logger.debug('invalid JWT, error splitting/decoding: %s', jwt, exc_info=True)
        raise exceptions.InvalidFormatError

    header = _verify_jose_header(utils.to_string(header_json))
    claims = _verify_claims(utils.to_string(claims_json))

    if keypair:
        try:
            keypair.verify(*(jwt.rsplit('.', 1)))
        except:
            logger.debug('invalid signature, header=%s, claims=%s', header, claims)
            raise exceptions.InvalidSignatureError

    return claims


def _normalize_claims(raw_claims, issuer=None):
    now = int(time.time())
    claims = {
        # Required claims, may be over-written by entries in raw_claims
        'jti': utils.make_nonce(),
        'nbf': now,
        'exp': now + TOKEN_EXPIRATION_TIME_SEC,
    }
    if issuer:
        claims['iss'] = issuer

    claims.update(raw_claims)

    return claims


def _verify_jose_header(header_json, strict_jwt=True):
    header = None
    try:
        header = json.loads(header_json)
        logger.debug('parsed header, header=%s', header)
    except ValueError:
        logger.debug('invalid header, not valid json: %s', header_json)
        raise exceptions.InvalidFormatError
    except Exception:  # pragma: no cover
        logger.debug('unknown error verifying header: %s', header, exc_info=True)
        raise

    if strict_jwt:
        for key, value in MINIMAL_JWT_HEADER.items():
            if key not in header or header.get(key, None) != value:
                logger.debug('invalid header, missing or incorrect %s: %s', key, header)
                raise exceptions.InvalidFormatError
        if len(MINIMAL_JWT_HEADER) != len(header):
            logger.debug('invalid header, extra elements: %s', header)
            raise exceptions.InvalidFormatError
    else:
        if 'typ' not in header or header['typ'] not in ['JWT', 'JOSE', 'JOSE+JSON']:
            logger.debug('invalid "typ" in header: %s', header)
            raise exceptions.InvalidFormatError

        if 'alg' not in header or header['alg'] != 'ES256':
            logger.debug('invalid "alg" in header: %s', header)
            raise exceptions.InvalidAlgorithmError

    logger.debug('returning %s', header)
    return header


def _verify_claims(payload):
    try:
        claims = json.loads(payload)
    except:
        logger.debug('unknown error verifying payload: %s', payload, exc_info=True)
        raise exceptions.InvalidFormatError

    now = int(time.time())

    if 'exp' in claims and (int(claims['exp']) + TOKEN_EXPIRATION_LEEWAY_SEC) < now:
        logger.warning('Expired token, exp=%s, now=%s', claims['exp'], now)
        raise exceptions.InvalidClaimsError

    if 'nbf' in claims and (int(claims['nbf']) - TOKEN_NOT_BEFORE_LEEWAY_SEC) > now:
        logger.warning('Early token, nbf=%s, now=%s', claims['nbf'], now)
        raise exceptions.InvalidClaimsError

    if 'jti' in claims and not utils.verify_and_burn_nonce(claims['jti']):
        logger.warning('Invalid nonce: %s', claims['jti'])
        raise exceptions.InvalidClaimsError

    return claims
