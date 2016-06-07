# -*- coding: utf-8 -*-

"""
Provides useful functions for dealing with JWTs and JWSs

Based on the
`JWT <https://tools.ietf.org/html/rfc7519/>`_ and
`JWS <https://tools.ietf.org/html/rfc7515/>`_
IETF RFCs.

"""
from __future__ import unicode_literals

import collections
import json
import re
import time
import logging

from . import utils, exceptions

logger = logging.getLogger(__name__)


B64_URLSAFE_RE = '[0-9a-zA-Z-_]+'
COMPACT_JWS_RE = r'^{b64}\.{b64}\.{b64}$'.format(b64=B64_URLSAFE_RE)

MINIMAL_JWT_HEADER = {
    'typ': 'JWT',
    'alg': 'ES256',
}
MINIMAL_JSON_JWS_HEADER = {
    'typ': 'JOSE+JSON',
    'alg': 'ES256',
}
TOKEN_EXPIRATION_TIME_SEC = (1*60*60)  # one hour
TOKEN_NOT_BEFORE_LEEWAY_SEC = (2*60)   # two minutes
TOKEN_EXPIRATION_LEEWAY_SEC = (3)      # three seconds


def make_jwt(raw_claims, keypair, json_encoder=json.dumps):
    """
    Convert claims into JWT

    :param raw_claims: payload data that will be converted to json
    :type raw_claims: dict
    :param keypair: :py:class:`~oneid.keychain.Keypair` to sign the request
    :param json_encoder: a function to encode a :py:class:`dict` into JSON. Defaults to `json.dumps`
    :return: JWT
    """
    if not isinstance(raw_claims, dict):
        raise TypeError('dict required for claims, type=' + str(type(raw_claims)))

    claims = _normalize_claims(raw_claims, keypair.identity)
    claims_serialized = json_encoder(claims)
    claims_b64 = utils.to_string(utils.base64url_encode(claims_serialized))

    header = {}
    header.update(MINIMAL_JWT_HEADER)
    if keypair.identity:
        header['kid'] = keypair.identity
    header_b64 = utils.to_string(utils.base64url_encode(json_encoder(header)))

    payload = '{header}.{claims}'.format(header=header_b64, claims=claims_b64)

    signature = utils.to_string(keypair.sign(payload))

    return '{payload}.{sig}'.format(payload=payload, sig=signature)


def verify_jwt(jwt, keypair=None, json_decoder=json.loads):
    """
    Convert a JWT back to it's claims, if validated by the :py:class:`~oneid.keychain.Keypair`

    :param jwt: JWT to verify and convert
    :type jwt: str or bytes
    :param keypair: :py:class:`~oneid.keychain.Keypair` to verify the JWT
    :type keypair: :py:class:`~oneid.keychain.Keypair`
    :param json_decoder: a function to decode JSON into a :py:class:`dict`. Defaults to `json.loads`
    :returns: claims
    :rtype: dict
    :raises: :py:class:`~oneid.exceptions.InvalidFormatError` if not a valid JWT
    :raises: :py:class:`~oneid.exceptions.InvalidAlgorithmError` if unsupported algorithm specified
    :raises: :py:class:`~oneid.exceptions.InvalidClaimsError` if missing or invalid claims,
        including expiration, re-used nonce, etc.
    :raises: :py:class:`~oneid.exceptions.InvalidSignatureError` if signature is not valid
    """
    jwt = utils.to_string(jwt)
    if not re.match(COMPACT_JWS_RE, jwt):
        logger.debug('Given JWT doesnt match pattern: %s', jwt)
        raise exceptions.InvalidFormatError

    try:
        header_json, claims_json, signature = [utils.base64url_decode(p) for p in jwt.split('.')]
    except:
        logger.debug('invalid JWT, error splitting/decoding: %s', jwt, exc_info=True)
        raise exceptions.InvalidFormatError

    header = _verify_jose_header(utils.to_string(header_json), True, json_decoder)
    claims = _verify_claims(utils.to_string(claims_json), json_decoder)

    if keypair:
        try:
            keypair.verify(*(jwt.rsplit('.', 1)))
        except:
            logger.debug('invalid signature, header=%s, claims=%s', header, claims, exc_info=True)
            raise exceptions.InvalidSignatureError

    return claims


def make_jws(raw_claims, keypairs, json_encoder=json.dumps):
    """
    Convert claims into JWS format (compact or JSON)

    :param raw_claims: payload data that will be converted to json
    :type raw_claims: dict
    :param keypairs: :py:class:`~oneid.keychain.Keypair`\s to sign the request with
    :type keypairs: list
    :param json_encoder: a function to encode a :py:class:`dict` into JSON. Defaults to `json.dumps`
    :return: JWS
    """
    claims = _normalize_claims(raw_claims)
    claims_serialized = json_encoder(claims)
    claims_b64 = utils.to_string(utils.base64url_encode(claims_serialized))

    ret = {
        "payload": claims_b64,
        "signatures": [],
    }

    if not isinstance(keypairs, collections.Iterable):
        keypairs = [keypairs]

    for keypair in keypairs:
        if not keypair.identity:
            logger.debug('Missing Keypair.identity')
            raise exceptions.InvalidKeyError

        header = {
            'kid': keypair.identity,
        }
        header.update(MINIMAL_JSON_JWS_HEADER)
        header_b64 = utils.to_string(utils.base64url_encode(json_encoder(header)))
        to_sign = '{header}.{claims}'.format(header=header_b64, claims=claims_b64)

        signature = utils.to_string(keypair.sign(to_sign))

        ret['signatures'].append({
            'protected': header_b64,
            'signature': signature,
        })

    return json_encoder(ret)


def extend_jws_signatures(
    jws, keypairs, default_jwt_kid=None,
    json_encoder=json.dumps, json_decoder=json.loads,
):
    """
    Add signatures to an existing JWS (or JWT)

    :param jws: existing JWS (Compact or JSON) or JWT
    :type jws: str
    :param keypairs: additional :py:class:`~oneid.keychain.Keypair`\s to sign the request with
    :type keypairs: list
    :param default_jwt_kid: (optional) value for 'kid' header field if passing a JWT without one
    :type default_jwt_kid: str
    :param json_encoder: a function to encode a :py:class:`dict` into JSON. Defaults to `json.dumps`
    :param json_decoder: a function to decode JSON into a :py:class:`dict`. Defaults to `json.loads`
    :return: JWS
    """
    ret = _jws_as_dict(jws, default_jwt_kid, json_decoder)
    payload = ret['payload']

    if not isinstance(keypairs, collections.Iterable):
        keypairs = [keypairs]

    for keypair in keypairs:
        if not keypair.identity:
            logger.debug('Missing Keypair.identity')
            raise exceptions.InvalidKeyError

        header = {
            'kid': keypair.identity,
        }
        header.update(MINIMAL_JSON_JWS_HEADER)
        header_b64 = utils.to_string(utils.base64url_encode(json_encoder(header)))
        to_sign = '{header}.{claims}'.format(header=header_b64, claims=payload)

        signature = utils.to_string(keypair.sign(to_sign))

        ret['signatures'].append({
            'protected': header_b64,
            'signature': signature,
        })

    return json_encoder(ret)


def get_jws_key_ids(jws, default_kid=None, json_decoder=json.loads):
    """
    Extract the IDs of the keys used to sign a given JWS

    :param jws: JWS to get key IDs from
    :type jws: str or bytes
    :param default_kid: Value to use for looking up keypair if no `kid` found
                    in a given signature header, as may happen when extending a JWT
    :type default_kid: str
    :param json_decoder: a function to decode JSON into a :py:class:`dict`. Defaults to `json.loads`
    :returns: key IDs
    :rtype: list
    :raises: :py:class:`~oneid.exceptions.InvalidFormatError`: if not a valid JWS
    """
    try:
        jws = json_decoder(utils.to_string(jws))
    except:
        logger.debug('error parsing JWS', exc_info=True)
        raise exceptions.InvalidFormatError

    return [
        _get_kid_for_signature(signature, default_kid, json_decoder)
        for signature in jws['signatures']
    ]


def verify_jws(jws, keypairs=None, verify_all=True, default_kid=None, json_decoder=json.loads):
    """
    Convert a JWS back to it's claims, if validated by a set of
    required :py:class:`~oneid.keychain.Keypair`\s

    :param jws: JWS to verify and convert
    :type jws: str or bytes
    :param keypairs: :py:class:`~oneid.keychain.Keypair`\s to verify the JWS with.
                    Must include one for each specified in the JWS headers' `kid` values.
    :type keypairs: list
    :param verify_all: If True (default), all keypairs must validate a signature.
                    If False, only one needs to.
                    If any fail to validate, the JWS is still not validated.
                    This allows the caller to send multiple keys that _might_ have
                    corresponding signatures, without requiring that _all_ do.
    :type verify_all: bool
    :param default_kid: Value to use for looking up keypair if no `kid` found
                    in a given signature header, as may happen when extending a JWT
    :type default_kid: str
    :param json_encoder: a function to encode a :py:class:`dict` into JSON. Defaults to `json.dumps`
    :returns: claims
    :rtype: dict
    :raises: :py:class:`~oneid.exceptions.InvalidFormatError`: if not a valid JWS
    :raises: :py:class:`~oneid.exceptions.InvalidAlgorithmError`: if unsupported algorithm specified
    :raises: :py:class:`~oneid.exceptions.InvalidClaimsError`: if missing or invalid claims,
        including expiration, re-used nonce, etc.
    :raises: :py:class:`~oneid.exceptions.InvalidSignatureError`: if any relevant signature
        is not valid
    """

    if keypairs and not isinstance(keypairs, collections.Iterable):
        keypairs = [keypairs]

    jws = utils.to_string(jws)

    if re.match(COMPACT_JWS_RE, jws):

        if verify_all and keypairs and len(keypairs) != 1:
            raise exceptions.InvalidSignatureError(
                'Compact JWS found but multiple signatures required'
            )

        return verify_jwt(jws, keypairs and keypairs[0])

    jws = json_decoder(jws)

    if 'payload' not in jws or 'signatures' not in jws:
        raise exceptions.InvalidFormatError

    claims = _verify_claims(utils.to_string(utils.base64url_decode(jws['payload'])), json_decoder)

    if keypairs:
        _verify_jws_signatures(jws, keypairs, verify_all, default_kid, json_decoder)

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


def _jws_as_dict(jws, kid, json_decoder):

    if not re.match(COMPACT_JWS_RE, jws):
        return json_decoder(jws)

    header_b64, payload, signature = utils.to_string(jws).split('.')

    header = json_decoder(utils.to_string(utils.base64url_decode(header_b64)))
    extra_header = None

    if 'kid' not in header:
        claims = json_decoder(utils.to_string(utils.base64url_decode(payload)))
        kid = kid or claims.get('iss')
        extra_header = kid and {
            'kid': kid
        }

    ret = {
        'payload': payload,
        'signatures': [{
            'protected': header_b64,
            'signature': signature,
        }]
    }

    if extra_header:
        ret['signatures'][0]['header'] = extra_header

    return ret


def _verify_jose_header(header_json, strict_jwt, json_decoder):
    header = None
    try:
        header = json_decoder(header_json)
        logger.debug('parsed header, header=%s', header)
    except ValueError:
        logger.debug('invalid header, not valid json: %s', header_json)
        raise exceptions.InvalidFormatError
    except Exception:  # pragma: no cover
        logger.debug('unknown error verifying header: %s', header, exc_info=True)
        raise

    if strict_jwt:
        keys = {k: 1 for k in header}
        for key, value in MINIMAL_JWT_HEADER.items():
            if key not in header or header.get(key, None) != value:
                logger.debug('invalid header, missing or incorrect %s: %s', key, header)
                raise exceptions.InvalidFormatError
            keys.pop(key, None)
        keys.pop('kid', None)

        if len(keys) > 0:
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


def _verify_claims(payload, json_decoder):
    try:
        claims = json_decoder(payload)
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


def _verify_jws_signatures(jws, keypairs, verify_all, default_kid, json_decoder):
    if len(jws['signatures']) == 0:
        logger.warning('No signatures found, rejecting')
        raise exceptions.InvalidSignatureError

    if verify_all and len(keypairs) != len(jws['signatures']):
        raise exceptions.KeySignatureMismatch('number of keys doesn\'t match number of signatures')

    keypair_map = {str(keypair.identity): keypair for keypair in keypairs}

    if len(keypairs) != len(keypair_map):
        raise exceptions.InvalidKeyError('redundant keypairs found, unable to verify')

    found_sigs = [
        _get_kid_for_signature(sig, default_kid, json_decoder)
        in keypair_map for sig in jws['signatures']
    ]

    # need at least one signature
    if not any(found_sigs):
        logger.warning('No keypairs had corresponding signatures, rejecting')
        raise exceptions.KeySignatureMismatch

    # or all
    if verify_all and not all(found_sigs):
        logger.warning('Not all keys have corresponding signatures, rejecting')
        raise exceptions.KeySignatureMismatch

    for signature in jws['signatures']:
        kid = _get_kid_for_signature(signature, default_kid, json_decoder)

        if verify_all or kid in keypair_map:
            _verify_jws_signature(jws['payload'], keypair_map.get(kid), signature)


def _get_kid_for_signature(signature, default_kid, json_decoder):
    header = _get_signature_header(signature, json_decoder)
    kid = header.get('kid', signature.get('header', {}).get('kid', default_kid))

    if not kid:
        logger.warning(
            'invalid header in signature, missing "kid": %s', signature
        )
        raise exceptions.InvalidFormatError

    return kid


def _get_signature_header(signature, json_decoder):
    # TODO: check for overlapping keys in `protected` and `header`, merge together
    #       for now, we only look for `kid` in `header`, and only if it isn't in `protected`

    return _verify_jose_header(
        utils.to_string(utils.base64url_decode(signature['protected'])),
        False, json_decoder,
    )


def _verify_jws_signature(payload, keypair, signature):
    try:
        keypair.verify('.'.join([signature['protected'], payload]), signature['signature'])
    except:
        logger.debug('invalid signature', exc_info=True)
        raise exceptions.InvalidSignatureError
