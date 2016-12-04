# -*- coding: utf-8 -*-

import re
import json
import six
import time
import logging

from datetime import datetime
from dateutil import tz

from . import nonces, utils

logger = logging.getLogger(__name__)


B64_URLSAFE_RE = '[0-9a-zA-Z-_]+'
COMPACT_JWS_RE = r'^{b64}\.{b64}\.{b64}$'.format(b64=B64_URLSAFE_RE)


TOKEN_EXPIRATION_TIME_SEC = nonces.DEFAULT_NONCE_EXPIRY_SECONDS


def is_compact_jws(jws):
    return bool(re.match(COMPACT_JWS_RE, jws))


def is_jws(jws, json_decoder=json.loads):
    REQUIRED_FIELDS = ['payload', 'signatures']

    if isinstance(jws, six.string_types):
        if is_compact_jws(jws):
            return True
        jws = json_decoder(jws)

    if not isinstance(jws, dict):
        return False

    if not all([k in jws for k in REQUIRED_FIELDS]):
        return False

    return True


def normalize_claims(raw_claims, issuer=None):
    exp = None
    nbf = None
    nonce = None

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


def as_dict(jose_obj, json_decoder=json.loads):

    if not isinstance(jose_obj, dict):
        jose_obj = json_decoder(utils.to_string(jose_obj))

    return jose_obj
