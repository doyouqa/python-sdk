"""
Helpful utility functions
"""
from __future__ import unicode_literals

import os
import random
import re
from datetime import datetime, timedelta
from dateutil import parser, tz
import logging

logger = logging.getLogger(__name__)

NONCE_V1_PREFIX = '001'
NONCE_V2_PREFIX = '002'

DEFAULT_NONCE_EXPIRY_SECONDS = (1 * 60 * 60)  # one hour

_valid_chars = None


def make_nonce(expiry=None):
    """
    Create a nonce with expiration timestamp included

    :param expiry: a `datetime` that indicates when the nonce self-expires,
        defaults to now + 30 minutes

    :return: nonce
    """
    global _valid_chars

    if not _valid_chars:
        _valid_chars = ''
        # iterate over all the ascii characters for a list of all alpha-numeric characters
        for char_index in range(0, 128):
            if chr(char_index).isalpha() or chr(char_index).isalnum():
                _valid_chars += chr(char_index)

    if not expiry:
        now = datetime.utcnow().replace(tzinfo=tz.tzutc())
        expiry = (now + timedelta(seconds=DEFAULT_NONCE_EXPIRY_SECONDS))

    time_format = '%Y-%m-%dT%H:%M:%SZ'
    time_component = expiry.strftime(time_format)

    random_str = ''
    random_chr = random.SystemRandom()
    for i in range(0, 6):
        random_str += random_chr.choice(_valid_chars)

    return '{prefix}{time_str}{random_str}'.format(
        prefix=NONCE_V2_PREFIX,
        time_str=time_component,
        random_str=random_str,
    )


def _default_nonce_verifier(nonce):
    oneid_directory = os.path.join(os.path.expanduser('~'), '.oneid')
    nonce_cache_fn = os.path.join(oneid_directory, 'used_nonces.txt')

    if not os.path.exists(oneid_directory):
        os.makedirs(oneid_directory)

    if os.path.exists(nonce_cache_fn):
        count = 0
        with open(nonce_cache_fn, 'r') as fd:
            for saved_nonce in fd:
                saved_nonce = saved_nonce.rstrip()
                if saved_nonce == nonce:
                    return False
                count += 1
        if count > 10000:  # pragma: no cover  TODO: mock or attach handler to logger
            logger.warning(
                'nonce cache is getting full (%n entries), consider alternate store',
                count
            )
    return True

_nonce_verifier = _default_nonce_verifier


def _default_nonce_burner(nonce):
    oneid_directory = os.path.join(os.path.expanduser('~'), '.oneid')
    nonce_cache_fn = os.path.join(oneid_directory, 'used_nonces.txt')

    if not os.path.exists(oneid_directory):
        os.makedirs(oneid_directory)

    with open(nonce_cache_fn, 'a+') as fd:
        fd.write(nonce + '\n')

    return True

_nonce_burner = _default_nonce_burner


def set_nonce_handlers(nonce_verifier, nonce_burner):
    """
    Sets the functions to verify nonces and record their use.

    By default, the nonces are saved in a local file
    named `~/.oneid/used_nonces.txt` (or equivalent)

    :param nonce_burner: function to be called to verify. Passed one argument, the nonce
    :param nonce_verifier: function to be called to burn. Passed one argument, the nonce
    """
    global _nonce_burner, _nonce_verifier

    _nonce_verifier = nonce_verifier
    _nonce_burner = nonce_burner


def verify_nonce(nonce, expiry=None):
    """
    Ensure that the nonce is correct, and not from the future

    Callers should also store used nonces and reject messages
    with previously-used ones.

    :param nonce: Nonce as created with :func:`~oneid.nonces.make_nonce`
    :param expiry: If not None, a `datetime` before which the nonce is not valid
    :return: True only if nonce meets validation criteria
    :rtype: bool
    """
    NONCE_REGEX = (
        r'^00[12]'
        r'[2-9][0-9]{3}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])'
        r'T([01][0-9]|2[0-3])(:[0-5][0-9]){2}Z'
        r'[A-Za-z0-9]{6}$'
    )

    if not re.match(NONCE_REGEX, nonce):
        logger.debug('incorrectly-formatted nonce: %s', nonce)
        return False

    nonce_date = parser.parse(nonce[3:-6])

    if expiry and (nonce_date < expiry):
        logger.debug('out-of-date-range nonce: %s, expiry=%s', nonce, expiry)
        return False

    now = datetime.utcnow().replace(tzinfo=tz.tzutc())

    if nonce[:3] == NONCE_V1_PREFIX:
        now_ish = (now + timedelta(minutes=2))

        if nonce_date > now_ish:
            logger.debug('nonce from the future, invalid: %s', nonce)
            return False

    elif now > nonce_date:
        logger.debug('nonce is expired: %s', nonce)
        return False

    return _nonce_verifier(nonce)


def burn_nonce(nonce):
    return _nonce_burner(nonce)
