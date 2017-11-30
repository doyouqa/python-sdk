# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import os
import uuid
import tempfile
import random
import logging
from datetime import datetime, timedelta
from dateutil import tz


from unittest import TestCase

from ntdi import nonces

logger = logging.getLogger(__name__)


def _make_datetime(delta_minutes=0, delta_seconds=0):
    ret = datetime.utcnow().replace(tzinfo=tz.tzutc())

    if delta_minutes:
        ret += timedelta(minutes=delta_minutes)

    if delta_seconds:
        ret += timedelta(seconds=delta_seconds)

    return ret


def _timestamp(dt=None, delta_minutes=0, delta_seconds=0):

    if not dt:
        dt = _make_datetime(delta_minutes, delta_seconds)

    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def _make_nonce(version=2, dt=None, delta_minutes=0, delta_seconds=0):
    return '{:03d}{}{}'.format(
        version,
        _timestamp(dt, delta_minutes, delta_seconds),
        ''.join([random.SystemRandom().choice('01234567abcdefgABCDEFG') for _ in range(6)]),
    )


class TestMakeNonce(TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_make_nonce(self):
        nonce = nonces.make_nonce()
        self.assertRegexpMatches(
            nonce,
            r'^002'
            r'[2-9][0-9]{3}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])'
            r'T([01][0-9]|2[0-3])(:[0-5][0-9]){2}Z'
            r'[A-Za-z0-9]{6}$'
        )

    def test_make_nonce_with_date(self):
        dt = _make_datetime(delta_minutes=5)
        nonce = nonces.make_nonce(dt)
        self.assertRegexpMatches(
            nonce,
            r'^002'
            r'[2-9][0-9]{3}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])'
            r'T([01][0-9]|2[0-3])(:[0-5][0-9]){2}Z'
            r'[A-Za-z0-9]{6}$'
        )
        self.assertEqual(_timestamp(dt), nonce[3:-6])

    def test_make_nonce_expired(self):
        expiry = _make_datetime(delta_minutes=5)
        nonce = nonces.make_nonce(expiry)
        self.assertRegexpMatches(
            nonce,
            r'^002'
            r'[2-9][0-9]{3}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])'
            r'T([01][0-9]|2[0-3])(:[0-5][0-9]){2}Z'
            r'[A-Za-z0-9]{6}$'
        )
        self.assertEqual(_timestamp(expiry), nonce[3:-6])

    def test_uniquess_to_a_point(self):
        seen = {}

        for _ in range(10000):
            nonce = nonces.make_nonce()
            self.assertTrue(nonce not in seen)
            seen[nonce] = True


class TestVerifyAndBurnV1Nonces(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ['HOME'] = self.tmpdir
        logger.debug('writing nonce cache to %s/.oneid/used_nonces.txt', self.tmpdir)

    def tearDown(self):
        pass

    def test_valid_nonce(self):
        nonce = _make_nonce(version=1)
        logger.debug('nonce=%s', nonce)

        self.assertTrue(nonces.verify_nonce(nonce))
        self.assertTrue(nonces.burn_nonce(nonce))
        self.assertFalse(nonces.verify_nonce(nonce))

    def test_expired_nonce(self):
        nbf = _make_datetime(delta_seconds=3)
        nonce = _make_nonce(version=1)
        logger.debug('nonce=%s, nbf=%s', nonce, nbf)

        self.assertFalse(nonces.verify_nonce(nonce, nbf))

    def test_almost_expired_nonce(self):
        nbf = _make_datetime(delta_seconds=-3)
        nonce = _make_nonce(version=1, delta_minutes=0)
        logger.debug('nonce=%s, nbf=%s', nonce, nbf)

        self.assertTrue(nonces.verify_nonce(nonce, nbf))

    def test_future_nonce(self):
        # three seconds avoids possible race condition
        nonce = _make_nonce(version=1, delta_minutes=2, delta_seconds=3)
        logger.debug('nonce=%s', nonce)

        self.assertFalse(nonces.verify_nonce(nonce))

    def test_almost_future_nonce(self):
        # three seconds avoids possible race condition
        nonce = _make_nonce(version=1, delta_minutes=2, delta_seconds=-3)
        logger.debug('nonce=%s', nonce)

        self.assertTrue(nonces.verify_nonce(nonce))
        self.assertTrue(nonces.burn_nonce(nonce))

    def test_burned_nonce(self):
        nonce = _make_nonce(version=1)
        nonce2 = _make_nonce(version=1)
        logger.debug('nonce=%s, nonce2=%s', nonce, nonce2)

        self.assertTrue(nonces.verify_nonce(nonce))
        self.assertTrue(nonces.burn_nonce(nonce))
        self.assertFalse(nonces.verify_nonce(nonce))

        self.assertTrue(nonces.verify_nonce(nonce2))
        self.assertTrue(nonces.burn_nonce(nonce2))
        self.assertFalse(nonces.verify_nonce(nonce2))


class BaseTestVerifyAndBurnNonce(object):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ['HOME'] = self.tmpdir
        logger.debug('writing nonce cache to %s/.oneid/used_nonces.txt', self.tmpdir)

    def tearDown(self):
        pass

    def test_valid_nonce(self):
        nonce = nonces.make_nonce()
        logger.debug('nonce=%s', nonce)

        self.assertTrue(nonces.verify_nonce(nonce))
        self.assertTrue(nonces.burn_nonce(nonce))
        self.assertFalse(nonces.verify_nonce(nonce))

    def test_invalid_nonce(self):
        nonce = _make_nonce(version=999)
        logger.debug('nonce=%s', nonce)

        self.assertFalse(nonces.verify_nonce(nonce))

    def test_expired_nonce_nbf(self):
        nbf = _make_datetime(delta_seconds=-3)
        nonce = _make_nonce(delta_seconds=-6)
        logger.debug('nonce=%s, nbf=%s', nonce, nbf)

        self.assertFalse(nonces.verify_nonce(nonce, nbf))

    def test_expired_nonce_inherent(self):
        nonce = _make_nonce(delta_seconds=-3)
        logger.debug('nonce=%s', nonce)

        self.assertFalse(nonces.verify_nonce(nonce))

    def test_almost_expired_nonce(self):
        nbf = _make_datetime(delta_seconds=-3)
        nonce = nonces.make_nonce()
        logger.debug('nonce=%s, nbf=%s', nonce, nbf)

        self.assertTrue(nonces.verify_nonce(nonce, nbf))

    def test_burned_nonce(self):
        nonce = nonces.make_nonce()
        nonce2 = nonces.make_nonce()
        logger.debug('nonce=%s, nonce2=%s', nonce, nonce2)

        self.assertTrue(nonces.verify_nonce(nonce))
        self.assertTrue(nonces.burn_nonce(nonce))
        self.assertFalse(nonces.verify_nonce(nonce))

        self.assertTrue(nonces.verify_nonce(nonce2))
        self.assertTrue(nonces.burn_nonce(nonce2))
        self.assertFalse(nonces.verify_nonce(nonce2))


class TestVerifyAndBurnNonce(BaseTestVerifyAndBurnNonce, TestCase):
    pass


class TestPermissiveNonceStore(BaseTestVerifyAndBurnNonce, TestCase):
    def setUp(self):
        nonces.set_nonce_handlers(lambda _n: True, lambda _n: True)

    def tearDown(self):
        nonces.set_nonce_handlers(nonces._default_nonce_verifier, nonces._default_nonce_burner)

    def test_valid_nonce(self):
        nonce = nonces.make_nonce()
        logger.debug('nonce=%s', nonce)

        self.assertTrue(nonces.verify_nonce(nonce))
        self.assertTrue(nonces.burn_nonce(nonce))
        self.assertTrue(nonces.verify_nonce(nonce))

    def test_burned_nonce(self):
        nonce = _make_nonce(version=1)
        nonce2 = _make_nonce(version=1)
        logger.debug('nonce=%s, nonce2=%s', nonce, nonce2)

        self.assertTrue(nonces.verify_nonce(nonce))
        self.assertTrue(nonces.burn_nonce(nonce))
        self.assertTrue(nonces.verify_nonce(nonce))
        self.assertTrue(nonces.burn_nonce(nonce))

        self.assertTrue(nonces.verify_nonce(nonce2))
        self.assertTrue(nonces.burn_nonce(nonce2))
        self.assertTrue(nonces.verify_nonce(nonce2))


class TestRestrictiveNonceStore(BaseTestVerifyAndBurnNonce, TestCase):
    def setUp(self):
        nonces.set_nonce_handlers(lambda _n: False, lambda _n: False)

    def tearDown(self):
        nonces.set_nonce_handlers(nonces._default_nonce_verifier, nonces._default_nonce_burner)

    def test_valid_nonce(self):
        nonce = nonces.make_nonce()
        logger.debug('nonce=%s', nonce)

        self.assertFalse(nonces.verify_nonce(nonce))

    def test_almost_expired_nonce(self):
        nbf = _make_datetime(delta_seconds=-3)
        nonce = _make_nonce(version=1)
        logger.debug('nonce=%s, nbf=%s', nonce, nbf)

        self.assertFalse(nonces.verify_nonce(nonce, nbf))

    def test_burned_nonce(self):
        nonce = _make_nonce(version=1)
        nonce2 = _make_nonce(version=1)
        logger.debug('nonce=%s, nonce2=%s', nonce, nonce2)

        self.assertFalse(nonces.verify_nonce(nonce))
        self.assertFalse(nonces.verify_nonce(nonce))

        self.assertFalse(nonces.verify_nonce(nonce2))
        self.assertFalse(nonces.verify_nonce(nonce2))


class TestBurnWithoutVerify(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ['HOME'] = self.tmpdir
        logger.debug('writing nonce cache to %s/.oneid/used_nonces.txt', self.tmpdir)

    def test_just_burning(self):
        nonce = nonces.make_nonce()
        self.assertTrue(nonces.burn_nonce(nonce))


class TestContextualNonces(TestCase):
    def setUp(self):
        self.contexts = [uuid.uuid4() for _ in range(2)]
        self.burned_nonces = {}

        def _verify(nonce, context):
            return nonce not in self.burned_nonces or context not in self.burned_nonces[nonce]

        def _burn(nonce, context):
            if nonce not in self.burned_nonces:
                self.burned_nonces[nonce] = {}
            self.burned_nonces[nonce][context] = True
            return True

        nonces.set_nonce_handlers(_verify, _burn, True)

    def tearDown(self):
        nonces.set_nonce_handlers(nonces._default_nonce_verifier, nonces._default_nonce_burner)

    def test_valid_nonce(self):
        nonce = nonces.make_nonce()
        logger.debug('nonce=%s', nonce)

        self.assertTrue(nonces.verify_nonce(nonce, context=self.contexts[0]))
        self.assertTrue(nonces.burn_nonce(nonce, context=self.contexts[0]))
        self.assertFalse(nonces.verify_nonce(nonce, context=self.contexts[0]))

    def test_different_contexts(self):
        nonce = nonces.make_nonce()
        logger.debug('nonce=%s', nonce)

        self.assertTrue(nonces.verify_nonce(nonce, context=self.contexts[0]))
        self.assertTrue(nonces.verify_nonce(nonce, context=self.contexts[1]))

        self.assertTrue(nonces.burn_nonce(nonce, context=self.contexts[0]))
        self.assertFalse(nonces.verify_nonce(nonce, context=self.contexts[0]))
        self.assertTrue(nonces.verify_nonce(nonce, context=self.contexts[1]))

        self.assertTrue(nonces.burn_nonce(nonce, context=self.contexts[1]))
        self.assertFalse(nonces.verify_nonce(nonce, context=self.contexts[1]))

    def test_different_nonces(self):
        nonce = nonces.make_nonce()
        nonce2 = nonces.make_nonce()
        logger.debug('nonce=%s, nonce2=%s', nonce, nonce2)

        self.assertTrue(nonces.verify_nonce(nonce, context=self.contexts[0]))
        self.assertTrue(nonces.verify_nonce(nonce2, context=self.contexts[0]))

        self.assertTrue(nonces.burn_nonce(nonce, context=self.contexts[0]))
        self.assertFalse(nonces.verify_nonce(nonce, context=self.contexts[0]))
        self.assertTrue(nonces.verify_nonce(nonce2, context=self.contexts[0]))

        self.assertTrue(nonces.burn_nonce(nonce2, context=self.contexts[0]))
        self.assertFalse(nonces.verify_nonce(nonce2, context=self.contexts[0]))


class TestNonContextualNonces(BaseTestVerifyAndBurnNonce, TestCase):
    def setUp(self):
        self.contexts = [uuid.uuid4() for _ in range(2)]

    def test_burn_with_context(self):
        nonce = nonces.make_nonce()
        logger.debug('nonce=%s', nonce)

        self.assertTrue(nonces.verify_nonce(nonce))
        self.assertTrue(nonces.verify_nonce(nonce, context=self.contexts[0]))
        self.assertTrue(nonces.verify_nonce(nonce, context=self.contexts[1]))

        self.assertTrue(nonces.burn_nonce(nonce, context=self.contexts[0]))
        self.assertFalse(nonces.verify_nonce(nonce))
        self.assertFalse(nonces.verify_nonce(nonce, context=self.contexts[0]))
        self.assertFalse(nonces.verify_nonce(nonce, context=self.contexts[1]))

    def test_burn_without_context(self):
        nonce = nonces.make_nonce()
        logger.debug('nonce=%s', nonce)

        self.assertTrue(nonces.verify_nonce(nonce))
        self.assertTrue(nonces.verify_nonce(nonce, context=self.contexts[0]))
        self.assertTrue(nonces.verify_nonce(nonce, context=self.contexts[1]))

        self.assertTrue(nonces.burn_nonce(nonce))
        self.assertFalse(nonces.verify_nonce(nonce))
        self.assertFalse(nonces.verify_nonce(nonce, context=self.contexts[0]))
        self.assertFalse(nonces.verify_nonce(nonce, context=self.contexts[1]))
