# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import os
import tempfile
import time
import logging
from datetime import datetime
from dateutil import tz


from unittest import TestCase

from oneid import nonces

logger = logging.getLogger(__name__)


class TestMakeNonce(TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_make_nonce(self):
        nonce = nonces.make_nonce()
        self.assertRegexpMatches(
            nonce,
            r'^001'
            r'[2-9][0-9]{3}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])'
            r'T([01][0-9]|2[0-3])(:[0-5][0-9]){2}Z'
            r'[A-Za-z0-9]{6}$'
        )

    def test_uniquess_to_a_point(self):
        seen = {}

        for _ in range(10000):
            nonce = nonces.make_nonce()
            self.assertTrue(nonce not in seen)
            seen[nonce] = True


class BaseTestVerifyAndBurnNonce(object):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ['HOME'] = self.tmpdir
        logger.debug('writing nonce cache to %s/.oneid/used_nonces.txt', self.tmpdir)

    def tearDown(self):
        pass

    def test_valid_nonce(self):
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime()) + '123456'
        logger.debug('nonce=%s', nonce)

        self.assertTrue(nonces.verify_and_burn_nonce(nonce))

    def test_invalid_nonce(self):
        nonce = '002' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime()) + '123456'
        logger.debug('nonce=%s', nonce)

        self.assertFalse(nonces.verify_and_burn_nonce(nonce))

    def test_expired_nonce(self):
        now = int(time.time())
        nbf = datetime.utcfromtimestamp(now + 3).replace(tzinfo=tz.tzutc())
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime(now)) + '123456'
        logger.debug('nonce=%s, nbf=%s', nonce, nbf)

        self.assertFalse(nonces.verify_and_burn_nonce(nonce, nbf))

    def test_almost_expired_nonce(self):
        now = int(time.time())
        nbf = datetime.utcfromtimestamp(now - 3).replace(tzinfo=tz.tzutc())
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime(now)) + '123456'
        logger.debug('nonce=%s, nbf=%s', nonce, nbf)

        self.assertTrue(nonces.verify_and_burn_nonce(nonce, nbf))

    def test_future_nonce(self):
        now = int(time.time())
        then = now+((2*60)+3)   # three seconds avoids possible race condition
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime(then)) + '123456'
        logger.debug('nonce=%s', nonce)

        self.assertFalse(nonces.verify_and_burn_nonce(nonce))

    def test_almost_future_nonce(self):
        now = int(time.time())
        then = now+((2*60)-3)   # three seconds avoids possible race condition
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime(then)) + '123456'
        logger.debug('nonce=%s', nonce)

        self.assertTrue(nonces.verify_and_burn_nonce(nonce))

    def test_burned_nonce(self):
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime()) + '123456'
        nonce2 = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                       time.gmtime()) + '654321'
        logger.debug('nonce=%s, nonce2=%s', nonce, nonce2)

        self.assertTrue(nonces.verify_and_burn_nonce(nonce))
        self.assertFalse(nonces.verify_and_burn_nonce(nonce))

        self.assertTrue(nonces.verify_and_burn_nonce(nonce2))
        self.assertFalse(nonces.verify_and_burn_nonce(nonce2))


class BaseTestVerifyAndBurnNonce(BaseTestVerifyAndBurnNonce, TestCase):
    pass


class TestPermissiveNonceStore(BaseTestVerifyAndBurnNonce, TestCase):
    def setUp(self):
        nonces.set_nonce_handler(lambda _n: True)

    def tearDown(self):
        nonces.set_nonce_handler(nonces._default_nonce_handler)

    def test_burned_nonce(self):
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime()) + '123456'
        nonce2 = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                       time.gmtime()) + '654321'
        logger.debug('nonce=%s, nonce2=%s', nonce, nonce2)

        self.assertTrue(nonces.verify_and_burn_nonce(nonce))
        self.assertTrue(nonces.verify_and_burn_nonce(nonce))

        self.assertTrue(nonces.verify_and_burn_nonce(nonce2))
        self.assertTrue(nonces.verify_and_burn_nonce(nonce2))


class TestRestrictiveNonceStore(BaseTestVerifyAndBurnNonce, TestCase):
    def setUp(self):
        nonces.set_nonce_handler(lambda _n: False)

    def tearDown(self):
        nonces.set_nonce_handler(nonces._default_nonce_handler)

    def test_valid_nonce(self):
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime()) + '123456'
        logger.debug('nonce=%s', nonce)

        self.assertFalse(nonces.verify_and_burn_nonce(nonce))

    def test_almost_expired_nonce(self):
        now = int(time.time())
        nbf = datetime.utcfromtimestamp(now - 3).replace(tzinfo=tz.tzutc())
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime(now)) + '123456'
        logger.debug('nonce=%s, nbf=%s', nonce, nbf)

        self.assertFalse(nonces.verify_and_burn_nonce(nonce, nbf))

    def test_almost_future_nonce(self):
        now = int(time.time())
        then = now+((2*60)-3)   # three seconds avoids possible race condition
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime(then)) + '123456'
        logger.debug('nonce=%s', nonce)

        self.assertFalse(nonces.verify_and_burn_nonce(nonce))

    def test_burned_nonce(self):
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime()) + '123456'
        nonce2 = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                       time.gmtime()) + '654321'
        logger.debug('nonce=%s, nonce2=%s', nonce, nonce2)

        self.assertFalse(nonces.verify_and_burn_nonce(nonce))
        self.assertFalse(nonces.verify_and_burn_nonce(nonce))

        self.assertFalse(nonces.verify_and_burn_nonce(nonce2))
        self.assertFalse(nonces.verify_and_burn_nonce(nonce2))
