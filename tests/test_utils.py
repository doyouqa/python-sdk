# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import os
import tempfile
import time
import logging
from datetime import datetime
from dateutil import tz


from unittest import TestCase

from oneid import utils

logger = logging.getLogger(__name__)


class TestBytesStringConverters(TestCase):
    def setUp(self):
        self.bytes_thing = b'hello\xf0\x9f\xa4\x94'
        self.str_thing = 'hello🤔'

    def tearDown(self):
        pass

    def test_to_bytes(self):
        self.assertEqual(self.bytes_thing, utils.to_bytes(self.str_thing))
        self.assertEqual(self.bytes_thing, utils.to_bytes(self.bytes_thing))

    def test_to_string(self):
        self.assertEqual(self.str_thing, utils.to_string(self.str_thing))
        self.assertEqual(self.str_thing, utils.to_string(self.bytes_thing))


class TestBase64URL(TestCase):
    def setUp(self):
        self.pairs = (
            ('hello🤔', b'aGVsbG_wn6SU'),
            ('something 0', b'c29tZXRoaW5nIDA'),
            ('something 123', b'c29tZXRoaW5nIDEyMw'),
        )

    def tearDown(self):
        pass

    def test_encode(self):
        for s, b in self.pairs:
            self.assertEqual(utils.base64url_encode(s), b)

    def test_decode(self):
        for s, b in self.pairs:
            self.assertEqual(utils.base64url_decode(b).decode('utf-8'), s)


class TestMakeNonce(TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_make_nonce(self):
        nonce = utils.make_nonce()
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
            nonce = utils.make_nonce()
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

        self.assertTrue(utils.verify_and_burn_nonce(nonce))

    def test_invalid_nonce(self):
        nonce = '002' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime()) + '123456'
        logger.debug('nonce=%s', nonce)

        self.assertFalse(utils.verify_and_burn_nonce(nonce))

    def test_expired_nonce(self):
        now = int(time.time())
        nbf = datetime.utcfromtimestamp(now + 3).replace(tzinfo=tz.tzutc())
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime(now)) + '123456'
        logger.debug('nonce=%s, nbf=%s', nonce, nbf)

        self.assertFalse(utils.verify_and_burn_nonce(nonce, nbf))

    def test_almost_expired_nonce(self):
        now = int(time.time())
        nbf = datetime.utcfromtimestamp(now - 3).replace(tzinfo=tz.tzutc())
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime(now)) + '123456'
        logger.debug('nonce=%s, nbf=%s', nonce, nbf)

        self.assertTrue(utils.verify_and_burn_nonce(nonce, nbf))

    def test_future_nonce(self):
        now = int(time.time())
        then = now+((2*60)+3)   # three seconds avoids possible race condition
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime(then)) + '123456'
        logger.debug('nonce=%s', nonce)

        self.assertFalse(utils.verify_and_burn_nonce(nonce))

    def test_almost_future_nonce(self):
        now = int(time.time())
        then = now+((2*60)-3)   # three seconds avoids possible race condition
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime(then)) + '123456'
        logger.debug('nonce=%s', nonce)

        self.assertTrue(utils.verify_and_burn_nonce(nonce))

    def test_burned_nonce(self):
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime()) + '123456'
        nonce2 = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                       time.gmtime()) + '654321'
        logger.debug('nonce=%s, nonce2=%s', nonce, nonce2)

        self.assertTrue(utils.verify_and_burn_nonce(nonce))
        self.assertFalse(utils.verify_and_burn_nonce(nonce))

        self.assertTrue(utils.verify_and_burn_nonce(nonce2))
        self.assertFalse(utils.verify_and_burn_nonce(nonce2))


class BaseTestVerifyAndBurnNonce(BaseTestVerifyAndBurnNonce, TestCase):
    pass


class TestPermissiveNonceStore(BaseTestVerifyAndBurnNonce, TestCase):
    def setUp(self):
        utils.set_nonce_handler(lambda _n: True)

    def tearDown(self):
        utils.set_nonce_handler(utils._default_nonce_handler)

    def test_burned_nonce(self):
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime()) + '123456'
        nonce2 = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                       time.gmtime()) + '654321'
        logger.debug('nonce=%s, nonce2=%s', nonce, nonce2)

        self.assertTrue(utils.verify_and_burn_nonce(nonce))
        self.assertTrue(utils.verify_and_burn_nonce(nonce))

        self.assertTrue(utils.verify_and_burn_nonce(nonce2))
        self.assertTrue(utils.verify_and_burn_nonce(nonce2))


class TestRestrictiveNonceStore(BaseTestVerifyAndBurnNonce, TestCase):
    def setUp(self):
        utils.set_nonce_handler(lambda _n: False)

    def tearDown(self):
        utils.set_nonce_handler(utils._default_nonce_handler)

    def test_valid_nonce(self):
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime()) + '123456'
        logger.debug('nonce=%s', nonce)

        self.assertFalse(utils.verify_and_burn_nonce(nonce))

    def test_almost_expired_nonce(self):
        now = int(time.time())
        nbf = datetime.utcfromtimestamp(now - 3).replace(tzinfo=tz.tzutc())
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime(now)) + '123456'
        logger.debug('nonce=%s, nbf=%s', nonce, nbf)

        self.assertFalse(utils.verify_and_burn_nonce(nonce, nbf))

    def test_almost_future_nonce(self):
        now = int(time.time())
        then = now+((2*60)-3)   # three seconds avoids possible race condition
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime(then)) + '123456'
        logger.debug('nonce=%s', nonce)

        self.assertFalse(utils.verify_and_burn_nonce(nonce))

    def test_burned_nonce(self):
        nonce = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime()) + '123456'
        nonce2 = '001' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                       time.gmtime()) + '654321'
        logger.debug('nonce=%s, nonce2=%s', nonce, nonce2)

        self.assertFalse(utils.verify_and_burn_nonce(nonce))
        self.assertFalse(utils.verify_and_burn_nonce(nonce))

        self.assertFalse(utils.verify_and_burn_nonce(nonce2))
        self.assertFalse(utils.verify_and_burn_nonce(nonce2))
