# -*- coding: utf-8 -*-

from __future__ import unicode_literals

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


class TestTimestampConverters(TestCase):
    def setUp(self):
        self.ts = int(time.time())
        self.dt = datetime.fromtimestamp(self.ts, tz.tzutc())
        self.iso_dt = self.dt.isoformat()

    def tearDown(self):
        pass

    def test_to_timestamp(self):
        self.assertEqual(utils.to_timestamp(self.dt), self.ts)
        self.assertEqual(utils.to_timestamp(self.iso_dt), self.ts)

    def test_from_timestamp(self):
        self.assertEqual(utils.from_timestamp(self.ts), self.dt)


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
