# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import os
import tempfile
import logging

from unittest import TestCase

# from nose.tools import nottest

from oneid import utils
from oneid.file_adapter import plain_file_handler

logger = logging.getLogger(__name__)


class TestPlainFileHandler(TestCase):
    def setUp(self):
        self.data = utils.to_bytes('Héllo!😀')
        self.dirname = tempfile.mkdtemp()
        logger.debug('created directory: %s', self.dirname)

        with tempfile.NamedTemporaryFile(dir=self.dirname, delete=False) as tf:
            logger.debug('created file: %s', tf.name)
            tf.write(self.data)
            self.filename = tf.name

    def tearDown(self):
        if os.path.exists(self.filename):
            os.remove(self.filename)
            logger.debug('removed file %s', self.filename)

        if os.path.exists(self.dirname):
            os.rmdir(self.dirname)
            logger.debug('removed directory %s', self.dirname)

    def test_join_paths(self):
        self.assertEqual(
            plain_file_handler.join_paths(self.dirname, 'foo', 'bar'),
            os.path.join(self.dirname, 'foo', 'bar'),
        )

    def test_file_exists(self):
        self.assertTrue(plain_file_handler.file_exists(self.filename))
        os.remove(self.filename)
        logger.debug('removed %s', self.filename)
        self.assertFalse(plain_file_handler.file_exists(self.filename))

    def test_file_directory_exists(self):
        self.assertTrue(
            plain_file_handler.file_directory_exists(self.filename)
        )
        os.remove(self.filename)
        self.assertTrue(
            plain_file_handler.file_directory_exists(self.filename)
        )
        os.rmdir(self.dirname)
        self.assertFalse(
            plain_file_handler.file_directory_exists(self.filename)
        )

    def test_prepare_directory(self):
        dirname = tempfile.mkdtemp()
        os.rmdir(dirname)

        dirname = os.path.join(dirname, 'foo', 'baz')

        self.assertFalse(os.path.exists(dirname))
        plain_file_handler.prepare_directory(dirname)
        self.assertTrue(os.path.exists(dirname))
        plain_file_handler.prepare_directory(dirname)

        os.rmdir(dirname)

    def test_prepare_file_directory(self):
        dirname = tempfile.mkdtemp()
        os.rmdir(dirname)

        filename = os.path.join(dirname, 'somefile.txt')

        self.assertFalse(os.path.exists(dirname))
        self.assertFalse(os.path.exists(filename))
        plain_file_handler.prepare_file_directory(filename)
        self.assertTrue(os.path.exists(dirname))
        self.assertFalse(os.path.exists(filename))
        plain_file_handler.prepare_file_directory(filename)
        self.assertFalse(os.path.exists(filename))

        os.rmdir(dirname)

    def test_read_file(self):
        with plain_file_handler.read_file(self.filename, True) as data:
            self.assertEqual(data, self.data)

        with plain_file_handler.read_file(self.filename, False) as data:
            self.assertEqual(utils.to_bytes(data), self.data)

    def _check_write_file(self, binary):
        filename = None

        with tempfile.NamedTemporaryFile(delete=True) as tf:
            filename = tf.name
        self.assertIsNotNone(filename)

        data = self.data if binary else 'hello'

        plain_file_handler.write_file(filename, data, binary)

        mode = 'r' + ('b' if binary else '')

        with open(filename, mode) as f:
            self.assertEqual(f.read(), data)

        os.remove(filename)

    def test_write_file(self):
        self._check_write_file(True)
        self._check_write_file(False)
