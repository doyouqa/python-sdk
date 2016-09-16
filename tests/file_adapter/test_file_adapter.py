# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import logging

from unittest import TestCase
import mock

# from nose.tools import nottest

from oneid import file_adapter

logger = logging.getLogger(__name__)


_mock_implementation = mock.Mock(
    join_paths=lambda *_: 'jjj',
    file_exists=lambda *_: True,
    file_directory_exists=lambda *_: True,
    prepare_directory=lambda *_: None,
    prepare_file_directory=lambda *_: None,
    read_file=lambda *_: 'a',
    write_file=lambda *_: None,
)


@mock.patch('oneid.file_adapter._get_handler', return_value=_mock_implementation)
class TestFileAdapter(TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_join_paths(self, _):
        self.assertEqual(file_adapter.join_paths('a', 'b'), 'jjj')

    def test_file_exists(self, _):
        self.assertEqual(file_adapter.file_exists('a'), True)

    def test_file_directory_exists(self, _):
        self.assertEqual(file_adapter.file_directory_exists('a'), True)

    def test_prepare_directory(self, _):
        self.assertEqual(file_adapter.prepare_directory('a'), None)

    def test_prepare_file_directory(self, _):
        self.assertEqual(file_adapter.prepare_file_directory('a'), None)

    def test_read_file(self, _):
        self.assertEqual(file_adapter.read_file('a'), 'a')

    def test_write_file(self, _):
        self.assertEqual(file_adapter.write_file('a', 'b'), None)


class TestGetHandler(TestCase):
    """
    Dive into implementation because we have little else useful to do
    """
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_get_handler(self):
        filenames = [
            'some_file', '/some/file', '/some/other/file', '/some/dir/'
        ]
        for filename in filenames:
            self.assertIs(
                file_adapter._get_handler(filename),
                file_adapter.plain_file_handler
            )
            self.assertIs(
                file_adapter._get_handler('s3://' + filename),
                file_adapter.s3_handler
            )
            self.assertIs(
                file_adapter._get_handler('s3:' + filename),
                file_adapter.plain_file_handler
            )
            self.assertIs(
                file_adapter._get_handler('anything://' + filename),
                file_adapter.plain_file_handler
            )
