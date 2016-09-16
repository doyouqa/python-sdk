# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import tempfile
import logging

import boto3

from unittest import TestCase
from moto import mock_s3

# from nose.tools import nottest

from oneid import utils
from oneid.file_adapter import s3_handler

logger = logging.getLogger(__name__)


@mock_s3
class TestS3Handler(TestCase):
    def setUp(self):
        self.s3 = boto3.resource('s3')
        self.data = utils.to_bytes('Héllo!😀')
        self.bucket_name = 'somebucket'
        self.other_bucket_name = 'otherbucket'
        self.bucket = self.s3.Bucket(self.bucket_name)
        self.assertIsInstance(self.bucket.create(), dict)

        with tempfile.NamedTemporaryFile(delete=True) as tf:
            self.key = tf.name[1:]
            self.filename = 's3://{}/{}'.format(self.bucket_name, self.key)
            self.object = self.bucket.Object(self.key)
            self.object.put(Body=self.data)

    def tearDown(self):
        try:
            self.bucket.delete_objects(Objects=[{
                'Key': self.key,
            }], Quiet=True)
            self.bucket.delete()
        except:
            pass

    def test_join_paths(self):
        self.assertEqual(
            s3_handler.join_paths(self.filename, 'foo', 'bar'),
            '/'.join([self.filename, 'foo', 'bar']),
        )

    def test_file_exists(self):
        self.assertTrue(s3_handler.file_exists(self.filename))
        self.object.delete()
        logger.debug('removed %s', self.filename)
        self.assertFalse(s3_handler.file_exists(self.filename))

    def test_file_directory_exists(self):
        self.assertTrue(
            s3_handler.file_directory_exists(self.filename)
        )
        self.object.delete()
        self.assertTrue(
            s3_handler.file_directory_exists(self.filename)
        )
        self.bucket.delete()
        self.assertFalse(
            s3_handler.file_directory_exists(self.filename)
        )

    def test_prepare_directory(self):
        objectname = 's3://{}/{}'.format(self.other_bucket_name, 'something')
        self.assertFalse(s3_handler._bucket_exists(self.other_bucket_name))
        s3_handler.prepare_directory(objectname)
        self.assertTrue(s3_handler._bucket_exists(self.other_bucket_name))
        s3_handler.prepare_directory(objectname)
        self.assertTrue(s3_handler._bucket_exists(self.other_bucket_name))
        s3_handler._s3().Bucket(self.other_bucket_name).delete()

    def test_prepare_file_directory(self):
        objectname = 's3://{}/{}'.format(self.other_bucket_name, 'something')
        self.assertFalse(s3_handler._bucket_exists(self.other_bucket_name))
        s3_handler.prepare_file_directory(objectname)
        self.assertTrue(s3_handler._bucket_exists(self.other_bucket_name))
        s3_handler.prepare_file_directory(objectname)
        self.assertTrue(s3_handler._bucket_exists(self.other_bucket_name))
        s3_handler._s3().Bucket(self.other_bucket_name).delete()

    def test_read_file(self):
        with s3_handler.read_file(self.filename, True) as data:
            self.assertEqual(data, self.data)

        with s3_handler.read_file(self.filename, False) as data:
            self.assertEqual(utils.to_bytes(data), self.data)

    def _check_write_file(self, binary):
        filename = None

        with tempfile.NamedTemporaryFile(delete=True) as tf:
            key = tf.name[1:]
            filename = 's3://{}/{}'.format(self.bucket_name, key)
        self.assertIsNotNone(filename)
        s3_handler.write_file(filename, self.data, binary)

        obj = self.bucket.Object(key)
        data = obj.get()['Body'].read()

        if binary:
            self.assertEqual(data, self.data)
        else:
            self.assertEqual(utils.to_string(data), utils.to_string(self.data))

        obj.delete()

    def test_write_file(self):
        self._check_write_file(True)
        self._check_write_file(False)

    def test_invalid_filenames(self):
        bad_filenames = [
            's3:///key/here',
            's3:/bucket/isnt/right',
            's3:not.right.at.all',
            'not even a url',
        ]

        for filename in bad_filenames:
            logger.debug('filename=%s', filename)
            self.assertRaises(
                ValueError,
                s3_handler.file_exists, filename,
            )
