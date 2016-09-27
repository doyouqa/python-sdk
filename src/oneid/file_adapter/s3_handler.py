
import re
import contextlib

import boto3
import botocore

from .. import utils


def join_paths(*paths):
    return '/'.join(paths)


def file_exists(path):
    return _object_exists(*_parse_path(path))


def file_directory_exists(path):
    # any key will work if the bucket exists
    return _bucket_exists(_parse_path(path)[0])


def prepare_directory(dirname):
    bucket_name, _ = _parse_path(dirname)

    if not _bucket_exists(bucket_name):
        _s3().Bucket(bucket_name).create()


def prepare_file_directory(filename):
    prepare_directory(filename)  # only need to create the bucket


@contextlib.contextmanager
def read_file(filename, binary):
    obj = _s3().Object(*_parse_path(filename))
    # data = obj.get(**settings.AWS_S3_OBJECT_PARAMS)['Body'].read()
    data = obj.get()['Body'].read()
    yield data if binary else utils.to_string(data)


def write_file(filename, data, binary):
    obj = _s3().Object(*_parse_path(filename))
    data = data if binary else utils.to_string(data)
    obj.put(Body=data, ServerSideEncryption='AES256')  # , **settings.AWS_S3_OBJECT_PARAMS)


__s3 = None


def _s3():
    global __s3

    if not __s3:
        __s3 = boto3.resource('s3')
    return __s3


def _parse_path(path):
    match = re.match(r'^s3://(?P<bucket_name>.*?)/(?P<key_name>.*)$', path)

    if not match:
        raise ValueError('invalid s3 filename specified')

    bucket_name, key_name = match.groups()

    if not bucket_name or not key_name:
        raise ValueError('empty bucket and/or key')

    return bucket_name, key_name


def _bucket_exists(bucket_name):
    # http://boto3.readthedocs.io/en/latest/guide/migrations3.html#accessing-a-bucket

    try:
        _s3().meta.client.head_bucket(Bucket=bucket_name)
        return True
    except botocore.exceptions.ClientError as e:
        error_code = int(e.response['Error']['Code'])
        if error_code == 404:
            return False
        raise  # pragma: no cover


def _object_exists(bucket_name, key_name):

    try:
        _s3().meta.client.head_object(Bucket=bucket_name, Key=key_name)
        return True
    except botocore.exceptions.ClientError as e:
        error_code = int(e.response['Error']['Code'])
        if error_code == 404:
            return False
        raise  # pragma: no cover
