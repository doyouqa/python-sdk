
from . import plain_file_handler
from . import s3_handler


def join_paths(root, *paths):
    return _get_handler(root).join_paths(root, *paths)


def file_exists(path):
    return _get_handler(path).file_exists(path)


def file_directory_exists(filename):
    return _get_handler(filename).file_directory_exists(filename)


def prepare_directory(dirname):
    return _get_handler(dirname).prepare_directory(dirname)


def prepare_file_directory(filename):
    return _get_handler(filename).prepare_file_directory(filename)


def read_file(filename, binary=True):
    return _get_handler(filename).read_file(filename, binary)


def write_file(filename, data, binary=True):
    return _get_handler(filename).write_file(filename, data, binary)


def _get_handler(path):
    if path.startswith('s3://'):
        return s3_handler
    return plain_file_handler
