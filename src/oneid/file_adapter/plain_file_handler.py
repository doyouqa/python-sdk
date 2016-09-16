
import os
import contextlib


def join_paths(*paths):
    return os.path.join(*paths)


def file_exists(path):
    return os.path.exists(path)


def file_directory_exists(filename):
    return os.path.exists(os.path.dirname(filename))


def prepare_directory(dirname):
    if not os.path.exists(dirname):
        os.makedirs(dirname)


def prepare_file_directory(filename):
    prepare_directory(os.path.dirname(filename))


@contextlib.contextmanager
def read_file(filename, binary):
    mode = 'r' + ('b' if binary else '')

    with open(filename, mode) as f:
        yield f.read()


def write_file(filename, data, binary):
    mode = 'w' + ('b' if binary else '')

    with open(filename, mode) as f:
        f.write(data)
