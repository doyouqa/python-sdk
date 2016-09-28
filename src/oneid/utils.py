"""
Helpful utility functions
"""
from __future__ import unicode_literals
import six

import base64
import logging

logger = logging.getLogger(__name__)


def to_bytes(data):
    return data.encode('utf-8') if isinstance(data, six.text_type) else data


def to_string(data):
    return data if isinstance(data, six.text_type) else data.decode('utf-8')


def base64url_encode(msg):
    """
    Default b64_encode adds padding, jwt spec removes padding
    :param input:
    :type input: string or bytes
    :return: base64 en
    :rtype: bytes
    """
    encoded_input = base64.urlsafe_b64encode(to_bytes(msg))
    stripped_input = to_bytes(to_string(encoded_input).replace('=', ''))
    return stripped_input


def base64url_decode(msg):
    """
    JWT spec doesn't allow padding characters. base64url_encode removes them,
    base64url_decode, adds them back in before trying to base64 decode the message

    :param msg: URL safe base64 message
    :type msg: string or bytes
    :return: decoded data
    :rtype: bytes
    """
    bmsg = to_bytes(msg)
    pad = len(bmsg) % 4
    if pad > 0:
        bmsg += b'=' * (4 - pad)

    return base64.urlsafe_b64decode(bmsg)
