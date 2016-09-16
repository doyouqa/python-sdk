# -*- coding: utf-8 -*-

"""
Provides useful functions for interacting with the oneID API, including creation of
keys, etc.
"""
from __future__ import unicode_literals

import os
import base64
import re
import logging

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization \
    import Encoding, PrivateFormat, NoEncryption

from .keychain import Keypair
from . import jwts
from . import utils
from . import file_adapter

logger = logging.getLogger(__name__)


AUTHENTICATION_ENDPOINT = 'http://developer-portal.oneid.com/api/{project}/authenticate'


class ServiceCreator(object):
    """
    Read yaml file and add methods dynamically from file
    Created by Session
    """
    def create_service_class(self, service_name, service_model, session, **kwargs):
        """
        Service Model is either user, server or edge_device
        """
        class_attrs = self._create_methods(service_model, **kwargs)
        cls = type(str(service_name), (BaseService,), class_attrs)

        return cls(session, kwargs.get('project_credentials'))

    def _create_methods(self, service_model, **kwargs):
        """
        :param service_model:
        :return: Dictionary of class attributes
        """
        base_url = os.environ.get('ONEID_API_SERVER_BASE_URL', kwargs.get('base_url', ''))

        methods = dict()
        for method_name, method_values in service_model.items():
            required_jwt = []
            all_jwt = []
            required_url = []
            all_url = []

            for arg_name, arg_properties in method_values['arguments'].items():
                if arg_properties['location'] == 'jwt':
                    all_jwt.append(arg_name)
                    if arg_properties['required'] is True:
                        required_jwt.append(arg_name)
                if arg_properties['location'] == 'url':
                    all_url.append(arg_name)
                    if arg_properties['required'] is True:
                        required_url.append(arg_name)

            absolute_url = '{base}{endpoint}'.format(base=base_url,
                                                     endpoint=method_values['endpoint'])

            methods[method_name] = self._create_api_method(method_name,
                                                           absolute_url,
                                                           method_values['method'],
                                                           all_body_args=all_jwt,
                                                           required_body_args=required_jwt,
                                                           all_url_args=all_url,
                                                           required_url_args=required_url,
                                                           )
        return methods

    def _create_api_method(self, name,
                           endpoint, http_method,
                           all_body_args, required_body_args,
                           all_url_args, required_url_args,
                           ):
        """
        Add methods to session dynamically from yaml file

        :param method_name: method that will be called
        """
        def _api_call(self, *args, **kwargs):
            if kwargs.get('body') is None:
                # if the body isn't specified, check for
                # required body arguments
                for required in required_body_args:
                    if required not in kwargs:
                        raise TypeError('Missing Required Keyword Argument:'
                                        ' %s' % required)
                kwargs.update(body_args=all_body_args)
            for required in required_url_args:
                if required not in kwargs:
                    raise TypeError('Missing Required URL Argument: %s' % required)
            return self._make_api_request(endpoint, http_method, **kwargs)

        _api_call.__name__ = str(name)
        return _api_call


class BaseService(object):
    """
    Dynamically loaded by data files.
    """
    def __init__(self, session, project_credentials=None):
        """
        Create a new Service

        :param session: :class:`oneid.session.Session` instance
        """
        self.session = session

        self.project_credentials = None
        if hasattr(self.session, 'project_credentials') and self.session.project_credentials:
            self.project_credentials = self.session.project_credentials

        self.identity = self.session.identity_credentials.id
        self.credentials = self.session.identity_credentials

        if self.project_credentials and self.project_credentials.id:
            self.project_id = self.project_credentials.id

    def _format_url(self, url_template, **kwargs):
        """
        Url from yaml may require formatting

        :Example:

            /project/{project_id}
            >>> /project/abc-123

        :param url_template: url with arguments that need replaced by vars
        :param params: Dictionary lookup to replace url arguments with
        :return: absolute url
        """
        encoded_params = dict()
        url_args = re.findall(r'{(\w+)}', url_template)
        for url_arg in url_args:
            if url_arg in kwargs:
                encoded_params[url_arg] = kwargs[url_arg]
            elif hasattr(self, url_arg):
                # Check if the argument is a class attribute (i.e. project_id)
                encoded_params[url_arg] = getattr(self, url_arg)
            else:
                raise TypeError('Missing URL argument %s' % url_arg)
        return url_template.format(**encoded_params)

    def _make_api_request(self, endpoint, http_method, **kwargs):
        """
        Convenience method to make HTTP requests and handle responses/error codes

        :param endpoint: URL to the resource
        :param http_method: HTTP method, GET, POST, PUT, DELETE
        :param kwargs: Params to pass to the body or url
        """
        # Split the params based on their type (url or jwt)
        url = self._format_url(endpoint, **kwargs)

        if kwargs.get('body_args'):
            claims = {arg: kwargs[arg] for arg in kwargs.get('body_args')}
            jwt = jwts.make_jwt(claims, self.credentials.keypair)
            return self.session.service_request(http_method, url, body=jwt)
        else:
            # Replace the entire body with kwargs['body'] (if present)
            return self.session.service_request(http_method, url, body=kwargs.get('body'))


def create_secret_key(output=None):
    """
    Create a secret key and save it to a secure location

    :param output: Path to save the secret key
    :return: oneid.keychain.Keypair
    """
    secret_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    secret_key_bytes = secret_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    # Save the secret key bytes to a secure file
    if output and file_adapter.file_directory_exists(output):
        file_adapter.write_file(output, secret_key_bytes)

    return Keypair.from_secret_pem(key_bytes=secret_key_bytes)


def create_aes_key():
    """
    Create an AES256 key for symmetric encryption

    :return: Encryption key bytes
    """
    return os.urandom(32)


def encrypt_attr_value(attr_value, aes_key):
    """
    Convenience method to encrypt attribute properties

    :param attr_value: plain text (string or bytes) that you want encrypted
    :param aes_key: symmetric key to encrypt attribute value with
    :return: Dictionary with base64 encoded cipher text and base 64 encoded iv
    """
    iv = os.urandom(16)
    cipher_alg = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher_alg.encryptor()
    encr_value = encryptor.update(utils.to_bytes(attr_value)) + encryptor.finalize()
    encr_value_b64 = base64.b64encode(encr_value + encryptor.tag)
    iv_b64 = base64.b64encode(iv)
    return {'cipher': 'aes', 'mode': 'gcm', 'ts': 128, 'iv': iv_b64, 'ct': encr_value_b64}


def decrypt_attr_value(attr_ct, aes_key):
    """
    Convenience method to decrypt attribute properties

    :param attr_ct: Dictionary with base64 encoded cipher text and base 64 encoded iv
    :param aes_key: symmetric key to decrypt attribute value with
    :return: plaintext bytes
    """
    if not isinstance(attr_ct, dict) or \
            attr_ct.get('cipher', 'aes') != 'aes' or \
            attr_ct.get('mode', 'gcm') != 'gcm':

        raise ValueError('invalid encrypted attribute')

    iv = base64.b64decode(attr_ct['iv'])
    tag_ct = base64.b64decode(attr_ct['ct'])
    ts = attr_ct.get('ts', 64) // 8
    tag = tag_ct[-ts:]
    ct = tag_ct[:-ts]
    cipher_alg = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag, min_tag_length=8),
        backend=default_backend()
    )
    decryptor = cipher_alg.decryptor()
    return decryptor.update(ct) + decryptor.finalize()
