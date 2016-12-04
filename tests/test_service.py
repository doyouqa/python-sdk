# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import tempfile
import base64
import logging

import unittest
import mock

from oneid import service, session, keychain, utils

# TODO: this is starting to look like a fixture
from .test_session import TestSession, mock_request

logger = logging.getLogger(__name__)


class TestServiceCreator(unittest.TestCase):
    def setUp(self):
        mock_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.id_key_bytes
        )
        self.credentials = keychain.Credentials('me', mock_keypair)
        self.model = {
            'test_method': {
                'endpoint': 'https://myservice/my/endpoint',
                'method': 'GET',
                'arguments': {
                    'in_jwt': {
                        'location': 'jwt',
                        'required': True,
                    },
                    'in_url': {
                        'location': 'url',
                        'required': True,
                    },
                    'optional': {
                        'location': 'jwt',
                        'required': False,
                    },
                    'optional_in_url': {
                        'location': 'url',
                        'required': False,
                    },
                },
            }
        }
        self.session = session.ServerSession(self.credentials)
        self.service_creator = service.ServiceCreator()
        self.service = self.service_creator.create_service_class('svc',
                                                                 self.model,
                                                                 self.session)

    def test_created_service_class(self):
        self.assertEqual(self.service.__class__.__name__, "svc")
        self.assertTrue(hasattr(self.service, "test_method"))

    def test_service_class_with_project_creds(self):
        mock_proj_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.proj_key_bytes
        )
        proj_credentials = keychain.Credentials('proj-id', mock_proj_keypair)
        sess = session.ServerSession(self.credentials,
                                     project_credentials=proj_credentials)
        svc = self.service_creator.create_service_class('svc',
                                                        self.model,
                                                        sess)

        self.assertEqual(svc.__class__.__name__, "svc")
        self.assertTrue(hasattr(svc, "test_method"))

    @mock.patch('oneid.session.request', side_effect=mock_request)
    def test_call_created_method(self, mock_request):
        test_method = self.service.test_method(in_jwt="a",
                                               in_url="b",
                                               optional=None)
        self.assertEqual(test_method, "tested")

    @mock.patch('oneid.session.request', side_effect=mock_request)
    def test_call_created_method_with_body(self, mock_request):
        test_method = self.service.test_method(body="hello", in_url='something')
        self.assertEqual(test_method, "tested")

    @mock.patch('oneid.session.request', side_effect=mock_request)
    def test_call_created_method_missing_args(self, mock_request):
        with self.assertRaises(TypeError):
            self.service.test_method()

    @mock.patch('oneid.session.request', side_effect=mock_request)
    def test_call_created_method_with_body_missing_url_param(self, mock_request):
        with self.assertRaises(TypeError):
            self.service.test_method(body="hello")


class TestBaseService(unittest.TestCase):
    def setUp(self):
        mock_credentials = mock.Mock()
        mock_credentials.configure_mock(id='me')
        mock_session = mock.Mock()
        mock_attrs = {'identity_credentials.return_value': mock_credentials}
        mock_session.configure_mock(**mock_attrs)

        self.service = service.BaseService(mock_session, None)

    def test_form_url_params(self):
        url = '/{test_param}/end_test'
        rendered_url = self.service._format_url(url, test_param='swapped')
        self.assertEqual('/swapped/end_test', rendered_url)

    def test_form_url_attr(self):
        url = '/{test_attr}/end_test'
        self.service.test_attr = 'swapped'
        rendered_url = self.service._format_url(url)
        self.assertEqual('/swapped/end_test', rendered_url)

    def test_form_missing_param(self):
        url = '/{test_unknown}/end_test'
        self.assertRaises(TypeError, self.service._format_url, url)

    def test_string_encryption(self):
        key = service.create_aes_key()
        data = 'Hello, Im Data'
        edata = service.encrypt_attr_value(data, key)
        self.assertEqual(
            utils.to_string(service.decrypt_attr_value(edata, key)),
            data
        )

    def test_bytes_encryption(self):
        key = service.create_aes_key()
        data = b'Hello, Im Data'
        edata = service.encrypt_attr_value(data, key)
        self.assertEqual(service.decrypt_attr_value(edata, key), data)


class TestCreateSecretKey(unittest.TestCase):
    def test_basic_call(self):
        kp = service.create_secret_key()
        self.assertIsInstance(kp, keychain.Keypair)

    def test_save_to_file(self):
        fp = tempfile.NamedTemporaryFile()
        filename = fp.name
        fp.close()

        kp = service.create_secret_key(output=filename)

        with open(filename, 'rb') as f:
            key_data = f.read()
            self.assertEqual(key_data, kp.secret_as_pem)


class TestEncryptDecryptAttributes(unittest.TestCase):
    def setUp(self):
        self.key = service.create_aes_key()
        self.data = 'hoôray!🎉'

    def test_encrypt_with_legacy(self):
        enc = service.encrypt_attr_value(self.data, self.key, True)
        self.assertIn("cipher", enc)
        self.assertIn("mode", enc)
        self.assertIn("ts", enc)
        self.assertIn("header", enc)
        self.assertIn("ciphertext", enc)
        self.assertIn("tag", enc)
        self.assertEqual(enc.get("cipher"), "aes")
        self.assertEqual(enc.get("mode"), "gcm")
        self.assertEqual(enc.get("ts"), 128)

    def test_encrypt_without_legacy(self):
        enc = service.encrypt_attr_value(self.data, self.key, False)
        self.assertNotIn("cipher", enc)
        self.assertNotIn("mode", enc)
        self.assertNotIn("ts", enc)
        self.assertIn("header", enc)
        self.assertIn("ciphertext", enc)
        self.assertIn("tag", enc)

    def test_decrypt_with_legacy(self):
        enc = service.encrypt_attr_value(self.data, self.key, True)
        decrypted = utils.to_string(service.decrypt_attr_value(enc, self.key))
        self.assertEqual(decrypted, self.data)

    def test_decrypt_without_legacy(self):
        enc = service.encrypt_attr_value(self.data, self.key, False)
        decrypted = utils.to_string(service.decrypt_attr_value(enc, self.key))
        self.assertEqual(decrypted, self.data)

    def test_decrypt_without_legacy_follow_standard_encoding(self):
        enc = service.encrypt_attr_value(self.data, self.key, False)
        enc['iv'] = base64.b64encode(utils.base64url_decode(enc['iv']))
        decrypted = utils.to_string(service.decrypt_attr_value(enc, self.key))
        self.assertEqual(decrypted, self.data)

    def test_decrypt_only_legacy(self):
        enc = service.encrypt_attr_value(self.data, self.key, True)
        del enc['header']
        del enc['ciphertext']
        del enc['tag']
        decrypted = utils.to_string(service.decrypt_attr_value(enc, self.key))
        self.assertEqual(decrypted, self.data)

    def test_decrypt_bytes(self):
        data = utils.to_bytes(self.data)
        enc = service.encrypt_attr_value(data, self.key)
        decrypted = service.decrypt_attr_value(enc, self.key)
        self.assertEqual(decrypted, data)

    def test_decrypt_wrong_type(self):
        with self.assertRaises(ValueError):
            service.decrypt_attr_value(None, self.key)

        with self.assertRaises(ValueError):
            service.decrypt_attr_value("foo", self.key)

        with self.assertRaises(ValueError):
            service.decrypt_attr_value(b"foo", self.key)

        with self.assertRaises(ValueError):
            service.decrypt_attr_value(["foo"], self.key)

    def test_decrypt_incorrect_params(self):
        enc = {
            'cipher': 'hope',
            'mode': 'niave',
        }

        with self.assertRaises(ValueError):
            service.decrypt_attr_value(enc, self.key)


class TestKeyWrapUnwrap(unittest.TestCase):
    def setUp(self):
        # arbitrary set of NIST CAVP vectors via pyca/cryptography/.../KW_AD_256.txt
        self.vectors = [
            {
                'count': 21,
                'key': 'd17c69d99de8ef419806e217d2beb10c439628b0252324534c7029659f5d0d51',
                'ciphertext': '4c46d20b3ef76d466ff16049227afbfa012ab04545164310',
                'plaintext': '819e142888ea323a3f127ddc972aa23f',
            },
            {
                'count': 22,
                'key': '71e9abf9daed93b6a1565ce1e0aeecf5945bc9b65c330f853acd91b9c760ed5a',
                'ciphertext': '8e3dc40df3fe168b29dd687b557edf7539927734ad502a85',
                'plaintext': '4e7b85ac4548230362e615b6e7e081f9',
            },
            {
                'count': 23,
                'key': '2dc77923638672c4ae42886e9c11fe84767bc0bcb12dd9e46cb43d35a4d550cb',
                'ciphertext': '267fe9821e5a7981ff1d698ad7be09a50d629155ee723c73',
                'plaintext': '685b0c79c092bce176b6eb7d91eff334',
            },
        ]

    def tearDown(self):
        pass

    def test_wrap_unwrap(self):
        for vector in self.vectors:
            logger.debug('count=%s', vector['count'])
            key = bytes(bytearray.fromhex(vector['key']))
            ciphertext = bytes(bytearray.fromhex(vector['ciphertext']))
            plaintext = bytes(bytearray.fromhex(vector['plaintext']))

            self.assertEqual(service.key_wrap(key, plaintext), ciphertext)
            self.assertEqual(service.key_unwrap(key, ciphertext), plaintext)
