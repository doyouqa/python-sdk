# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import tempfile
import uuid
import base64
import logging
import unittest

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from oneid import keychain, service, utils, exceptions

logger = logging.getLogger(__name__)


class TestCredentials(unittest.TestCase):
    def setUp(self):
        self.uuid = uuid.uuid4()
        self.keypair = service.create_secret_key()

    def test_basic_object(self):
        creds = keychain.Credentials(self.uuid, self.keypair)
        self.assertEqual(creds.id, self.uuid)
        self.assertEqual(creds.keypair, self.keypair)

    def test_invalid_keypair(self):
        with self.assertRaises(ValueError):
            keychain.Credentials(self.uuid, None)


class TestProjectCredentials(TestCredentials):
    def setUp(self):
        super(TestProjectCredentials, self).setUp()
        self.encryption_key = os.urandom(32)
        self.data = 'super 🔥data'
        self.project_credentials = keychain.ProjectCredentials(
            self.uuid,
            self.keypair,
            self.encryption_key
        )

    def test_encrypt(self):
        enc = self.project_credentials.encrypt(self.data)
        self.assertIn("cipher", enc)
        self.assertIn("mode", enc)
        self.assertIn("ts", enc)
        self.assertEqual(enc.get("cipher"), "aes")
        self.assertEqual(enc.get("mode"), "gcm")
        self.assertEqual(enc.get("ts"), 128)

        cleartext = utils.to_string(
            self.project_credentials.decrypt(enc['ct'], enc['iv'])
        )
        self.assertEqual(cleartext, self.data)

    def test_encrypt_bytes(self):
        data = ['string', b'bytes']

        for text in data:
            logger.debug('enc/dec %s', text)
            enc = self.project_credentials.encrypt(text)
            cleartext = utils.to_string(
                self.project_credentials.decrypt(enc['ct'], enc['iv'])
            )
            self.assertEqual(cleartext, utils.to_string(text))

    def test_decrypt_dict(self):
        enc = self.project_credentials.encrypt(self.data)

        cleartext = utils.to_string(self.project_credentials.decrypt(enc))
        self.assertEqual(cleartext, self.data)

    def test_decrypt_dict_invalid(self):
        with self.assertRaises(ValueError):
            self.project_credentials.decrypt({})
        with self.assertRaises(ValueError):
            self.project_credentials.decrypt(
                {'cipher': 'BES', 'mode': 'gcm',
                 'ts': 128, 'iv': 'aa', 'ct': 'aa'}
            )
        with self.assertRaises(ValueError):
            self.project_credentials.decrypt(
                {'cipher': 'aes', 'mode': 'HCM',
                 'ts': 128, 'iv': 'aa', 'ct': 'aa'}
            )
        with self.assertRaises(ValueError):
            self.project_credentials.decrypt(
                {
                    'cipher': 'aes', 'mode': 'gcm',
                    'ts': 129, 'iv': 'aa', 'ct': 'aa'
                }
            )

    def test_decrypt_no_iv(self):
        with self.assertRaises(ValueError):
            self.project_credentials.decrypt("aa")

        with self.assertRaises(ValueError):
            self.project_credentials.decrypt("aa", None)


class TestKeypair(unittest.TestCase):
    BASE_PATH = os.path.dirname(__file__)
    x509_PATH = os.path.join(BASE_PATH, 'x509')

    def test_load_pem_path(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        keypair = keychain.Keypair.from_secret_pem(path=pem_path)
        self.assertIsInstance(keypair, keychain.Keypair)

    def test_load_pem_path_pkcs8(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_pkcs8_private_key.pem')
        keypair = keychain.Keypair.from_secret_pem(path=pem_path)
        self.assertIsInstance(keypair, keychain.Keypair)

    def test_load_pem_path_missing(self):
        pem_path = None
        with tempfile.NamedTemporaryFile(suffix='.pem') as tf:
            pem_path = tf.name
        keypair = keychain.Keypair.from_secret_pem(path=pem_path)
        self.assertIsNone(keypair)

    def test_load_pem_bytes(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        with open(pem_path, 'rb') as f:
            pem_data = f.read()
            keypair = keychain.Keypair.from_secret_pem(key_bytes=pem_data)
            self.assertIsInstance(keypair, keychain.Keypair)

    def test_load_pem_bytes_pkcs8(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_pkcs8_private_key.pem')
        with open(pem_path, 'rb') as f:
            pem_data = f.read()
            keypair = keychain.Keypair.from_secret_pem(key_bytes=pem_data)
            self.assertIsInstance(keypair, keychain.Keypair)

    def test_load_pem_public_path(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_public_key.pem')
        keypair = keychain.Keypair.from_public_pem(path=pem_path)
        self.assertIsInstance(keypair, keychain.Keypair)

    def test_load_public_pem_bytes(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_public_key.pem')
        with open(pem_path, 'rb') as f:
            pem_data = f.read()
            keypair = keychain.Keypair.from_public_pem(key_bytes=pem_data)
            self.assertIsInstance(keypair, keychain.Keypair)

    def test_load_public_pem_path_missing(self):
        pem_path = None
        with tempfile.NamedTemporaryFile(suffix='.pem') as tf:
            pem_path = tf.name

        keypair = keychain.Keypair.from_public_pem(path=pem_path)
        self.assertIsNone(keypair)

    def test_load_der_bytes(self):
        der_path = os.path.join(self.x509_PATH, 'ec_sha256.der')
        with open(der_path, 'rb') as f:
            der_data = f.read()
            keypair = keychain.Keypair.from_secret_der(der_data)
            self.assertIsInstance(keypair, keychain.Keypair)

    def test_export_pem(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        with open(pem_path, 'rb') as f:
            pem_bytes = f.read()
            token = keychain.Keypair.from_secret_pem(key_bytes=pem_bytes)
            self.assertEqual(token.secret_as_pem, pem_bytes)

    def test_export_der(self):
        der_path = os.path.join(self.x509_PATH, 'ec_sha256.der')
        with open(der_path, 'rb') as f:
            der_bytes = f.read()
            token = keychain.Keypair.from_secret_der(der_bytes)
            self.assertEqual(token.secret_as_der, der_bytes)

    def test_sign_verify(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        with open(pem_path, 'rb') as f:
            pem_bytes = f.read()
            token = keychain.Keypair.from_secret_pem(key_bytes=pem_bytes)
            signature = token.sign(b'MESSAGE')
            self.assertTrue(token.verify(b"MESSAGE", signature))

    def test_public_key(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_public_key.pem')
        pubkeypair = keychain.Keypair.from_public_pem(path=pem_path)
        self.assertIsInstance(pubkeypair.public_key, EllipticCurvePublicKey)

        pem_path = os.path.join(self.x509_PATH, 'ec_sha256.pem')
        seckeypair = keychain.Keypair.from_secret_pem(path=pem_path)
        self.assertIsInstance(seckeypair.public_key, EllipticCurvePublicKey)

        # for branch coverage
        nullkeypair = keychain.Keypair()
        self.assertIsNone(nullkeypair.public_key)

    def test_public_key_der(self):
        der = base64.b64decode(
            'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJLzzbuz2tRnLFlOL+6bTX6giVavA'
            'sc6NDFFT0IMCd2ibTTNUDDkFGsgq0cH5JYPg/6xUlMBFKrWYe3yQ4has9w=='
        )
        keypair = keychain.Keypair.from_public_der(der)
        self.assertEqual(keypair.public_key_der, der)

    def test_public_key_pem(self):
        pem_path = os.path.join(self.x509_PATH, 'ec_public_key.pem')
        with open(pem_path, 'rb') as f:
            pem = f.read()
            keypair = keychain.Keypair.from_public_pem(pem)
            self.assertEqual(keypair.public_key_pem, pem)

    def test_private_jwk(self):
        keypair = service.create_secret_key()
        jwk = keypair.jwk
        self.assertIn('kty', jwk)
        self.assertIn('crv', jwk)
        self.assertIn('x', jwk)
        self.assertIn('y', jwk)
        self.assertIn('d', jwk)

        self.assertNotIn('kid', jwk)

        self.assertEqual(jwk['kty'], 'EC')
        self.assertEqual(jwk['crv'], 'P-256')

        self.assertEqual(jwk, keypair.jwk_private)
        self.assertNotEqual(jwk, keypair.jwk_public)

    def test_jwk_with_identity(self):
        keypair = service.create_secret_key()
        jwk = keypair.jwk

        self.assertNotIn('kid', jwk)

        identity = str(uuid.uuid4())
        keypair.identity = identity

        jwk = keypair.jwk
        self.assertIn('kid', jwk)

        self.assertEqual(identity, jwk['kid'])

    def test_public_jwk(self):
        der = base64.b64decode(
            'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJLzzbuz2tRnLFlOL+6bTX6giVavA'
            'sc6NDFFT0IMCd2ibTTNUDDkFGsgq0cH5JYPg/6xUlMBFKrWYe3yQ4has9w=='
        )
        keypair = keychain.Keypair.from_public_der(der)
        jwk = keypair.jwk
        self.assertIn('kty', jwk)
        self.assertIn('crv', jwk)
        self.assertIn('x', jwk)
        self.assertIn('y', jwk)
        self.assertNotIn('d', jwk)

        self.assertNotIn('kid', jwk)

        self.assertEqual(jwk['kty'], 'EC')
        self.assertEqual(jwk['crv'], 'P-256')

        self.assertEqual(jwk, keypair.jwk_public)

        with self.assertRaises(exceptions.InvalidFormatError):
            keypair.jwk_private

    def test_from_private_jwk(self):
        keypair = service.create_secret_key()
        keypair2 = keychain.Keypair.from_jwk(keypair.jwk)
        self.assertEqual(keypair.secret_as_der, keypair2.secret_as_der)
        self.assertEqual(keypair.public_key_der, keypair2.public_key_der)

    def test_from_private_jwk_with_identity(self):
        keypair = service.create_secret_key()
        jwk = keypair.jwk

        keypair2 = keychain.Keypair.from_jwk(jwk)
        self.assertIsNone(keypair2.identity)

        identity = str(uuid.uuid4())
        jwk['kid'] = identity

        keypair3 = keychain.Keypair.from_jwk(jwk)
        self.assertIsNotNone(keypair3.identity)
        self.assertEqual(identity, keypair3.identity)

    def test_from_public_jwk(self):
        der = base64.b64decode(
            'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJLzzbuz2tRnLFlOL+6bTX6giVavA'
            'sc6NDFFT0IMCd2ibTTNUDDkFGsgq0cH5JYPg/6xUlMBFKrWYe3yQ4has9w=='
        )
        keypair = keychain.Keypair.from_public_der(der)
        keypair2 = keychain.Keypair.from_jwk(keypair.jwk)
        self.assertEqual(keypair.public_key_der, keypair2.public_key_der)

    def test_from_invalid_jwk_type(self):
        keypair = service.create_secret_key()
        jwk = keypair.jwk
        jwk['kty'] = 'RSA'
        with self.assertRaises(ValueError):
            keypair = keychain.Keypair.from_jwk(jwk)

    def test_from_invalid_jwk_curve(self):
        keypair = service.create_secret_key()
        jwk = keypair.jwk
        jwk['crv'] = 'P-384'
        with self.assertRaises(ValueError):
            keypair = keychain.Keypair.from_jwk(jwk)
