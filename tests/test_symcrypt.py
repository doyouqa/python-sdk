# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import base64
import logging

import unittest

from ntdi import symcrypt, utils

logger = logging.getLogger(__name__)


class TestEncryptDecrypt(unittest.TestCase):
    def setUp(self):
        pass

    def test_string_encryption(self):
        key = symcrypt.create_aes_key()
        data = 'Hello, Im Data'
        edata = symcrypt.aes_encrypt(data, key)
        self.assertEqual(
            utils.to_string(symcrypt.aes_decrypt(edata, key)),
            data
        )

    def test_bytes_encryption(self):
        key = symcrypt.create_aes_key()
        data = b'Hello, Im Data'
        edata = symcrypt.aes_encrypt(data, key)
        self.assertEqual(symcrypt.aes_decrypt(edata, key), data)


class TestEncryptDecryptAttributes(unittest.TestCase):
    def setUp(self):
        self.key = symcrypt.create_aes_key()
        self.data = 'hoôray!🎉'

    def test_encrypt_with_legacy(self):
        enc = symcrypt.aes_encrypt(self.data, self.key, True)
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
        enc = symcrypt.aes_encrypt(self.data, self.key, False)
        self.assertNotIn("cipher", enc)
        self.assertNotIn("mode", enc)
        self.assertNotIn("ts", enc)
        self.assertIn("header", enc)
        self.assertIn("ciphertext", enc)
        self.assertIn("tag", enc)

    def test_decrypt_with_legacy(self):
        enc = symcrypt.aes_encrypt(self.data, self.key, True)
        decrypted = utils.to_string(symcrypt.aes_decrypt(enc, self.key))
        self.assertEqual(decrypted, self.data)

    def test_decrypt_without_legacy(self):
        enc = symcrypt.aes_encrypt(self.data, self.key, False)
        decrypted = utils.to_string(symcrypt.aes_decrypt(enc, self.key))
        self.assertEqual(decrypted, self.data)

    def test_decrypt_without_legacy_follow_standard_encoding(self):
        enc = symcrypt.aes_encrypt(self.data, self.key, False)
        enc['iv'] = base64.b64encode(utils.base64url_decode(enc['iv']))
        decrypted = utils.to_string(symcrypt.aes_decrypt(enc, self.key))
        self.assertEqual(decrypted, self.data)

    def test_decrypt_only_legacy(self):
        enc = symcrypt.aes_encrypt(self.data, self.key, True)
        del enc['header']
        del enc['ciphertext']
        del enc['tag']
        decrypted = utils.to_string(symcrypt.aes_decrypt(enc, self.key))
        self.assertEqual(decrypted, self.data)

    def test_decrypt_bytes(self):
        data = utils.to_bytes(self.data)
        enc = symcrypt.aes_encrypt(data, self.key)
        decrypted = symcrypt.aes_decrypt(enc, self.key)
        self.assertEqual(decrypted, data)

    def test_decrypt_wrong_type(self):
        with self.assertRaises(ValueError):
            symcrypt.aes_decrypt(None, self.key)

        with self.assertRaises(ValueError):
            symcrypt.aes_decrypt("foo", self.key)

        with self.assertRaises(ValueError):
            symcrypt.aes_decrypt(b"foo", self.key)

        with self.assertRaises(ValueError):
            symcrypt.aes_decrypt(["foo"], self.key)

    def test_decrypt_incorrect_params(self):
        enc = {
            'cipher': 'hope',
            'mode': 'niave',
        }

        with self.assertRaises(ValueError):
            symcrypt.aes_decrypt(enc, self.key)

    def test_decrypt_invalid_tag_size(self):
        enc = symcrypt.aes_encrypt(self.data, self.key, False)
        enc['tag'] = enc['tag'][:12]

        with self.assertRaises(ValueError):
            symcrypt.aes_decrypt(enc, self.key)


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

            self.assertEqual(symcrypt.key_wrap(key, plaintext), ciphertext)
            self.assertEqual(symcrypt.key_unwrap(key, ciphertext), plaintext)
