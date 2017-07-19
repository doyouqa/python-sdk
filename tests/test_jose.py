# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import os
import json
import tempfile
import uuid

import logging

from unittest import TestCase

from oneid import jose, jwes, jwts, service, nonces, utils, exceptions

logger = logging.getLogger(__name__)


class TestIsJWS(TestCase):
    def setUp(self):
        # self.tmpdir = tempfile.mkdtemp()
        # os.environ['HOME'] = self.tmpdir
        # nonces.set_nonce_handlers(lambda _n: True, lambda _n: True)

        self.claim_keys = ['a', 'b', 'c', 'héllo!', '😬']
        self.raw_claims = {k: 0 for k in self.claim_keys}

        self.keypair = service.create_secret_key()
        self.keypair.identity = str(uuid.uuid4())

        self.jws = jwts.make_jws(self.raw_claims, self.keypair)
        self.jwt = jwts.make_jwt(self.raw_claims, self.keypair)

    def tearDown(self):
        # nonces.set_nonce_handlers(nonces._default_nonce_verifier, nonces._default_nonce_burner)
        pass

    def test_with_jws(self):
        self.assertTrue(jose.is_jws(self.jws))
        self.assertTrue(jose.is_jws(json.loads(self.jws)))
        self.assertFalse(jose.is_jws([]))
        self.assertFalse(jose.is_jws("[]"))

        for k in ['payload', 'signatures']:
            jws_json = json.loads(self.jws)
            del jws_json[k]
            self.assertFalse(jose.is_jws(json.dumps(jws_json)))

    def test_with_jwt(self):
        self.assertTrue(jose.is_jws(self.jwt))


class TestIsJWE(TestCase):
    def setUp(self):
        # self.tmpdir = tempfile.mkdtemp()
        # os.environ['HOME'] = self.tmpdir
        # nonces.set_nonce_handlers(lambda _n: True, lambda _n: True)

        self.claim_keys = ['a', 'b', 'c', 'héllo!', '😬']
        self.raw_claims = {k: 0 for k in self.claim_keys}

        self.sender_keypair = service.create_secret_key()
        self.sender_keypair.identity = str(uuid.uuid4())

        self.recipient_keypair = service.create_secret_key()
        self.recipient_keypair.identity = str(uuid.uuid4())

        self.jwe = jwes.make_jwe(self.raw_claims, self.sender_keypair, self.recipient_keypair)

    def tearDown(self):
        # nonces.set_nonce_handlers(nonces._default_nonce_verifier, nonces._default_nonce_burner)
        pass

    def test_is_jwe(self):
        self.assertTrue(jose.is_jwe(self.jwe))
        self.assertTrue(jose.is_jwe(json.loads(self.jwe)))
        self.assertFalse(jose.is_jwe([]))
        self.assertFalse(jose.is_jwe("[]"))

        for k in ['iv', 'ciphertext', 'tag', 'recipients']:
            jwe_json = json.loads(self.jwe)
            del jwe_json[k]
            self.assertFalse(jose.is_jwe(json.dumps(jwe_json)))


class TestJWESharedHeader(TestCase):
    def setUp(self):
        self.claim_keys = ['a', 'b', 'c', 'héllo!', '😬']
        self.raw_claims = {k: 0 for k in self.claim_keys}

    def tearDown(self):
        pass

    def test_unprotected(self):
        jwe = {
            'iv': '1234',
            'ciphertext': 'hello',
            'tag': '4567',
            'recipients': [{}],
            'unprotected': self.raw_claims,
        }
        self.assertDictEqual(jose.get_jwe_shared_header(jwe), self.raw_claims)

    def test_protected(self):
        jwe = {
            'iv': '1234',
            'ciphertext': 'hello',
            'tag': '4567',
            'recipients': [{}],
            'protected': utils.base64url_encode(json.dumps(self.raw_claims)),
        }
        self.assertDictEqual(jose.get_jwe_shared_header(jwe), self.raw_claims)

    def test_protected_overrides(self):
        jwe = {
            'iv': '1234',
            'ciphertext': 'hello',
            'tag': '4567',
            'recipients': [{}],
            'unprotected': {k: 'bogus' for k in self.claim_keys},
            'protected': utils.base64url_encode(json.dumps(self.raw_claims)),
        }
        self.assertDictEqual(jose.get_jwe_shared_header(jwe), self.raw_claims)

    def test_invalid_jwe(self):
        with self.assertRaises(exceptions.InvalidFormatError):
            jose.get_jwe_shared_header({})


class TestNormalizeClaims(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ['HOME'] = self.tmpdir
        nonces.set_nonce_handlers(lambda _n: True, lambda _n: True)

        self.claim_keys = ['a', 'b', 'c', 'héllo!', '😬']
        self.raw_claims = {k: 0 for k in self.claim_keys}

        self.standard_claims = {
            'iss': str(uuid.uuid4()),
            'jti': nonces.make_nonce(),
            'nbf': 12345,
            'exp': 12346,
        }
        self.dummy_jwe = {
            'iv': '1234',
            'ciphertext': 'hello',
            'tag': '4567',
            'recipients': [{}],
            'unprotected': self.standard_claims,
        }

    def tearDown(self):
        nonces.set_nonce_handlers(nonces._default_nonce_verifier, nonces._default_nonce_burner)

    def test_sunny_day(self):
        claims = jose.normalize_claims(self.raw_claims)

        self.assertIsInstance(claims, dict)

        for k in self.claim_keys + ['jti', 'nbf', 'exp']:
            self.assertIn(k, claims)

        self.assertNotIn('iss', claims)

        self.assertEqual(utils.to_timestamp(claims['jti'][3:-6]), claims['exp'])
        self.assertGreater(claims['exp'], claims['nbf'])

    def test_sunny_day_with_issuer(self):
        iss = 'me'
        claims = jose.normalize_claims(self.raw_claims, iss)

        self.assertIn('iss', claims)
        self.assertEqual(claims['iss'], iss)

    def test_existing_standard_claims(self):
        self.raw_claims.update(self.standard_claims)
        claims = jose.normalize_claims(self.raw_claims)

        for claim, value in self.standard_claims.items():
            self.assertIn(claim, claims)
            self.assertEqual(claims[claim], value)

    def test_existing_standard_claims_in_jwe(self):
        claims = jose.normalize_claims(self.dummy_jwe)

        for claim, value in self.standard_claims.items():
            self.assertIn(claim, claims)
            self.assertEqual(claims[claim], value)

    def test_existing_standard_claims_in_jwe_with_issuer(self):
        iss = 'me'
        claims = jose.normalize_claims(self.dummy_jwe, iss)

        self.assertIn('iss', claims)
        self.assertEqual(claims['iss'], iss)

    def test_using_existing_expiration_in_nonce(self):
        datestr = '2016-12-03T15:12:15Z'
        exp = utils.to_timestamp(datestr)

        self.raw_claims.update({'exp': exp})
        claims = jose.normalize_claims(self.raw_claims)

        self.assertIn('jti', claims)
        self.assertEqual(claims['jti'][3:-6], datestr)

    def test_using_nonce_expiration_in_exp(self):
        datestr = '2016-12-03T10:12:15Z'
        exp = utils.to_timestamp(datestr)
        nonce = '002' + datestr + 'ABC123'

        self.raw_claims.update({'jti': nonce})
        claims = jose.normalize_claims(self.raw_claims)

        self.assertIn('exp', claims)
        self.assertEqual(claims['exp'], exp)

    def test_using_v001_nonce(self):
        datestr = '2016-12-03T10:12:15Z'
        exp = utils.to_timestamp(datestr)
        nonce = '001' + datestr + 'ABC123'

        self.raw_claims.update({'jti': nonce})
        claims = jose.normalize_claims(self.raw_claims)

        self.assertIn('exp', claims)
        self.assertNotEqual(claims['exp'], exp)

    def test_using_invalid_nonce(self):
        nonce = '002'

        self.raw_claims.update({'jti': nonce})
        claims = jose.normalize_claims(self.raw_claims)

        self.assertIn('jti', claims)
        self.assertEqual(claims['jti'], nonce)


class TestAsDict(TestCase):

    def test_as_dict(self):
        obj = {
            'a': 1,
        }
        obj_json = json.dumps(obj)

        self.assertDictEqual(obj, jose.as_dict(obj_json))
        self.assertDictEqual(obj, jose.as_dict(obj))
