# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import os
import json
import uuid
import tempfile

import logging

from unittest import TestCase

# from nose.tools import nottest

from oneid import jwes, nonces, service, exceptions, utils

logger = logging.getLogger(__name__)


def _remove_secret(keypair):
    keypair._public_key = keypair.public_key
    keypair._private_key = None


def _generate_keypair(private=True):
    ret = service.create_secret_key()
    ret.identity = str(uuid.uuid4())

    if not private:
        _remove_secret(ret)

    return ret


class TestJWEs(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ['HOME'] = self.tmpdir
        nonces.set_nonce_handlers(lambda _n: True, lambda _n: True)

        self.claim_keys = ['a', 'b', 'c', 'héllo!', '😬']
        self.raw_claims = {k: 0 for k in self.claim_keys}

        self.sender_keypair = service.create_secret_key()
        self.sender_keypair.identity = str(uuid.uuid4())

        self.recipient_keypairs = []
        for _ in range(3):
            recipient_keypair = _generate_keypair()
            self.recipient_keypairs.append(recipient_keypair)
        self.jwe = jwes.make_jwe(self.raw_claims, self.sender_keypair, self.recipient_keypairs)

    def tearDown(self):
        nonces.set_nonce_handlers(nonces._default_nonce_verifier, nonces._default_nonce_burner)

    def _assertValidClaims(self, claims, expected_claim_keys=None):
        if expected_claim_keys is None:
            expected_claim_keys = self.claim_keys

        for k in expected_claim_keys + ['jti', 'nbf', 'exp']:
            self.assertIn(k, claims)

    def test_sunny_day(self):
        logger.debug('jwe=%s', self.jwe)
        jwe_json = json.loads(self.jwe)
        self.assertNotIn('d', jwe_json['unprotected']['epk'])

        for recipient_keypair in self.recipient_keypairs:
            claims = jwes.decrypt_jwe(self.jwe, recipient_keypair)
            self._assertValidClaims(claims)

    def test_skip_jsonify(self):
        self.assertIsInstance(self.jwe, str)

        claims1 = jwes.decrypt_jwe(self.jwe, self.recipient_keypairs[0])

        jwe_json = jwes.make_jwe(
            claims1, self.sender_keypair, self.recipient_keypairs, jsonify=False
        )
        self.assertIsInstance(jwe_json, dict)

        claims2 = jwes.decrypt_jwe(jwe_json, self.recipient_keypairs[0])

        self.assertDictEqual(claims1, claims2)

    def test_key_not_present(self):
        eve_keypair = _generate_keypair(False)
        with self.assertRaises(exceptions.InvalidRecipient):
            jwes.decrypt_jwe(self.jwe, eve_keypair)

    def test_protected_header_overrides(self):
        jwe_json = json.loads(self.jwe)
        jwe_json['protected'] = utils.to_string(utils.base64url_encode(json.dumps({
            "apu": utils.to_string(utils.base64url_encode('bogus')),
        })))
        jwe = json.dumps(jwe_json)

        with self.assertRaises(exceptions.DecryptionFailed):
            jwes.decrypt_jwe(jwe, self.recipient_keypairs[0])

    def test_single_recipient(self):
        jwe = jwes.make_jwe(self.raw_claims, self.sender_keypair, self.recipient_keypairs[0])

        claims = jwes.decrypt_jwe(jwe, self.recipient_keypairs[0])
        self._assertValidClaims(claims)

        with self.assertRaises(exceptions.InvalidRecipient):
            jwes.decrypt_jwe(jwe, self.recipient_keypairs[1])

    def test_anonymous_sender(self):
        with self.assertRaises(exceptions.IdentityRequired):
            sender_keypair = service.create_secret_key()
            jwes.make_jwe(self.raw_claims, sender_keypair, self.recipient_keypairs)

    def test_anonymous_recipient(self):
        with self.assertRaises(exceptions.IdentityRequired):
            self.recipient_keypairs[0].identity = None
            jwes.decrypt_jwe(self.jwe, self.recipient_keypairs[0])

    def test_decrypt_invalid_jwe(self):
        with self.assertRaises(exceptions.InvalidFormatError):
            jwes.decrypt_jwe({}, self.recipient_keypairs[0])

    def test_content_encryption_failure(self):
        jwe_json = json.loads(self.jwe)
        jwe_json['ciphertext'] = utils.to_string(utils.base64url_encode('bogus'))
        jwe = json.dumps(jwe_json)

        with self.assertRaises(exceptions.DecryptionFailed):
            jwes.decrypt_jwe(jwe, self.recipient_keypairs[0])

    def test_disallowed_claims(self):

        for claim in ['enc', 'alg', 'epk', 'apu']:
            with self.assertRaises(ValueError):
                jwes.make_jwe({claim: 'bogus'}, self.sender_keypair, self.recipient_keypairs)
