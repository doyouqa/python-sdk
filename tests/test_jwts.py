# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import os
import tempfile
import time
import base64
import uuid
import json
from datetime import datetime, timedelta
from dateutil import parser, tz

import logging

from unittest import TestCase

# from nose.tools import nottest

from oneid import service, keychain, jwts, nonces, utils, exceptions

logger = logging.getLogger(__name__)

MSGS = [
    'hello there',
    'héllo!',
    '😬',
    '😬' * 2 ** 20,  # 1M
]


class TestJWTs(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ['HOME'] = self.tmpdir
        nonces.set_nonce_handlers(lambda _n: True, lambda _n: True)
        self.keypair = service.create_secret_key()

    def tearDown(self):
        nonces.set_nonce_handlers(
            nonces._default_nonce_verifier, nonces._default_nonce_burner)

    def _create_and_verify_good_jwt(self, claims, keypair=None):
        keypair = keypair or self.keypair
        jwt = jwts.make_jwt(claims, keypair)
        claims1 = jwts.verify_jwt(jwt, keypair)
        claims2 = jwts.verify_jwt(jwt)

        self.assertTrue(claims1)
        self.assertEqual(claims1, claims2)

        for claim in claims:
            self.assertIn(claim, claims1)
            self.assertEqual(claims1.get(claim), claims[claim])

        return claims1

    def test_jwt_sunny_day(self):
        for msg in MSGS:
            logger.debug('testing jwt for "%s"', msg[:1000])
            self._create_and_verify_good_jwt({'message': msg})

    def test_keypair_identity(self):
        keypair = service.create_secret_key()
        keypair.identity = '1234'
        self._create_and_verify_good_jwt({'message': MSGS[0]}, keypair=keypair)

    # def test_null_message(self):
    #     self._create_and_verify_good_jwt(None)
    #
    def test_sample_sjcl_token_one(self):
        sec_der = (
            'MHcCAQEEILVcaIaPYITt3Hxh6ocwALM1HSDwh0ZuxZSocIWMKCbVoAoGCCqGSM49'
            'AwEHoUQDQgAEoj9k67GCZ0J4giV6FzT1diXBNtAqUB/+CIrEkmSNDB4XU9hLfYPC'
            'COEaGaC+WoOShLcM2BRJ6DLodM9zqhYFrQ=='
        )
        pub_der = (
            'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoj9k67GCZ0J4giV6FzT1diXBNtAq'
            'UB/+CIrEkmSNDB4XU9hLfYPCCOEaGaC+WoOShLcM2BRJ6DLodM9zqhYFrQ=='
        )
        token = (
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.'
            'eyJpc3MiOiJvbmVJRCJ9.'
            '18Uo2vYWGizuUlAjqPHbsAPwDiabQ-nD89JP0rdBL0pTo7kMacPZlcA2YIuSDWHx2'
            'tqrRXwY49EqqW6Pz6LaTw'
        )
        pri = keychain.Keypair.from_secret_der(base64.b64decode(sec_der))
        self.assertTrue(jwts.verify_jwt(token, pri))

        pub = keychain.Keypair.from_public_der(base64.b64decode(pub_der))
        self.assertTrue(jwts.verify_jwt(token, pub))

    def test_sample_sjcl_token_two(self):
        sec_der = (
            'MHcCAQEEIA7WRfmTNEW2rMcRCbDuGZcJiRvEq/UBA/13vk0FYAP+oAoGCCqGSM49'
            'AwEHoUQDQgAEs3IdFC73cm7J9gMMt4l3h0VTVzM4goEZiTSp+fukB/l0W4m97qd8'
            'MSEXHak/D7/cOJYEVAWijVuYRVz0Ke9lkg=='
        )
        pub_der = (
            'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs3IdFC73cm7J9gMMt4l3h0VTVzM4'
            'goEZiTSp+fukB/l0W4m97qd8MSEXHak/D7/cOJYEVAWijVuYRVz0Ke9lkg=='
        )
        token = (
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.'
            'eyJpc3MiOiJvbmVJRCJ9.'
            'gkIx8hdH1gHuLl1GIOARztb2ljSPcfaNlMFgkn5m6Sqb-bmGbFzMu-b94WFBUbZr'
            'v3_X8LMCejnwbt_832vvkA'
        )

        pri = keychain.Keypair.from_secret_der(base64.b64decode(sec_der))
        self.assertTrue(jwts.verify_jwt(token, pri))

        pub = keychain.Keypair.from_public_der(base64.b64decode(pub_der))
        self.assertTrue(jwts.verify_jwt(token, pub))

    def test_empty_message(self):
        self._create_and_verify_good_jwt({'1': 1})
        self._create_and_verify_good_jwt({})

    def test_jwt_wrong_type(self):
        with self.assertRaises(Exception):
            jwts.make_jwt(123, self.keypair)

        with self.assertRaises(Exception):
            jwts.make_jwt(123.456, self.keypair)

        with self.assertRaises(Exception):
            jwts.make_jwt(['a', 'b'], self.keypair)

        with self.assertRaises(Exception):
            jwts.make_jwt(lambda a: a, self.keypair)

    def test_jwt_wrong_key(self):
        new_keypair = service.create_secret_key()
        msg = 'bad jwt here❌'

        with self.assertRaises(exceptions.InvalidSignatureError):
            verify_jwt = jwts.make_jwt({"badmsg": msg}, self.keypair)
            jwts.verify_jwt(verify_jwt, new_keypair)

        with self.assertRaises(exceptions.InvalidSignatureError):
            verify_jwt = jwts.make_jwt({"badmsg": msg}, new_keypair)
            jwts.verify_jwt(verify_jwt, self.keypair)

    def test_jwt_bad_header_invalid_typ(self):
        jwt = jwts.make_jwt({'message': 'hi'}, self.keypair)
        header = json.dumps({
            'typ': 'JWT',
            'alg': 'NONE',
        })

        header_str = utils.base64url_encode(header).decode('utf-8')
        bad_jwt = '.'.join([header_str] + jwt.split('.')[1:])

        with self.assertRaises(exceptions.InvalidFormatError):
            jwts.verify_jwt(bad_jwt, self.keypair)

    def test_jwt_bad_header_invalid_alg(self):
        jwt = jwts.make_jwt({'message': 'hi'}, self.keypair)
        header = json.dumps({
            'typ': 'JWT',
            'alg': 'NONE',
        })
        header_str = utils.base64url_encode(header).decode('utf-8')
        bad_jwt = '.'.join([header_str] + jwt.split('.')[1:])
        with self.assertRaises(exceptions.InvalidFormatError):
            jwts.verify_jwt(bad_jwt, self.keypair)

    def test_jwt_bad_header_extra_keys(self):
        jwt = jwts.make_jwt({'message': 'hi'}, self.keypair)
        header = json.dumps({
            'typ': 'JWT',
            'alg': 'ES256',
            'bogosity': True,
        })

        header_str = utils.base64url_encode(header).decode('utf-8')
        bad_jwt = '.'.join([header_str] + jwt.split('.')[1:])
        with self.assertRaises(exceptions.InvalidFormatError):
            jwts.verify_jwt(bad_jwt, self.keypair)

    def test_jwt_bad_header_not_json(self):
        jwt = jwts.make_jwt({'message': 'hi'}, self.keypair)
        plain_text = 'woo-hoo! we just do what we want!!'
        bad_jwt = '.'.join(
            [utils.base64url_encode(plain_text).decode('utf-8')] +
            jwt.split('.')[1:]
        )

        with self.assertRaises(exceptions.InvalidFormatError):
            jwts.verify_jwt(bad_jwt, self.keypair)

    def test_jwt_malformed_header(self):
        jwt = jwts.make_jwt({'message': 'hi'}, self.keypair)
        good_header = json.dumps(jwts.MINIMAL_JWT_HEADER)
        header = utils.base64url_encode(good_header).decode('utf-8')[:-4]
        bad_jwt = '.'.join([header] + jwt.split('.')[:2])
        with self.assertRaises(exceptions.InvalidFormatError):
            jwts.verify_jwt(bad_jwt, self.keypair)

    def test_injected_issuer_claim(self):
        with_iss = {
            'iss': 'not-oneid'
        }
        self._create_and_verify_good_jwt(with_iss)
        with_iss['iss'] = 'oneID'
        self._create_and_verify_good_jwt(with_iss)

    def test_jwt_invalid_base64(self):
        jwt = jwts.make_jwt({'message': 'hi'}, self.keypair)
        header = 'a'
        bad_jwt = '.'.join([header] + jwt.split('.')[:2])

        with self.assertRaises(exceptions.InvalidFormatError):
            jwts.verify_jwt(bad_jwt, self.keypair)

    def test_jwt_malformed_payload(self):
        jwt = jwts.make_jwt({'message': 'hi'}, self.keypair)
        header, payload, signature = jwt.split('.')
        payload = payload[:-8]
        bad_jwt = '.'.join([header, payload, signature])
        with self.assertRaises(Exception):
            jwts.verify_jwt(bad_jwt, self.keypair)

    def test_jwt_missing_signature(self):
        jwt = jwts.make_jwt({'message': 'hi'}, self.keypair)
        bad_jwt = '.'.join(jwt.split('.')[:2])

        with self.assertRaises(exceptions.InvalidFormatError):
            jwts.verify_jwt(bad_jwt, self.keypair)

    def test_not_quite_expired_then_expired(self):
        now = int(time.time())
        logger.debug('pre-sleep now=%s', now)
        exp = now + 2
        jwt = jwts.make_jwt({'message': 'hi', 'exp': exp}, self.keypair)

        self.assertTrue(jwts.verify_jwt(jwt, self.keypair))

        time.sleep(jwts.TOKEN_EXPIRATION_LEEWAY_SEC + 4)
        logger.debug('post-sleep now=%s', int(time.time()))

        with self.assertRaises(exceptions.InvalidClaimsError):
            jwts.verify_jwt(jwt, self.keypair)

    def test_expired(self):
        now = int(time.time())
        logger.debug('now=%s', now)
        exp = now - (jwts.TOKEN_EXPIRATION_LEEWAY_SEC + 1)
        jwt = jwts.make_jwt({'message': 'hi', 'exp': exp}, self.keypair)

        with self.assertRaises(exceptions.InvalidClaimsError):
            jwts.verify_jwt(jwt, self.keypair)

    def test_use_before_in_future(self):
        now = int(time.time())
        logger.debug('now=%s', now)
        jwt = jwts.make_jwt({'message': 'hi', 'nbf': (now + (3 * 60))},
                            self.keypair)

        with self.assertRaises(exceptions.InvalidClaimsError):
            jwts.verify_jwt(jwt, self.keypair)

    def test_valid_nonce(self):
        nonce = nonces.make_nonce()
        logger.debug('nonce=%s', nonce)
        jwt = jwts.make_jwt({'message': 'hi', 'jti': nonce}, self.keypair)

        self.assertTrue(jwts.verify_jwt(jwt, self.keypair))

    def test_invalid_nonce(self):
        nonce = '999' + time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                      time.gmtime()) + '123456'
        logger.debug('nonce=%s', nonce)
        jwt = jwts.make_jwt({'message': 'hi', 'jti': nonce}, self.keypair)

        with self.assertRaises(exceptions.InvalidClaimsError):
            jwts.verify_jwt(jwt, self.keypair)

    def test_expired_nonce(self):
        then = datetime.utcnow().replace(tzinfo=tz.tzutc()) + timedelta(hours=-24)
        nonce = nonces.make_nonce(then)
        logger.debug('nonce=%s', nonce)
        jwt = jwts.make_jwt({'message': 'hi', 'jti': nonce}, self.keypair)

        with self.assertRaises(exceptions.InvalidClaimsError):
            jwts.verify_jwt(jwt, self.keypair)

    def test_nonce_from_exp(self):
        exp = int(time.time()) + 2 * 60
        exp_dt = datetime.fromtimestamp(exp, tz.tzutc())

        claims_in = {'exp': exp}
        claims_out = self._create_and_verify_good_jwt(claims_in)

        self.assertEqual(exp_dt, parser.parse(claims_out['jti'][3:-6]))

    def test_exp_from_nonce(self):
        exp = int(time.time()) + 2 * 60
        exp_dt = datetime.fromtimestamp(exp, tz.tzutc())

        nonce = nonces.make_nonce(exp_dt)

        claims_in = {'jti': nonce}
        claims_out = self._create_and_verify_good_jwt(claims_in)

        self.assertEqual(exp, claims_out['exp'])

    def test_exp_not_from_v1_nonce(self):
        now_ts = int(time.time())
        now_dt = datetime.fromtimestamp(now_ts, tz.tzutc())

        nonce = '001' + nonces.make_nonce(now_dt)[3:]

        claims_in = {'jti': nonce}
        claims_out = self._create_and_verify_good_jwt(claims_in)

        self.assertNotEqual(now_ts, claims_out['exp'])

    def test_exp_and_nonce(self):
        exp = int(time.time()) + 2 * 60
        nonce = nonces.make_nonce()

        claims_in = {'exp': exp, 'jti': nonce}
        claims_out = self._create_and_verify_good_jwt(claims_in)

        self.assertEqual(exp, claims_out['exp'])
        self.assertEqual(nonce, claims_out['jti'])

    def test_exp_and_v1_nonce(self):
        now = datetime.utcnow().replace(tzinfo=tz.tzutc())
        nonce = '001' + nonces.make_nonce(now)[3:]

        exp = int(time.time()) + 2 * 60 * 60

        claims_in = {'exp': exp, 'jti': nonce}
        claims_out = self._create_and_verify_good_jwt(claims_in)

        self.assertEqual(exp, claims_out['exp'])
        self.assertEqual(nonce, claims_out['jti'])

    def test_neither_exp_nor_nonce(self):
        claims_in = {}
        claims_out = self._create_and_verify_good_jwt(claims_in)

        exp_dt = datetime.fromtimestamp(claims_out['exp'], tz.tzutc())

        self.assertEqual(exp_dt, parser.parse(claims_out['jti'][3:-6]))

    def test_non_standard_nonce(self):
        nonce = '0022020-02-31T02:28:42ZCdv3Yv'
        claims_in = {'jti': nonce}

        jwt = jwts.make_jwt(claims_in, self.keypair)

        self.assertTrue(jwt)

        # TODO: parse JWT (it won't validate using the sdk)
        #
        # claims_out = self._create_and_verify_good_jwt(claims_in)
        #
        # self.assertEqual(nonce, parser.parse(claims_out['jti']))
        # self.assertIn('exp', claims_out)


class TestKnownJWTs(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ['HOME'] = self.tmpdir
        nonces.set_nonce_handlers(lambda _n: True, lambda _n: True)
        self.keypair = keychain.Keypair.from_secret_der(base64.b64decode(
            'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOiXcCrreAqzw3xOT'
            'L44O8DFyDfBAPQgZ0AmPGZfWmMShRANCAARD66FPRWFIFrNcn+DjLTSb8lP3pha3'
            'joBvC7Cf4JR/LP7lECAc0mNfokw84+pLurAkP2rG1Y63n9KPwntflfRD='
        ))

    def tearDown(self):
        nonces.set_nonce_handlers(
            nonces._default_nonce_verifier, nonces._default_nonce_burner)

    def test_previously_generated_good_vectors(self):
        # msg = '{"claim": '
        #       '"this is a decently long test string with some
        #           înterésting characters!😀"'
        #       ', "iss": "oneID"}'
        good_tokens = [
            'eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJFUzI1NiJ9.'
            'eyJjbGFpbSI6ICJ0aGlzIGlzIGEgZGVjZW50bHkgbG9uZyB0ZXN0IHN0cmluZyB3'
            'aXRoIHNvbWUgw65udGVyw6lzdGluZyBjaGFyYWN0ZXJzIfCfmIAiLCAiaXNzIjog'
            'Im9uZUlEIn0.'
            'Y5_T3I4fKvDaV7C9iRO4CAE7ZyVDZSJaKb1lE8oefsHc9_7BdNzz9qcfS8DFutNG'
            'XPHp073AdkirIHiDKNSmmA',
            'eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJFUzI1NiJ9.'
            'eyJjbGFpbSI6ICJ0aGlzIGlzIGEgZGVjZW50bHkgbG9uZyB0ZXN0IHN0cmluZyB3'
            'aXRoIHNvbWUgw65udGVyw6lzdGluZyBjaGFyYWN0ZXJzIfCfmIAiLCAiaXNzIjog'
            'Im9uZUlEIn0.'
            'qgD5uRmnhAyymQ1APU8Zy0WBycw2FNleym6AB31GfELgpkPaeZJqckOKeNT5c6yT'
            'h99wJHi0PjXtblD6ddlWzA',
            'eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJFUzI1NiJ9.'
            'eyJjbGFpbSI6ICJ0aGlzIGlzIGEgZGVjZW50bHkgbG9uZyB0ZXN0IHN0cmluZyB3'
            'aXRoIHNvbWUgw65udGVyw6lzdGluZyBjaGFyYWN0ZXJzIfCfmIAiLCAiaXNzIjog'
            'Im9uZUlEIn0.'
            'Yaj0JiCMBAQslap3WiBTSnNAZUEQZ5rACI_oHbP5gKCXGo_bUVoSvGygUMVmDipn'
            'mxZmqQpVYEXNqTCKVVKLRQ',

            'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.'
            'eyJjbGFpbSI6ICJ0aGlzIGlzIGEgZGVjZW50bHkgbG9uZyB0ZXN0IHN0cmluZyB3'
            'aXRoIHNvbWUgXHUwMGVlbnRlclx1MDBlOXN0aW5nIGNoYXJhY3RlcnMhXHVkODNk'
            'XHVkZTAwIiwg'
            'ImlzcyI6ICJvbmVJRCJ9.eX1ob01UqDOoFY0IVKHw7ycl7jVjYb7UWhWTZZD1MaK'
            'GSmQ9XuNgica4USLbQlVLt5_n1ihar2lAedpgw5QGgg',
            'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.'
            'eyJjbGFpbSI6ICJ0aGlzIGlzIGEgZGVjZW50bHkgbG9uZyB0ZXN0IHN0cmluZyB3'
            'aXRoIHNvbWUgXHUwMGVlbnRlclx1MDBlOXN0aW5nIGNoYXJhY3RlcnMhXHVkODNk'
            'XHVkZTAwIiwg'
            'ImlzcyI6ICJvbmVJRCJ9.d79RLEQ00KDsZ81bZ9lN-SMTKTXEwJDaIjEkkfa1Iho'
            'zWKcf6vHwA0iqZxjYF6WD-8oErFlEpnTSw4pIG-b1Yw',
            'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.'
            'eyJjbGFpbSI6ICJ0aGlzIGlzIGEgZGVjZW50bHkgbG9uZyB0ZXN0IHN0cmluZyB3'
            'aXRoIHNvbWUgXHUwMGVlbnRlclx1MDBlOXN0aW5nIGNoYXJhY3RlcnMhXHVkODNk'
            'XHVkZTAwIiwg'
            'ImlzcyI6ICJvbmVJRCJ9.P2GvYyl34tQb47HC7qIJZ8yEh4T8tzzCgjLjgzJMFSm'
            '3BwK-svxjm3O09RWB_6dPAGYrN2RKYVwdFdQqpWtKeA',

            'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.'
            'eyJpc3MiOiAib25lSUQiLCAiY2xhaW0iOiAidGhpcyBpcyBhIGRlY2VudGx5IGxv'
            'bmcgdGVzdCBzdHJpbmcgd2l0aCBzb21lIFx1MDBlZW50ZXJcdTAwZTlzdGluZyBj'
            'aGFyYWN0ZXJz'
            'ITpncmlubmluZzoifQ.kSlrw28fvkDYE0BASk-qqdiBYJLzFdkkZLIvbRoEUNr0o'
            'y3C0ZmKy1Lx8zkGMdS2HQCZ49y_7W03Merch45s-g',
        ]

        for token in good_tokens:
            self.assertTrue(jwts.verify_jwt(token, self.keypair))

    def test_previously_generated_bad_vectors(self):
        bad_tokens = [
            # different private key
            'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJjbGFpbSI6ICJ0aGlzIGl'
            'zIGEgZGVjZW50bHkgbG9uZyB0ZXN0IHN0cmluZyB3aXRoIHNvbWUgw65udGVyw6l'
            'zdGluZyBjaGFyYWN0ZXJzIfCfmIAiLCAiaXNzIjogIm9uZUlEIn0.MEYCIQCcozU'
            '44vPzvyiBwyb0sM0N_fJ5bDnmub0tbFNSs-xtBAIhAK37PVBOkcckGg1fodFHnI7'
            'kpohaDSFNlhmZUWvXJmIg',
            # TODO: invalid headers
            # (missing required, extra keys, different values)
            # TODO: bad signatures
        ]

        for token in bad_tokens:
            with self.assertRaises(exceptions.InvalidSignatureError):
                jwts.verify_jwt(token, self.keypair)


class TestJWSs(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ['HOME'] = self.tmpdir
        nonces.set_nonce_handlers(lambda _n: True, lambda _n: True)

        self.keypairs = []

        for _ in range(3):
            key = service.create_secret_key()
            key.identity = str(uuid.uuid4())
            self.keypairs.append(key)

        self.JWS_MISSING_2_SIGNATURE_INDEXES = json.dumps(
            {
                "signatures": [
                    {
                        "signature": ("qv3yMkk5ASPWYKHduH07JtwziPvZjOVlUpBX4ePd8YYPu4H5poHBn12QgjY9"
                                      "MF081UH2-BARVRzDaJ7N02nXFA"),
                        "protected": ("eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpPU0UrSlNPTiIsICJraWQiOiAi"
                                      "MDAyY2Q5MTAtYzEyMi00ZmY3LWEwMmMtMzQyNjAzOTQ1YzFiIn0")
                    },
                    {
                        "signature": ("rwm1ohxoHPCFWT_rsQKV0CPezUHp-Udgc4JsuqjtWpqMFuQEDYDTMEDlx93B"
                                      "2RWGvF7WyjNeftCSr-olAcM04A"),
                        "protected": ("eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpPU0UrSlNPTiIsICJraWQiOiAi"
                                      "NTU2YTZlOTctNzZlNS00NGRmLTkyMGUtMTE0OTA5MDNiNDZhIn0")
                    },
                    {
                        "signature": ("HUSPH2fP8MTb2F4wT5cClNzzvIWtxn7oTLaFlSMMiAWmTKnUbMpA6GcGhPNg"
                                      "b3Yu5RPyNQuyx_cwXsV00sDO8Q"),
                        "protected": ("eyJhbGciOiAiRVMyNTYiLCAic2lkIjogMCwgInR5cCI6ICJKT1NFK0pTT04i"
                                      "LCAia2lkIjogIjA2ZjY2ODdhLWIxYTQtNGMyZC04YmIwLWQ3ZjdhMjU3ODE2"
                                      "MSJ9")
                    }
                ],
                "payload": ("eyJqdGkiOiAiMDAyMjQ4OS0wMi0yN1QxNjowMDowMFpPbE13WUgiLCAibmJmIjogMTQ3OT"
                            "QxNTY3OCwgImEiOiAxLCAiZXhwIjogMTYzODMxNjgwMDB9")
            }
        )

        self.JWS_MISSING_1_SIGNATURE_INDEXES = json.dumps(
            {
                "signatures": [
                    {
                        "signature": ("W8HUqYZi3F3xI-Hx2KUwXCeEwhxLDqpSOs4syaAaHJvvwArShgdZibwFLmy9"
                                      "w4sdR2oFRQU2Uz7-flOuaDukTA"),
                        "protected": ("eyJhbGciOiAiRVMyNTYiLCAia2lkIjogIjg2M2E4MDU1LTU2OGUtNGE3Yy04"
                                      "YjAwLWQxYTdhMjBkZjc0MSIsICJ0eXAiOiAiSk9TRStKU09OIiwgInNpZHgi"
                                      "OiAwfQ")
                    },
                    {
                        "signature": ("O5q9H9vXTiGh0Qrv6Rc1r7Tbc_eO-K5CMX_-Z5ir33GPX4c-AuQuKoE4vLvi"
                                      "n30LfnCOcG5USXVE8G-Q3eD-TQ"),
                        "protected": ("eyJhbGciOiAiRVMyNTYiLCAia2lkIjogImFlOGVhOWI4LWZlMmQtNDI0My05"
                                      "OGE5LWQ5ZjAyYjBiYWEwYiIsICJ0eXAiOiAiSk9TRStKU09OIiwgInNpZHgi"
                                      "OiAxfQ")
                    },
                    {
                        "signature": ("kFQeh4tYgsioE71umxNc4_r6diil7vVFC7nYiXQpaAZA9FfWVnM6vSCgS2UX"
                                      "wKicHrf-S5_1ZjiXPR-uInZKeg"),
                        "protected": ("eyJraWQiOiAiMzc0MGU1YjUtMDc3MC00YjcwLWIzN2MtOTUyMTA4ZTBhYzE0"
                                      "IiwgInR5cCI6ICJKT1NFK0pTT04iLCAiYWxnIjogIkVTMjU2In0")
                    }
                ],
                "payload": ("eyJhIjogMSwgIm5iZiI6IDE0Nzk0MTYyMzEsICJqdGkiOiAiMDAyMjQ4OS0wMi0yN1QxNj"
                            "owMDowMFo3WW1QQ1IiLCAiZXhwIjogMTYzODMxNjgwMDB9")
            }
        )

        self.JWS_DUPLICATE_SIGNATURE_INDEXES = json.dumps(
            {
                "signatures": [
                    {
                        "signature": ("0xmM4kfdd9vXc58nwGrrur_ddzppnB90OeTYLGO6aeNLuCzM7rTcL3edeCyR"
                                      "nqddn3hyXl4eCQSSOGCjdHwlRQ"),
                        "protected": ("eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpPU0UrSlNPTiIsICJraWQiOiAi"
                                      "MTg2NjEzY2UtOWZmNy00ZWNjLTlkZTgtNzY2NjdmOWIwZjQ5IiwgInNpZHgi"
                                      "OiAxfQ")
                    },
                    {
                        "signature": ("vT6zww3UwMO-ECi1E74qJuV2U2hEJwC_k8ab2fumQZRsqG4vCJob8pQaGa-k"
                                      "dF88FSXDqj6j_09UXa0Fx_eOHA"),
                        "protected": ("eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpPU0UrSlNPTiIsICJraWQiOiAi"
                                      "ZjMyYzE1ZGYtZGNmNS00YThiLWJhMzktYjM0Y2QwNGJiMjhjIiwgInNpZHgi"
                                      "OiAxfQ")
                    }
                ],
                "payload": ("eyJhIjogMSwgImV4cCI6IDE0Nzk0Mjk2NDMsICJqdGkiOiAiMDAyMjAxNi0xMS0xOFQwMD"
                            "o0MDo0M1pWS09WOTIiLCAibmJmIjogMTQ3OTQyNjA0M30")
            }
        )

    def tearDown(self):
        nonces.set_nonce_handlers(
            nonces._default_nonce_verifier, nonces._default_nonce_burner)

    def _create_and_verify_good_jws(self, claims, keypairs=None):
        keypairs = keypairs or self.keypairs
        jws = jwts.make_jws(claims, keypairs)

        self.assertIsInstance(jws, str)

        verifications = [
            jwts.verify_jws(jws, keypairs),
            jwts.verify_jws(jws),
            jwts.verify_jws(utils.to_bytes(jws)),
        ]

        for verification in verifications:
            self.assertTrue(verification)

            for claim in claims:
                self.assertIn(claim, verification)
                self.assertEqual(verification.get(claim), claims[claim])

    def test_jws_sunny_day(self):
        for msg in MSGS:
            logger.debug('testing jws for "%s"', msg[:1000])
            self._create_and_verify_good_jws({'message': msg})

    def test_single_key(self):
        self._create_and_verify_good_jws({'hello': 7}, self.keypairs[0])

    def test_missing_keypair_identity(self):
        keypair = service.create_secret_key()

        with self.assertRaises(exceptions.InvalidKeyError):
            jwts.make_jws({"hi": 7}, keypair)

    def test_incorrect_number_of_headers(self):
        with self.assertRaises(exceptions.KeyHeaderMismatch):
            jwts.make_jws({'hello': 7}, self.keypairs[
                0], multiple_sig_headers=[{'z': 0}, {'z': 99}])

    def test_invalid_headers(self):
        with self.assertRaises(exceptions.ReservedHeader):
            jwts.make_jws({'hello': 7}, self.keypairs[
                0], multiple_sig_headers=[{'alg': 99}])

    def test_extend_jws_signatures_from_jwt(self):
        jwt = jwts.make_jwt({"a": 1}, self.keypairs[0])
        jws = jwts.extend_jws_signatures(jwt,
                                         self.keypairs[1:],
                                         self.keypairs[0].identity)

        verified_msg = jwts.verify_jws(jws, self.keypairs)
        self.assertIsInstance(verified_msg, dict)

    def test_verify_jws_from_jwt(self):
        jwt = jwts.make_jwt({'a': 1}, self.keypairs[0])
        verified_msg = jwts.verify_jws(jwt, self.keypairs[0])
        self.assertIsInstance(verified_msg, dict)

    def test_extend_jws_signatures_from_jwt_single_key(self):
        jwt = jwts.make_jwt({'a': 1}, self.keypairs[0])
        jws = jwts.extend_jws_signatures(jwt,
                                         self.keypairs[1],
                                         self.keypairs[1].identity)

        verified_msg = jwts.verify_jws(jws, self.keypairs[:2])
        self.assertIsInstance(verified_msg, dict)

    def test_extend_jws_signatures_from_jwt_no_kid(self):
        keypair = service.create_secret_key()
        kid = str(uuid.uuid4())

        jwt = jwts.make_jwt({'a': 1}, keypair)
        jws = jwts.extend_jws_signatures(jwt, self.keypairs, kid)

        keypair.identity = kid
        keypairs = self.keypairs + [keypair]
        verified_msg = jwts.verify_jws(jws, keypairs)
        self.assertIsInstance(verified_msg, dict)

    def test_extend_jws_missing_keypair_identity(self):
        keypair = service.create_secret_key()
        jws = jwts.make_jws({'a': 1}, self.keypairs[0])

        with self.assertRaises(exceptions.InvalidKeyError):
            jwts.extend_jws_signatures(jws, keypair)

    def test_extend_jws_signatures_from_jws(self):
        jws = jwts.make_jws({'a': 1}, self.keypairs[:2])
        jws = jwts.extend_jws_signatures(jws, self.keypairs[2:])
        verified_msg = jwts.verify_jws(jws, self.keypairs)
        self.assertIsInstance(verified_msg, dict)

    def test_extend_jws_signatures_from_jws_multiple_without_sidx(self):
        jws = self.JWS_MISSING_2_SIGNATURE_INDEXES
        jws = jwts.extend_jws_signatures(jws, self.keypairs[2:])
        headers = jwts.get_jws_headers(jws)
        indexes = list(filter(None, [h.get('sidx', None) for h in headers]))
        self.assertEqual(len(indexes), 0)

    def test_extend_jws_signatures_from_jws_without_1_sidx(self):
        jws = self.JWS_MISSING_1_SIGNATURE_INDEXES
        jws = jwts.extend_jws_signatures(jws, self.keypairs[2:])
        self.assertIsInstance(jwts.get_jws_key_ids(jws, ordered=True), list)

    def test_extend_incorrect_number_of_headers(self):
        jws = jwts.make_jws({'a': 1}, self.keypairs[:2])
        with self.assertRaises(exceptions.KeyHeaderMismatch):
            jwts.extend_jws_signatures(
                jws, self.keypairs[0], multiple_sig_headers=[{'z': 0}, {'z': 99}])

    def test_remove_jws_signature(self):
        jws = jwts.make_jws({'a': 1}, self.keypairs)
        jws = jwts.remove_jws_signatures(jws, self.keypairs[0].identity)
        verified_msg = jwts.verify_jws(jws, self.keypairs[1:])
        self.assertIsInstance(verified_msg, dict)

    def test_none_headers(self):
        jws = jwts.make_jws({'a': 1}, self.keypairs[:1], multiple_sig_headers=None)
        jws_headers = jwts.get_jws_headers(jws)
        self.assertIsInstance(jws_headers[0], dict)

    def test_remove_jws_signature_list(self):
        jws = jwts.make_jws({'a': 1}, self.keypairs)
        ids = [keypair.identity for keypair in self.keypairs[:2]]
        jws = jwts.remove_jws_signatures(jws, ids)
        verified_msg = jwts.verify_jws(jws, self.keypairs[2:])
        self.assertIsInstance(verified_msg, dict)

    def test_get_jws_key_ids(self):
        jws = jwts.make_jws({'a': 1}, self.keypairs)
        kids = [keypair.identity for keypair in self.keypairs]
        msg_ids = jwts.get_jws_key_ids(jws)
        self.assertEqual(msg_ids, kids)

    def test_get_ordered_jws_key_ids(self):
        jws = jwts.make_jws({'a': 1}, self.keypairs)
        kids = [keypair.identity for keypair in self.keypairs]
        msg_ids = jwts.get_jws_key_ids(jws, ordered=True)
        self.assertEqual(msg_ids, kids)

    def test_get_ordered_jws_key_ids_without_sidx(self):
        jws = self.JWS_MISSING_2_SIGNATURE_INDEXES
        with self.assertRaises(exceptions.InvalidSignatureIndexes):
            jwts.get_jws_key_ids(jws, ordered=True)

    def test_get_ordered_jws_key_ids_with_duplicate_sidx(self):
        jws = self.JWS_DUPLICATE_SIGNATURE_INDEXES
        with self.assertRaises(exceptions.InvalidSignatureIndexes):
            jwts.get_jws_key_ids(jws, ordered=True)

    def test_get_jws_key_invalid_jws(self):
        with self.assertRaises(exceptions.InvalidFormatError):
            jwts.get_jws_key_ids("not a jws")

    def test_get_jws_key_ids_from_jwt(self):
        jwt = jwts.make_jwt({'a': 1}, self.keypairs[0])
        kids = [self.keypairs[0].identity]
        msg_ids = jwts.get_jws_key_ids(jwt)
        self.assertEqual(msg_ids, kids)

    def test_jwt_verify_with_mult_sigs(self):
        jwt = jwts.make_jwt({'a': 1}, self.keypairs[0])

        with self.assertRaises(Exception):
            jwts.verify_jws(jwt, self.keypairs[:2])

    def test_invalid_message_not_a_jws(self):
        jws = jwts.make_jws({'a': 1}, self.keypairs[:2])
        jws_dict = json.loads(jws)

        no_payload = {k: v for k, v in jws_dict.items() if k != 'payload'}
        with self.assertRaises(exceptions.InvalidFormatError):
            jwts.verify_jws(json.dumps(no_payload), self.keypairs[:2])

        no_sigs = {k: v for k, v in jws_dict.items() if k != 'signatures'}
        with self.assertRaises(exceptions.InvalidFormatError):
            jwts.verify_jws(json.dumps(no_sigs), self.keypairs[:2])

    def test_jwt_verify_with_redundant_keypairs(self):
        jws = jwts.make_jws({'a': 1}, self.keypairs[:2])

        with self.assertRaises(exceptions.InvalidKeyError):
            jwts.verify_jws(jws, self.keypairs[:1] * 2)

    def test_missing_typ_in_jws_header(self):
        jws = json.loads(jwts.make_jws({'a': 1}, self.keypairs[:1]))
        header = json.loads(utils.to_string(
            utils.base64url_decode(jws['signatures'][0]['protected'])
        ))
        del header['typ']
        jws['signatures'][0]['protected'] = utils.to_string(
            utils.base64url_encode(json.dumps(header))
        )

        with self.assertRaises(exceptions.InvalidFormatError):
            jwts.verify_jws(json.dumps(jws), self.keypairs[:1])

    def test_invalid_typ_in_jws_header(self):
        jws = json.loads(jwts.make_jws({'a': 1}, self.keypairs[:1]))
        header = json.loads(utils.to_string(
            utils.base64url_decode(jws['signatures'][0]['protected'])
        ))
        header['typ'] = 'bog'
        jws['signatures'][0]['protected'] = utils.to_string(
            utils.base64url_encode(json.dumps(header))
        )

        with self.assertRaises(exceptions.InvalidFormatError):
            jwts.verify_jws(json.dumps(jws), self.keypairs[:1])

    def test_missing_alg_in_jws_header(self):
        jws = json.loads(jwts.make_jws({'a': 1}, self.keypairs[:1]))
        header = json.loads(utils.to_string(
            utils.base64url_decode(jws['signatures'][0]['protected'])
        ))
        del header['alg']
        jws['signatures'][0]['protected'] = utils.to_string(
            utils.base64url_encode(json.dumps(header))
        )

        with self.assertRaises(exceptions.InvalidAlgorithmError):
            jwts.verify_jws(json.dumps(jws), self.keypairs[:1])

    def test_invalid_alg_in_jws_header(self):
        jws = json.loads(jwts.make_jws({'a': 1}, self.keypairs[:1]))
        header = json.loads(utils.to_string(
            utils.base64url_decode(jws['signatures'][0]['protected'])
        ))
        header['alg'] = 'bog'
        jws['signatures'][0]['protected'] = utils.to_string(
            utils.base64url_encode(json.dumps(header))
        )

        with self.assertRaises(exceptions.InvalidAlgorithmError):
            jwts.verify_jws(json.dumps(jws), self.keypairs[:1])

    def test_missing_kid_in_jws_header(self):
        jws = json.loads(jwts.make_jws({'a': 1}, self.keypairs[:1]))
        header = json.loads(utils.to_string(
            utils.base64url_decode(jws['signatures'][0]['protected'])
        ))
        del header['kid']
        jws['signatures'][0]['protected'] = utils.to_string(
            utils.base64url_encode(json.dumps(header))
        )

        with self.assertRaises(exceptions.InvalidFormatError):
            jwts.verify_jws(json.dumps(jws), self.keypairs[:1])

    def test_jws_verify_with_wrong_keypair(self):
        jws = jwts.make_jws({'a': 1}, self.keypairs[:1])

        with self.assertRaises(exceptions.KeySignatureMismatch):
            jwts.verify_jws(jws, self.keypairs[1:2])

        with self.assertRaises(exceptions.KeySignatureMismatch):
            jwts.verify_jws(jws, self.keypairs[1:2])

    def test_jws_verify_invalid_signature(self):
        jws = json.loads(jwts.make_jws({'a': 1}, self.keypairs[:1]))
        jws['signatures'][0]['signature'] = 'bogus'

        with self.assertRaises(exceptions.InvalidSignatureError):
            jwts.verify_jws(json.dumps(jws), self.keypairs[:1])

    def test_jws_verify_no_signatures(self):
        jws = jwts.make_jws({"a": 1}, [])

        with self.assertRaises(exceptions.InvalidSignatureError):
            jwts.verify_jws(jws, self.keypairs[:2])

        with self.assertRaises(exceptions.InvalidSignatureError):
            jwts.verify_jws(jws, self.keypairs[:2])

    def test_jws_verify_not_enough_signatures(self):
        jws = jwts.make_jws({"a": 1}, self.keypairs[:1])

        with self.assertRaises(exceptions.KeySignatureMismatch):
            jwts.verify_jws(jws, self.keypairs[:2])

    def test_jws_verify_too_many_signatures(self):
        jws = jwts.make_jws({"a": 1}, self.keypairs[:2])

        with self.assertRaises(exceptions.KeySignatureMismatch):
            jwts.verify_jws(jws, self.keypairs[:1])

    def test_jws_verify_mismatched_signatures(self):
        jws = jwts.make_jws({"a": 1}, self.keypairs[:2])

        # this test requires equal-length arrays, with some overlap
        with self.assertRaises(exceptions.KeySignatureMismatch):
            jwts.verify_jws(jws, self.keypairs[1:3])

        jwts.verify_jws(jws, self.keypairs[1:3], verify_all=False)

    def test_jws_verify_any_signature_is_ok(self):
        jws = jwts.make_jws({'a': 1}, self.keypairs[:1])

        verified_msg = jwts.verify_jws(
            jws, self.keypairs[:2], verify_all=False)
        self.assertIn("a", verified_msg)

    def test_get_jws_headers(self):
        header = {'z': 99}
        jws = jwts.make_jws({'a': 1}, self.keypairs[:1], [header])
        jws_headers = jwts.get_jws_headers(jws)
        self.assertTrue(jws_headers[0]['z'] == header['z'])

    def test_get_jws_headers_invalid_json(self):
        jws = jwts.make_jws({'message': 'hi'}, self.keypairs[:1])
        header = json.dumps({
            'typ': 'JWT',
            'alg': 'NONE',
        })

        header_str = utils.base64url_encode(header).decode('utf-8')
        bad_jws = '.'.join([header_str] + jws.split('.')[1:])

        with self.assertRaises(exceptions.InvalidFormatError):
            jwts.get_jws_headers(bad_jws)


class TestKnownJWSs(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ['HOME'] = self.tmpdir
        nonces.set_nonce_handlers(lambda _n: True, lambda _n: True)
        self.keypair = keychain.Keypair.from_secret_der(base64.b64decode(
            'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgOiXcCrreAqzw3xOT'
            'L44O8DFyDfBAPQgZ0AmPGZfWmMShRANCAARD66FPRWFIFrNcn+DjLTSb8lP3pha3'
            'joBvC7Cf4JR/LP7lECAc0mNfokw84+pLurAkP2rG1Y63n9KPwntflfRD='
        ))
        self.keypair.identity = '12345'

    def tearDown(self):
        nonces.set_nonce_handlers(
            nonces._default_nonce_verifier, nonces._default_nonce_burner)

    def test_missing_nonce(self):
        jws = json.dumps({
            "payload": "eyJhIjogMX0",
            "signatures": [{
                "protected": (
                    "eyJ0eXAiOiAiSk9TRStKU09OIiwgImFsZyI6ICJFUzI1"
                    "NiIsICJraWQiOiAiMTIzNDUifQ"
                ),
                "signature": (
                    "9PXHibGclG2wNT5f6BZhkk6YGFI0kUSITBWlmBQIKipL"
                    "N-UMPKvKUMvelhZX7EIqNpmZB7b9LvIiiNYZ6NFkJg"
                )
            }]
        })
        self.assertTrue(jwts.verify_jws(jws, self.keypair))

        # TODO: add more
