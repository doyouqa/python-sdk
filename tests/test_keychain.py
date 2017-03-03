# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import tempfile
import uuid
import base64
import binascii
import logging
import unittest

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from oneid import keychain, service, utils, exceptions

from .common import keypair_from_nist_hex, hex2bytes


logger = logging.getLogger(__name__)


def _private_to_public(private_keypair):
    return keychain.Keypair.from_public_der(private_keypair.public_key_der)


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
            self.project_credentials.decrypt(enc)
        )
        self.assertEqual(cleartext, self.data)

    def test_encrypt_bytes(self):
        data = ['string', b'bytes']

        for text in data:
            logger.debug('enc/dec %s', text)
            enc = self.project_credentials.encrypt(text)
            cleartext = utils.to_string(
                self.project_credentials.decrypt(enc)
            )
            self.assertEqual(cleartext, utils.to_string(text))

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
        with self.assertRaises((binascii.Error, TypeError)):
            self.project_credentials.decrypt(
                {
                    'cipher': 'aes', 'mode': 'gcm',
                    'ts': 128, 'iv': 'aa', 'ct': 'aa'
                }
            )


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

    def test_ecdh(self):
        ue_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "d": "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo",
        }
        apu = 'Alice'
        u_private_keypair = keychain.Keypair.from_jwk(ue_jwk)
        u_public_keypair = _private_to_public(u_private_keypair)
        v_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw",
        }
        apv = 'Bob'
        v_private_keypair = keychain.Keypair.from_jwk(v_jwk)
        v_public_keypair = _private_to_public(v_private_keypair)

        ku = u_private_keypair.ecdh(v_public_keypair, party_u_info=apu, party_v_info=apv)
        kv = v_private_keypair.ecdh(u_public_keypair, party_u_info=apu, party_v_info=apv)

        self.assertEqual(len(ku), 32)
        self.assertEqual(ku, kv)

        eve_keypair = service.create_secret_key()
        keve = eve_keypair.ecdh(u_private_keypair, party_u_info=apu, party_v_info=apv)
        self.assertNotEqual(ku, keve)

    def test_ecdh_empty_apuv(self):
        u_keypair = service.create_secret_key()
        v_keypair = service.create_secret_key()

        ku = u_keypair.ecdh(v_keypair)
        kv = v_keypair.ecdh(u_keypair)

        self.assertEqual(ku, kv)

        eve_keypair = service.create_secret_key()
        keve = eve_keypair.ecdh(u_keypair)
        self.assertNotEqual(ku, keve)

    def test_ecdh_public_key(self):
        der = base64.b64decode(
            'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJLzzbuz2tRnLFlOL+6bTX6giVavA'
            'sc6NDFFT0IMCd2ibTTNUDDkFGsgq0cH5JYPg/6xUlMBFKrWYe3yQ4has9w=='
        )
        keypair = keychain.Keypair.from_public_der(der)
        keypair2 = service.create_secret_key()

        with self.assertRaises(exceptions.InvalidFormatError):
            keypair.ecdh(keypair2)

    def test_cavp_ecdh_vectors(self):
        # from KASTestVectorsECC2016/Key Confirmation/ECC One Pass DH Scheme/
        #       KASValidityTest_ECCOnePassDH_KDFConcat_KC_init_rcpt_ulat.fax
        #   [CCM AES256] (line 20702)
        #
        _CAVS_VECTORS = [
            {
                "COUNT": "0",
                "dsCAVS": "6d54ae0f8647c2eec0a2c2af60b56ce05d4695b9c0e7320448c6fd53cac7aa85",
                "QsCAVSx": "237eb9a7be11382785f77252be8fc2f07e87ed5f66faceba5d0a7e11a0ce7b7d",
                "QsCAVSy": "a11eecc27e1d93d7d08d0f26418fe36fac6ecbf569da0e2e6e66ebcd5af1aa94",
                "deIUT": "2dc6f3853c8fc7ce8a66692539ea6c4127440e85f764cbb686fd8afc96e2478e",
                "QeIUTx": "aab1b13842ef6dadf465700163067b2812684713c9beb678810c79d2f7d1a898",
                "QeIUTy": "1bf139ca3a6980574abfb0e316d864cdf296fbf444924dda65d93255f31f4f6b",
                "CCMNonce": "e46a2aa00c911408a595df62a9",
                "OI": (
                    "a1b2c3d4e5434156536964a98033271711305e2315ec0dab01dd636daf3f3d24"
                    "f85855f384ffb607e15f7479d3f999"
                ),
                "CAVSTag": "b3b1afdd72c028ecc7e1f99065439608",
                "Z": "730ba118d1e795e4be965263d0a9fdc53532dd0f864cd09f5b152de7ecd5f2bc",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e5aab1b13842ef6dadf465700163067b"
                    "2812684713c9beb678810c79d2f7d1a8981bf139ca3a6980574abfb0e316d864"
                    "cdf296fbf444924dda65d93255f31f4f6b"
                ),
                "DKM": "507d1de2bc5a21d73fdd4fd2ee3e22e61422e360bad13d88831764113e23b757",
                "Result": False,
                "errno": 1,  # CAVS's Static public key X fails PKV 5.6.2.5
            },
            {
                "COUNT": "1",
                "dsCAVS": "b7757e002d9b7afbf76fd0c59a5d24a3bfc18a8219550d2a46dfbf10bcf912d2",
                "QsCAVSx": "19572c94032cab024f08d6230b2eb301024bdf6df9c73789b9960d63c0b7cd7f",
                "QsCAVSy": "7b2ddb7b33cdcce010f0cb02731fe31f64febef223983fd948ad2f9bac5cd0ce",
                "deIUT": "a235c4cba6220a937146b6c3e36ca7c867a680598cad9ad27f9814627df986cd",
                "QeIUTx": "624a6522003c8576b3faf19a569f4de866675f5ae80cfc8762a75ab699d647a3",
                "QeIUTy": "f5561cd92c3be54d76f2b805e2c55acec62477a31d3a1ad0c35740951107e049",
                "CCMNonce": "1156052e04c430984aa3bdad11",
                "OI": (
                    "a1b2c3d4e5434156536964208bd5c82d31bfb2b025aec903a9e809be47e2df2b"
                    "7058ecfa639c0636502f7f78bd8eaa"
                ),
                "CAVSTag": "1acc74dffb965458e72af945e67cbe65",
                "Z": "042ffdeee43207064ade63862b3fa8f3a72814ce11d48df564e38747b0cb221f",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e5624a6522003c8576b3faf19a569f4d"
                    "e866675f5ae80cfc8762a75ab699d647a3f5561cd92c3be54d76f2b805e2c55a"
                    "cec62477a31d3a1ad0c35740951107e049"
                ),
                "DKM": "b06c959200ef3a2630730b604e052759df58bf7ea03d9161b8778611415fd2d3",
                "Result": True,
                "errno": 0,  # Correct
            },
            {
                "COUNT": "2",
                "dsCAVS": "d9267e6ab20efc7f2f677c0a72ec629ceb920d45f5650c04d377cb234c0ab528",
                "QsCAVSx": "0daad78d2abd865245a8f29c758340fd4dd001dadb3ed93825b6d2b1505d6e44",
                "QsCAVSy": "84f0100822f27b7d39d0b3e33a02ede7e6c3b92934b8e38692fd3e559271e504",
                "deIUT": "49444472a299228d6903f8c04f7e0f0b6e1a9396cfced92beedf05ee4fbf08f8",
                "QeIUTx": "7f8a540fdff29bba70429a894e3b2f484e140130b952e53afbaef790e739bddc",
                "QeIUTy": "66f7f1c31fcf0a753e5f19a008d95cf24cf0545bb15c974fd1234e1941a9eebf",
                "CCMNonce": "4a6497afbf32e0f2dc6fb02f63",
                "OI": (
                    "a1b2c3d4e5434156536964361aa22057cf81ceabf5e269d9ad3a2693ec74d3be"
                    "16360dd3cf65b3850eeb9ba472b883"
                ),
                "CAVSTag": "f27efae8f581e9714cb2028844c564b7",
                "Z": "6dd8e161a5a9d9d600d5626d4ad2dbbafa68319539f3a43fb85e5c9359f4b33f",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e57f8a540fdff29bba70429a894e3b2f"
                    "484e140130b952e53afbaef790e739bddc66f7f1c31fcf0a753e5f19a008d95c"
                    "f24cf0545bb15c974fd1234e1941a9eebf"
                ),
                "DKM": "a70cc4c10905ed83793f6a91677686e7a59a8c670f3965731c95f616489a6278",
                "Result": True,
                "errno": 0,  # Correct
            },
            {
                "COUNT": "3",
                "dsCAVS": "1b497ca0a1df98f6cbcda85951d70404d54853caa399a2b91dbe77005ab97700",
                "QsCAVSx": "5b1dff9f3644f7025649d5c62f367061f27b6f46c24273349a71132025da82af",
                "QsCAVSy": "2ac6a39d468e44c5f9178a495d9d35f20a63b7ad431bcae49e6a87921d82fe08",
                "deIUT": "77b30d595b8d039716274bf5ac63afbe6ea58c8ddd3e4029772eaccdccffca52",
                "QeIUTx": "b8d6cc3f4a4afd92004585fc2f664ea12bd79037ae0a3c144b977405feed6481",
                "QeIUTy": "821ebff506587fafc3b66f583046b249aa2687021b8b133e788da3547c0a016f",
                "CCMNonce": "21f5bb55b24bdfb765e827c1e0",
                "OI": (
                    "a1b2c3d4e5434156536964929c29f6e8f7474d0f3e80bbb3befaa04a66f70548"
                    "2caa2192ac4a223612642a593b7597"
                ),
                "CAVSTag": "b5d59f2d64784239f7b39f0b4fa5e3a4",
                "Z": "78a55936f6af82380cbc622f7eed314ba79bbe1ec22dcbf80bfb70d2abe593d3",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e5b8d6cc3f4a4afd92004585fc2f664e"
                    "a12bd79037ae0a3c144b977405feed6481821ebff506587fafc3b66f583046b2"
                    "49aa2687021b8b133e788da3547c0a016f"
                ),
                "DKM": "097253a7280464c6df45799a7894c8bffa0641f5691a05c2c79c729b62fd5dd2",
                "Result": True,
                "errno": 14,  # DKM value should have leading 0 nibble
            },
            {
                "COUNT": "4",
                "dsCAVS": "84ce55ea89cd5846a0a41c746c41a2e610153e834f04bdd517cafac186f9a5f4",
                "QsCAVSx": "a62f7e553475ceee42c89e2288f59770d2eac6506b163328fd276cde74c5974f",
                "QsCAVSy": "deea12e488087c716e19b0d5438782352a2045794494d48fbdf6d9bf8c68dc5b",
                "deIUT": "fe6dd4c965ae10f48126a1dccd9b9178939ecdc7969fa3450f991a97f366093a",
                "QeIUTx": "7284a5bde044e63a12f3c1cecd832ff748a2fe7fd2a4f784b54bb46694087479",
                "QeIUTy": "2aa86e2bcaf738a0a0a433dd617c678b73f117ccac5637bdf10064cf39c9d481",
                "CCMNonce": "5f78b26173502f20d1a230740e",
                "OI": (
                    "a1b2c3d4e543415653696465c579929daa663a91495c1fcf0503d5ec31346226"
                    "24bbf1488b5ccbce0414824ae8a06f"
                ),
                "CAVSTag": "8a93deed928d04eb880bfadeb3b4909d",
                "Z": "496a854dc33c8e0be66ac2ebdad2d2107f4b82b6c3c3ad6920583f44404cdd7b",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e57284a5bde044e63a12f3c1cecd832f"
                    "f748a2fe7fd2a4f784b54bb466940874792aa86e2bcaf738a0a0a433dd617c67"
                    "8b73f117ccac5637bdf10064cf39c9d481"
                ),
                "DKM": "c6a38211de0ebffec1c40dc05739babeae6c6c49897a565fa9898f417510e3ae",
                "Result": True,
                "errno": 0,  # Correct
            },
            # Not using COUNT=5  as we are not doing key validation
            {
                "COUNT": "6",
                "dsCAVS": "eba733dc240c96875eceb2cbc7c4b775c4da98dce53780cfc9ec0f7dc9743387",
                "QsCAVSx": "fc79ccbdd629d780a34695b1a701d931b06c41bff3001eff08a5d9c590507ed2",
                "QsCAVSy": "c322e16d4e11004286cae551cdf57b74d853c68c1e7eceb32a1f87cd4930a3df",
                "deIUT": "1a9925dbf033e2e774d91b432faf937285464621403da35fea7413c61fdb6d36",
                "QeIUTx": "d164779a62408771f23d3e22be60878829c386d86bda793b7c2a4cbf86b71c36",
                "QeIUTy": "bd2341d031fc58e43ca01cdb3795f77748c8d127bbb9f4bafa7feea8f5b0e6e5",
                "CCMNonce": "251fe13e2c7fa1a05f1a786188",
                "OI": (
                    "a1b2c3d4e5434156536964427395017566581d2d5297975b35e60254e1605e24"
                    "ff983f2553d32bd1427443d591b725"
                ),
                "CAVSTag": "8a34ca6d8b63257fb1c66d75aed0ebb1",
                "Z": "8b38ba2e79aabf6427f3f8019cb35ce4b6c08dbb6c7a8adc812e76fd1e010fa8",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e5d164779a62408771f23d3e22be6087"
                    "8829c386d86bda793b7c2a4cbf86b71c36bd2341d031fc58e43ca01cdb3795f7"
                    "7748c8d127bbb9f4bafa7feea8f5b0e6e5"
                ),
                "DKM": "a4c49261de2d44c6af5817f7683f80312f1da294c5239d702d6bbb3d36242721",
                "Result": False,
                "errno": 2,  # CAVS's Static public key Y fails PKV 5.6.2.5
            },
            # Not using COUNT=7  as we are not doing key validation
            {
                "COUNT": "8",
                "dsCAVS": "6bf7ff5712f2be839e72c427240f71ae69d360d25cef7948f6da961875bdf9c8",
                "QsCAVSx": "aa5ecd446a355f9147fee31acb2315c2a07e4caf821c3483597472297e602c67",
                "QsCAVSy": "794895148918351006031d09c50fed2a7a8231de26fb35e100dd5994df76b391",
                "deIUT": "85bdeeec07c354faf04699ae274ffe35d2c0590dcd8368fa2a83895adbccd392",
                "QeIUTx": "4087e5708a43f5567575a6406f975f25565529b5261aac32b53f6d282faf68e0",
                "QeIUTy": "19145c60ced476178a4444d3258903dfe84ce3e0516653e056d510c45d8286b9",
                "CCMNonce": "f9cb85f24b11415b7a83253789",
                "OI": (
                    "a1b2c3d4e54341565369645b9739bf9cacb655f1a4263bdd493f21dd7481549b"
                    "750d4064b4ba33dc996663f0aa8a33"
                ),
                "CAVSTag": "d53fdf34a731418916cc84f9fac21949",
                "Z": "0baa81f509281591a0e54b3b8c0d5d6d7852547ea0c3b854de70aa3fa9c73768",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e54087e5708a43f5567575a6406f975f"
                    "25565529b5261aac32b53f6d282faf68e019145c60ced476178a4444d3258903"
                    "dfe84ce3e0516653e056d510c45d8286b9"
                ),
                "DKM": "2a96a76a521383ac1ee26f25e8e6e6abc28c4db92cdf3b96aaf8d4f1ca49be20",
                "Result": True,
                "errno": 13,  # Z value should have leading 0 nibble
            },
            # Not sure why COUNT=9 is marked as "DKM changed", as DKM matches expected. May be
            # a part of key validation
            {
                "COUNT": "10",
                "dsCAVS": "b687cb6d92e075a26be081495fb3dbcb0c2fe361f75b96f662ca462c9a704874",
                "QsCAVSx": "f07788f2b1dbdf5e63ef09579936bd44ede1bdc23d4760125c3193e350188fd5",
                "QsCAVSy": "8bd38187045747859c4a72214d6e423a5d89a3143aa623b171ffd44a84d7347b",
                "deIUT": "3c9fc1b2ffe9da2f140fa53586a873aebbf2df2071ef316ac03df87fd1cbcaa4",
                "QeIUTx": "1d79f16d0756a4607954457f274f9e7c344ccae7bf633867ab50825d202da1ec",
                "QeIUTy": "e60d44ec51ba05822bc9942a583b2f28c6380caca19c2f325d4431c07b9669ff",
                "CCMNonce": "cd2023157911b18ef1496e6772",
                "OI": (
                    "a1b2c3d4e543415653696447b290071f5279312dbea982db0eeb637f8d6e1cd2"
                    "60d396a4688565ce694905676b1664"
                ),
                "CAVSTag": "12102679d61ba4b91f6ecc94e858f10c",
                "Z": "2d9b6457f1475d3143afc15b2e7528ed1d6b255cefee352abc15f1481dad802d",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e51d79f16d0756a4607954457f274f9e"
                    "7c344ccae7bf633867ab50825d202da1ece60d44ec51ba05822bc9942a583b2f"
                    "28c6380caca19c2f325d4431c07b9669ff"
                ),
                "DKM": "bb70d30146054017a1b0c1560fddf387b3ab3b034aaf2efc8926ff9cf55f45e1",
                "Result": True,
                "errno": 0,  # Correct
            },
            # Skippig COUNT=11 as we aren't checking Z, only DKM = KDF(Z)
            # Not sure why COUNT=2 works, when it shouldn't, may be testing key validation
            {
                "COUNT": "13",
                "dsCAVS": "3f2cf0b4440829264fe4c283528315b1791f3a303d5b6c360148011325024c46",
                "QsCAVSx": "ab305f835862eac7ac543d51633cc637846207e4cc2ffdd94a8748b583e631d0",
                "QsCAVSy": "aad4aadbfefa7cf349374620409512a5536f37880c1ce93f93df51a4b0fd7d1a",
                "deIUT": "dba3921f605cf1a291950938f7bcda3eaa4e1f5cbdcd044b1cbd020f1e71e08b",
                "QeIUTx": "7c41bd83e5bd3142d6f57181f0bc6285f546a0632e36d3806708053ca901b877",
                "QeIUTy": "6d494921106534db2f862beda4d1a14ccc5fcf6dcaf41e17fe5431e4fa160df0",
                "CCMNonce": "843bf88b215ce11fb1080b5e07",
                "OI": (
                    "a1b2c3d4e5434156536964b7e01b71c86b7c8624cc3fd2c3a6c444a68bad0a19"
                    "273f6035bb0aa6a8ceccb6b91f9374"
                ),
                "CAVSTag": "71a4e3a54eee76f24cde89d5f2fdcfb4",
                "Z": "a9ff8a7e2f7548456d1defda785033f3a317d3f1630e6ff27f321cb3613665c7",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e57c41bd83e5bd3142d6f57181f0bc62"
                    "85f546a0632e36d3806708053ca901b8776d494921106534db2f862beda4d1a1"
                    "4ccc5fcf6dcaf41e17fe5431e4fa160df0"
                ),
                "DKM": "3e79cc2ba3d9f7636b7885fe051ce4ad8f5af864747a25cb503bd967602d842f",
                "Result": True,
                "errno": 0,  # Correct
            },
            {
                "COUNT": "14",
                "dsCAVS": "7b5a0c9338413287ea6175859ee1fe3bb93e6cc136d520381fc0594d051e46cb",
                "QsCAVSx": "240921ef16b8ab315ca72b2d09cdc09499bf481e481a572fdc22fb50bed5a412",
                "QsCAVSy": "b59f08b23a445458ada3a776e964989add7a29ec8526a6c2966a5b04ba69dbd2",
                "deIUT": "994177e5a54fb2774329e51e239d81faba9d30376d40a6e711c22c08556d8fe9",
                "QeIUTx": "c38dc31156a6ff5ab4f364d530e71c9635210bff3fd4260aa9901ec3195b5a75",
                "QeIUTy": "1c795267f9cb10cbafd0c5677b4cd1180230222e70b865085e7c405a447ab2ed",
                "CCMNonce": "f4f87261abfa320c294257e9ef",
                "OI": (
                    "a1b2c3d4e5434156536964ef7968a5c316899ffe293df3ebe5c27d491b72b9f1"
                    "508c7bb91337e0978ec4840a5a34f5"
                ),
                "CAVSTag": "495f3033b4113b6774709ce03abb931c",
                "Z": "7409911f0a73fa2f8ffaabfd4df421c911b8e34e5df6587b897713feb7f5443f",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e5c38dc31156a6ff5ab4f364d530e71c"
                    "9635210bff3fd4260aa9901ec3195b5a751c795267f9cb10cbafd0c5677b4cd1"
                    "180230222e70b865085e7c405a447ab2ed"
                ),
                "DKM": "0360c8b28d94724cc0172ab253c8be32c97e401e5acbb8f6156a197b2f0b1a5c",
                "Result": True,
                "errno": 0,  # Correct
            },
            {
                "COUNT": "15",
                "dsCAVS": "1c9cf449e0c26bac6e53434bb1eb1109b0d949ade949a7f3f5cf959ec3efb151",
                "QsCAVSx": "a23277ff06cedfd9af5830e76ec21f622c055e1980da8fe3e4bdc4890ba6c0ec",
                "QsCAVSy": "9fb7e6e2d1e3340cb731032f774541866f5bb9e35ce02e94206deadf213762a0",
                "deIUT": "e45ae4860d9ae551c636469b336a3e3359b60a37c9b33a5174195b5f3e24f119",
                "QeIUTx": "87d59e270162c1e3eee1a67222b0bb6af2637f161e668417f27bfab1d05ee64c",
                "QeIUTy": "774c4cde652b6e36b812750237095ea98545e396eafd49cda93eee6fb673f61a",
                "CCMNonce": "d54418e97be4bd9fa3cb2a368a",
                "OI": (
                    "a1b2c3d4e5434156536964b3b8d667a410941cf70143c907cc334ad1c86b5daa"
                    "4cf8a82dcf85fe784e2cde98ef8c3c"
                ),
                "CAVSTag": "67a06652bec05456987e7106a1cdc593",
                "Z": "92d8b21a9597ce23fb5d2a9db40c5e91b8865f7ba70e514ae19f5ac529e84af7",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e587d59e270162c1e3eee1a67222b0bb"
                    "6af2637f161e668417f27bfab1d05ee64c774c4cde652b6e36b812750237095e"
                    "a98545e396eafd49cda93eee6fb673f61a"
                ),
                "DKM": "bea6569ce5c30133a0f9cbd81bcfc5ac66dbcd256281d6c750f10cde0428d07e",
                "Result": False,
                "errno": 1,  # CAVS's Static public key X fails PKV 5.6.2.5
            },
            # Skipping COUNT=16 as we aren't checking Z, only DKM = KDF(Z)
            {
                "COUNT": "17",
                "dsCAVS": "73f055106659418828c485dababab048802765ded1f457a33126573749578157",
                "QsCAVSx": "cf9daa70272378942c127163161da82f140b7ce28371dbed0c6ee88dd65c4756",
                "QsCAVSy": "e03f9915ca4dd2a92ed8a3db179d18d847b1105c17cbf02c9d3a5a273f5f897c",
                "deIUT": "ad0183ed9996fea214e311e6f08a51e4fca21192f698ed8ec6c0dac96559f441",
                "QeIUTx": "54c7b5b1b017a9a078f467b35ec7f5755d9f8332cc5b94838fb165f739bccf21",
                "QeIUTy": "66934f95868fa0d3b64eef8a2840594c27cb5ca2d1ad548e963a997968be1bec",
                "CCMNonce": "65cef6472a6c8f5b8caed4af6a",
                "OI": (
                    "a1b2c3d4e5434156536964badfa17a83dede5673c05abcf55e5c652f4bf7a673"
                    "ad8ee8d64c98581ee9a1e0e2d19155"
                ),
                "CAVSTag": "3ef8605dbf1be9827f2475c348841961",
                "Z": "f2928b050b6f1eccdc16f8ca0b8f9b76211308e60f17ab9360b3ed26e14043fe",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e554c7b5b1b017a9a078f467b35ec7f5"
                    "755d9f8332cc5b94838fb165f739bccf2166934f95868fa0d3b64eef8a284059"
                    "4c27cb5ca2d1ad548e963a997968be1bec"
                ),
                "DKM": "79baea0d4c3bf2d595fc7ea4992bfe80b54e23bce6e9615b103d0059c8e0a1d7",
                "Result": False,
                "errno": 2,  # CAVS's Static public key Y fails PKV 5.6.2.5
            },
            {
                "COUNT": "18",
                "dsCAVS": "971628ddadbcddfb922e70287a9adbfa30f7ac6bb2701a87527bec6e88ec1316",
                "QsCAVSx": "9868a83022febb4cab175df1e934245a25d095e50409f73b5d7a36097ff94d81",
                "QsCAVSy": "0eb09f73a870bd27b21d545a1baeed4936ad2ebd3ca9c7669fb2243710126a9f",
                "deIUT": "0df0aea34080f8618095381af570a8bdea639fc33aab814a3b3fffd7ede96067",
                "QeIUTx": "abcc7d56962bf462f73f7f503be442dd50f7faf4a94ae4e12f1576960b8596d2",
                "QeIUTy": "c67c4ba91ee820717085de45583c1093a8b47bb534607b3a85075d0303e2db1e",
                "CCMNonce": "9f52311f65537aa4f68284feba",
                "OI": (
                    "a1b2c3d4e54341565369649800d0f9a3664ac6ca8475f46f4562e4c22b574fe2"
                    "e6167f452562bf59acc0106ba67b1d"
                ),
                "CAVSTag": "b41648c98a7f07c644451e951cdf3522",
                "Z": "0a91f19edbd51ce5263d47deebca3b3b155751c7eb8157aade1205b850175bc7",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e5abcc7d56962bf462f73f7f503be442"
                    "dd50f7faf4a94ae4e12f1576960b8596d2c67c4ba91ee820717085de45583c10"
                    "93a8b47bb534607b3a85075d0303e2db1e"
                ),
                "DKM": "13894d83f2ccccd3b63f7fcbcc4fb025e734032b9e520fab5a1328c0cc38c5cc",
                "Result": True,
                "errno": 13,  # Z value should have leading 0 nibble
            },
            {
                "COUNT": "19",
                "dsCAVS": "c4065b9085d4c0f38d9aa7d6866e4230771d1714575a1a432f9a676b001e36b3",
                "QsCAVSx": "d7b7298026823282ff8368bdd400eedde82a28ca704c311e408fdf4b40effde5",
                "QsCAVSy": "94b17296022f27ba3f8f09ab513cc396a02a4378c8a44162e3924dd026cb4528",
                "deIUT": "333caadc8cba879cc7cc94f2f6ca7be7500257ad0b6457119053cd73f3277207",
                "QeIUTx": "a369487909814fc3399d4037e463fe807134403b8943533126856284149058a6",
                "QeIUTy": "0b9ec2046c697e28323693b8a6d9e765df48d90f443cce26a8e6e0fe0131c758",
                "CCMNonce": "b80ffb92260d5d8f0436e53a84",
                "OI": (
                    "a1b2c3d4e54341565369640be13e370c7fc1ddd14e380cc91324cf2a381df1da"
                    "1ccffd90ae436a373a600f9383b1dd"
                ),
                "CAVSTag": "6aacfe0fe8e7fb562769107bf5980b42",
                "Z": "f1a74f5c0d4ceeecd1cb15068df73e64858f6f7a40ac90ba3bce867e34f7834f",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e5a369487909814fc3399d4037e463fe"
                    "807134403b8943533126856284149058a60b9ec2046c697e28323693b8a6d9e7"
                    "65df48d90f443cce26a8e6e0fe0131c758"
                ),
                "DKM": "c90694e1f6b75611f6e44c4d7603a1ffc78c09896c1187e0ab43f4d5b5739e51",
                "Result": True,
                "errno": 0,  # Correct
            },
            {
                "COUNT": "20",
                "dsCAVS": "bf3b432d3b64d3b7d29b12b8335beb761e7e022d34a9c20b0e6133c7a0b6ecef",
                "QsCAVSx": "332873f5e7dc386db059b28d996dee0a3b11245824f02e063b0fe0e895195281",
                "QsCAVSy": "cd22fb45af7d19facccd33173a87fa7bbd3959ebcdde72d94b0b266174c9b387",
                "deIUT": "0e82fd1c88b2aeb384245851caa51d7ebca66df34afc6739e61e570d0f163d78",
                "QeIUTx": "90f5d3f7c714c81cae4a0262d9ce8629fe85c98f929d774a209c1ebf195a4bca",
                "QeIUTy": "2df3b49280fa430cc0ed8acf1a3afe740a7804894fb45a844950f36f85cecc45",
                "CCMNonce": "50cb421524d1f00f6f893b12f9",
                "OI": (
                    "a1b2c3d4e543415653696412eb216d2fa9e95304d4aa8b2c2d71fdbff7c5251b"
                    "ac8b65e4f027a049c3e40489fa9627"
                ),
                "CAVSTag": "7adb86cb75dc6b22d6f9b32a801e41e9",
                "Z": "3d3885b2fe181192165a54b02f7c1de7a7c494c96c350fd6d36a3d1ca712a1c8",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e590f5d3f7c714c81cae4a0262d9ce86"
                    "29fe85c98f929d774a209c1ebf195a4bca2df3b49280fa430cc0ed8acf1a3afe"
                    "740a7804894fb45a844950f36f85cecc45"
                ),
                "DKM": "9b71b952154b63142770f23c6c8dedc334bf9acaf36f1845c03268196ba1dfa2",
                "Result": True,
                "errno": 0,  # Correct
            },
            # Not sure why COUNT=21 is marked as "DKM changed", as DKM matches expected. May be
            # a part of key validation
            {
                "COUNT": "22",
                "dsCAVS": "bc273e80f489d70ed8c1da068fe20719384b498076cc780961ba69ba8c9e00b3",
                "QsCAVSx": "5601052c06b3a8b59396cf21be1925da225713ee4d415c778810baaeedcb667e",
                "QsCAVSy": "188aa7435b4207ae4db522414631b15b184113e45066b9f15e2e2f0d2e130a5c",
                "deIUT": "f47d59a75c44202994e0feebad7e9f9861b6a01eb1738125648536c052c824b6",
                "QeIUTx": "ba6783db86321ab1a957e0dd45d9033dfafdefc5d2090d4e229c49004268505b",
                "QeIUTy": "aea1bfcc190d33834aaf1ae4bbd0a6dc06dedddf061daf4ab4a23cd7118bda75",
                "CCMNonce": "d22480e4fcdcf5ebfae9f99af4",
                "OI": (
                    "a1b2c3d4e5434156536964d0ea4c09565268f8fe3b46d251ddce31933b85d398"
                    "a90340da8ca7adc86289216002b0d6"
                ),
                "CAVSTag": "c4b056c07a3b1f4a4770a0dadbffe330",
                "Z": "e599dfd15aa5b3875ba8a30696ba53252321625553b9a907897f60b6b7c7b7ea",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e5ba6783db86321ab1a957e0dd45d903"
                    "3dfafdefc5d2090d4e229c49004268505baea1bfcc190d33834aaf1ae4bbd0a6"
                    "dc06dedddf061daf4ab4a23cd7118bda75"
                ),
                "DKM": "1febe90df557326deb2c3424895c1c4c4a1efedb69628d3117573287dfbedb43",
                "Result": True,
                "errno": 0,  # Correct
            },
            # Not using COUNT=23  as we are not doing key validation
            {
                "COUNT": "24",
                "dsCAVS": "af80ece61de5bd77849ca9edc6d867c8a5920e8a0b9a717b6e6f4192f5a4ba21",
                "QsCAVSx": "7cba6558453fe19e641fbde76d3c5987c0bdc845d9cbdd5f41fa29c27ad8bde0",
                "QsCAVSy": "d7bf2539f39a6ece292b5ddc455ed829c750575b29be343f02e5058b59637677",
                "deIUT": "3b92f74f8c40ac09575e282cb45bd64d530e153255474c9aa35d0874f0543e56",
                "QeIUTx": "58558d3e7ecb148aa0cc19d8aa3de175b8eb5eaf3965d4c2155900424a0c29fa",
                "QeIUTy": "b35bc5f7058fc788a5cfd7f566e103e71b0f118357bd1e0ee7996903a38d7acd",
                "CCMNonce": "d138db9ebed322bcceacc39938",
                "OI": (
                    "a1b2c3d4e543415653696486607205e3b85cb5d03c2a7a2c624c9c76bcda5d31"
                    "cd1d738d1b51bc4385a92ec1d7940d"
                ),
                "CAVSTag": "0fcaefcce356c5186fade5b13e1eb33a",
                "Z": "ae80f8f68b7db1e8232378bbfd016d06232f16e7869218158d9357fac8868571",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e558558d3e7ecb148aa0cc19d8aa3de1"
                    "75b8eb5eaf3965d4c2155900424a0c29fab35bc5f7058fc788a5cfd7f566e103"
                    "e71b0f118357bd1e0ee7996903a38d7acd"
                ),
                "DKM": "700894558d6af3e0efc1d08cca8bcec2ac619dab53bbab5be522f74b62821f63",
                "Result": True,
                "errno": 0,  # Correct
            },
            {
                "COUNT": "25",
                "dsCAVS": "f65ce6e3eb5b0fcd2c224dab57629123df1c59d42b7a5114678b92f3b7a5a209",
                "QsCAVSx": "21c1d079a835f4e6ed38d76719bfb959170817f651b79ee92ed944cba5441797",
                "QsCAVSy": "79dc92df057f64f98a890cd28571384beec168e12d2d7494ba7b22cd136fdc6b",
                "deIUT": "b4b60bdc4577714c8cfa3acfb38917b3c5d7564d560c5530d7d98dc8b8da8991",
                "QeIUTx": "e19680b60d5d6d532e7542603662e1ba947a67363977cb07da1d90c811c4192f",
                "QeIUTy": "3d4aa730c26637fcdb9af0e74f61bc8b0a16bbcec3611baa93aad7decba4db61",
                "CCMNonce": "6b2a14d5493b2901c20f29cd3a",
                "OI": (
                    "a1b2c3d4e5434156536964cd161f482fbff2a2eb7456287d92c6c048bde3ce2c"
                    "25b09d5a0701016776313aa05b141c"
                ),
                "CAVSTag": "56c3a514f3c189e6ff41700d71fdfcb9",
                "Z": "ca1dd4ea3fcd2636216caea121fefa9a7243e0c874140c563bdf89899b0d096a",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e5e19680b60d5d6d532e7542603662e1"
                    "ba947a67363977cb07da1d90c811c4192f3d4aa730c26637fcdb9af0e74f61bc"
                    "8b0a16bbcec3611baa93aad7decba4db61"
                ),
                "DKM": "bd7425c3b573e5569bd92e82f3c35f76ae0705e58b6c9e6563746c7fc85716dd",
                "Result": True,
                "errno": 0,  # Correct
            },
            {
                "COUNT": "26",
                "dsCAVS": "3e9cecdd90fb68f446cc9503cf538a061b6923f56428449a3aad3d24a0654080",
                "QsCAVSx": "1e2a99aa1d36c64b83d0eb301427a2e9144c795846832e681015c0b316ad22bf",
                "QsCAVSy": "34490b9ad244fa0ec0981ed6daebecd8435da5f77a25ffa9be9385b7f44b804d",
                "deIUT": "54a8c21fa068c0e9acaad084293a9324394f972264dd2222b136888136d77bc3",
                "QeIUTx": "81eaa64483e11cac4cfa55042c9073af8e658a6551ca12228aa150238b674533",
                "QeIUTy": "7cc75e8a521b548b685821ce32d5cc63cd6f179ea1790050b3efdac18a98d3fd",
                "CCMNonce": "edb1af87767585d74dd9d7aabc",
                "OI": (
                    "a1b2c3d4e5434156536964b2225bc72f2233f1d30a3ccf8e1b86c091d06c42b3"
                    "b51864147c4a7e004e541f165f6a47"
                ),
                "CAVSTag": "5236954327fd1c772204b6c80fdd81d9",
                "Z": "8f1c402476a1ce5482e1f20c9400fddd370846ed15107716cefc679a243e743d",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e581eaa64483e11cac4cfa55042c9073"
                    "af8e658a6551ca12228aa150238b6745337cc75e8a521b548b685821ce32d5cc"
                    "63cd6f179ea1790050b3efdac18a98d3fd"
                ),
                "DKM": "0cd80e81897a7d69a735cc34c93230d0bd5df4d29976016c914ef2ab2bb138ee",
                "Result": True,
                "errno": 14,  # DKM value should have leading 0 nibble
            },
            {
                "COUNT": "27",
                "dsCAVS": "2c807902a704c607ff5ced6240eaaed76be93ab5277fd1a35d8835801b805912",
                "QsCAVSx": "99300c5b854b338eb5ad4fc1d37b39193c063f8ed2b886b77532a7866a88631b",
                "QsCAVSy": "6b1006910ed0c30b8a203f066e5ec0aa486437f81f6f8a8fe6c5e80a675bd0d7",
                "deIUT": "ec39d15b74c62ddbc04147f6901b67265bf259f556bebb3c15e42e3800db5081",
                "QeIUTx": "4d01a3cecc758d5d31b74583fe990f93dd8867664a7eae7d919c60a5017fa6a4",
                "QeIUTy": "516f995f57d01c3290e9fb3432c1eec5c2312c2e251eb414a1516d9bd1a2dd44",
                "CCMNonce": "fc68adb6c01fbe1d0141ee0fe4",
                "OI": (
                    "a1b2c3d4e5434156536964e788d9f273bdeee54e54f1bf56c259b046e36195dc"
                    "8f51283b6f00748e0e978dee33977d"
                ),
                "CAVSTag": "06e9fc35b4b50bc6987ce020c313d665",
                "Z": "50f6ee49c690f2e5b01ba70011cc88575f8a4d41d44fd244f97fd7f3ed73cb04",
                "MacData": (
                    "4b435f315f56434156536964a1b2c3d4e54d01a3cecc758d5d31b74583fe990f"
                    "93dd8867664a7eae7d919c60a5017fa6a4516f995f57d01c3290e9fb3432c1ee"
                    "c5c2312c2e251eb414a1516d9bd1a2dd44"
                ),
                "DKM": "0d30b098fe0bda5394d5ef97b03ef2c556a52793431fbbdafb350a350c6de04e",
                "Result": True,
                "errno": 0,  # Correct
            },
            # Not using COUNT=28  as we are not doing key validation
            # Not sure why COUNT=29 works, when it shouldn't, may be testing key validation
        ]

        for vec in _CAVS_VECTORS:
            logger.debug('COUNT=%s, Result=%s/%s', vec['COUNT'], vec['Result'], vec['errno'])
            otherinfo = hex2bytes(vec['OI'])

            ux = vec['QeIUTx']
            uy = vec['QeIUTy']
            ud = vec['deIUT']

            u_private_keypair = keypair_from_nist_hex(ux, uy, ud, otherinfo)
            u_public_keypair = _private_to_public(u_private_keypair)

            ux = vec['QsCAVSx']
            uy = vec['QsCAVSy']
            ud = vec['dsCAVS']

            if not vec['Result'] and vec['errno'] in [1, 2]:
                with self.assertRaises(ValueError):
                    v_private_keypair = keypair_from_nist_hex(ux, uy, ud, otherinfo)
                    # v_public_keypair = _private_to_public(v_private_keypair)
            else:
                v_private_keypair = keypair_from_nist_hex(ux, uy, ud, otherinfo)
                v_public_keypair = _private_to_public(v_private_keypair)

                ku = u_private_keypair.ecdh(v_public_keypair)
                kv = v_private_keypair.ecdh(u_public_keypair)

                self.assertEqual(len(ku), 32)
                self.assertEqual(len(kv), 32)

                if vec['Result']:
                    dkm = hex2bytes(vec['DKM'])
                    self.assertEqual(len(dkm), 32)

                    self.assertEqual(ku, dkm)
                    self.assertEqual(kv, dkm)

                    eve_keypair = service.create_secret_key()
                    keve = eve_keypair.ecdh(u_private_keypair)
                    self.assertNotEqual(ku, keve)
                else:
                    self.assertNotEqual(ku, kv)
