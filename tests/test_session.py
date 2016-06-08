import logging

import unittest
import mock

from cryptography.exceptions import InvalidSignature

from oneid import session, service, keychain, jwts, exceptions

logger = logging.getLogger(__name__)


def mock_request(http_method, url, headers=None, data=None):
    """
    Mock an HTTP GET Request
    :param http_method: GET, PUT, POST, DELETE
    :param url: url that will be overridden
    :param headers: Dictionary of additional header params
    :param data: Body/payload
    :return: :class:`~oneid.test_session.MockResponse`
    """
    class MockResponse:
        def __init__(self, response, status_code):
            self.content = response
            self.status_code = status_code

    if url == 'https://myservice/my/endpoint':
        if http_method.lower() == 'post':
            try:
                jwt_header, jwt_claims, jwt_sig = data.split('.')
            except IndexError:
                return MockResponse('Bad Request', 400)

            try:
                key = keychain.Keypair.from_secret_pem(
                    key_bytes=TestSession.id_key_bytes
                )
                payload = '{}.{}'.format(jwt_header, jwt_claims)
                key.verify(payload, jwt_sig)
            except InvalidSignature:
                return MockResponse('Forbidden', 403)

            return MockResponse('hello world', 200)
        elif http_method.lower() == 'get':
            return MockResponse('tested', 200)
        else:
            return MockResponse('Method Not Allowed', 405)

    elif url == 'https://myservice/unauthorized':
        return MockResponse('Forbidden', 403)

    else:
        logger.debug('url not found: %s', url)
        return MockResponse('Not Found', 404)


class TestSession(object):
    id_key_bytes = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCC' \
                   'qGSM49AwEHBG0wawIBAQQgbKk/yDq5mmGkhs7b\nLNiCMv25GvwYZNt' \
                   'S5JYUh4OLafKhRANCAAQ0B+TfNujp2TNlw+zufTwzZSv3yU9U\ncbl+' \
                   'Ip5kv8Snpp8ksaAGI+DSL7KCih3DXWr9b3Mwjcx0Uxzyrh0Y40z4\n-' \
                   '----END PRIVATE KEY-----'

    proj_key_bytes = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEG' \
                     'CCqGSM49AwEHBG0wawIBAQQgfI4sVem1tP+C8vmR\nZjgvAi2JTPK' \
                     'mDq6xasysp92WJEyhRANCAAQGFnKI49VPfm09stPFcREzzh0NE8OY' \
                     '\n1s6SabuTGcRKLevloCXsTD0+RhzqorXdZ63pk3B5ac9Ddd+8PWH' \
                     'pzUoz\n-----END PRIVATE KEY-----\n'

    app_key_bytes = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGC' \
                    'CqGSM49AwEHBG0wawIBAQQgLIGoI9j4s6ogppvx\nqf1j8ShoiiDFo' \
                    '2DndqhaAONXhkqhRANCAAQz7gH1LfLxD+8GmHAVFw1LWI6LK1GL\n2' \
                    'wNYb5NxR4ZHQKg/odM76371cvsaMa/w0WtwZ5b8aNKAUGqS+YO+v6m' \
                    'P\n-----END PRIVATE KEY-----\n'

    oneid_key_bytes = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgE' \
                      'GCCqGSM49AwEHBG0wawIBAQQgm0PZgUme63i6fC/G\nmNSSsFliy' \
                      'wt1eAOoW6Dm/Wz0UrihRANCAATbU7pd0Vg/MYuGOW8E+kpfuo4ov' \
                      '/il\nI9HAi/wHxHqlSxbzagczAUo9kNr4r2w3eTtvf4EuXaC9ZEC' \
                      '9xXCLRCpH\n-----END PRIVATE KEY-----\n'

    reset_key_A_bytes = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49A' \
                        'gEGCCqGSM49AwEHBG0wawIBAQQgoipfyjtZXMp5pV/V\naTMQQ' \
                        'Xg3BX78uMgM7ePLw7y740ShRANCAATcaPOHf92vDJqOxvny/4B' \
                        'qQhuThy3o\nbzqDKss/lRiEd3hRpEcnFkA1/5J7YD27d+Rwce8' \
                        'c3Mv5Fw+0EvTEfxvj\n-----END PRIVATE KEY-----\n'

    reset_key_B_bytes = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49A' \
                        'gEGCCqGSM49AwEHBG0wawIBAQQgGnaOW5frHzPyaxsq\noL5Ay' \
                        'lzMQR3n+noiYg6CuUUaNlWhRANCAATk2/T8BgFV9DkdvRZvquF' \
                        'zXII+zuKG\nQ9asmASeRMfM3/HNmMGil82P7PTCGsuumbWhX+T' \
                        'y0G3eZNE0FbLAK3o+\n-----END PRIVATE KEY-----\n'

    reset_key_C_bytes = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49A' \
                        'gEGCCqGSM49AwEHBG0wawIBAQQgySmjxLPOGxKxSqaT\nGGcjT' \
                        'JqbYGgFsnjBTsZ+p4GJ9bqhRANCAASk4ktRaOwSpyB6yQ4kCbh' \
                        'sV0KH9eZs\n+s7j/IlzbF0J0uwWeVYZifZxMS4dde/mWBvapkT' \
                        'a+oTiSEQoAwuVe4t3\n-----END PRIVATE KEY-----\n'


class TestBaseSession(unittest.TestCase):
    def test_invalid_method(self):
        base = session.SessionBase()
        self.assertRaises(TypeError, base.make_http_request,
                          "UNKOWN", "http://localhost:8080")

    @mock.patch('oneid.session.request', side_effect=mock_request)
    def test_authentication_error(self, mock_request):
        base = session.SessionBase()
        self.assertRaises(exceptions.InvalidAuthentication,
                          base.make_http_request,
                          "GET",
                          "https://myservice/unauthorized")


class TestDeviceSession(unittest.TestCase):
    def setUp(self):
        self.mock_id_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.id_key_bytes
        )
        self.mock_id_keypair.identity = 'device-id'

        self.id_credentials = keychain.Credentials(
            self.mock_id_keypair.identity,
            self.mock_id_keypair
        )

        self.mock_proj_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.proj_key_bytes
        )
        self.mock_proj_keypair.identity = 'proj-id'

        self.proj_credentials = keychain.Credentials(
            self.mock_proj_keypair.identity,
            self.mock_proj_keypair
        )

        self.mock_oneid_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.oneid_key_bytes
        )
        self.mock_oneid_keypair.identity = 'oneid-id'

        self.oneid_credentials = keychain.Credentials(
            self.mock_oneid_keypair.identity,
            self.mock_oneid_keypair
        )

        self.mock_resetA_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.reset_key_A_bytes
        )
        self.mock_resetA_keypair.identity = 'resetA-id'

        self.resetA_credentials = keychain.Credentials(
            self.mock_resetA_keypair.identity,
            self.mock_resetA_keypair
        )

        self.mock_resetB_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.reset_key_B_bytes
        )
        self.mock_resetB_keypair.identity = 'resetB-id'

        self.resetB_credentials = keychain.Credentials(
            self.mock_resetB_keypair.identity,
            self.mock_resetB_keypair
        )

        self.mock_resetC_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.reset_key_C_bytes
        )
        self.mock_resetC_keypair.identity = 'resetC-id'

        self.resetC_credentials = keychain.Credentials(
            self.mock_resetC_keypair.identity,
            self.mock_resetC_keypair
        )

    def test_prepare_message(self):
        sess = session.DeviceSession(self.id_credentials)
        jws = sess.prepare_message(a=1)

        claims = jwts.verify_jws(jws, self.id_credentials.keypair)

        self.assertIsInstance(claims, dict)
        self.assertIn("a", claims)
        self.assertEqual(claims.get("a"), 1)

    def test_verify_message(self):
        message = jwts.make_jws(
            {'b': 2},
            [self.mock_proj_keypair, self.mock_oneid_keypair]
        )

        sess = session.DeviceSession(
            self.id_credentials, self.proj_credentials, self.oneid_credentials
        )

        claims = sess.verify_message(message)
        self.assertIsInstance(claims, dict)
        self.assertIn("b", claims)
        self.assertEqual(claims.get("b"), 2)

    def test_verify_message_with_rekey(self):
        message = jwts.make_jws({'c': 3}, [
            self.mock_proj_keypair, self.mock_oneid_keypair,
            self.mock_resetA_keypair,
            self.mock_resetB_keypair,
            self.mock_resetC_keypair,
        ])

        sess = session.DeviceSession(
            self.id_credentials, self.proj_credentials, self.oneid_credentials,
        )

        claims = sess.verify_message(message, rekey_credentials=[
            self.resetA_credentials,
            self.resetB_credentials,
            self.resetC_credentials,
        ])

        self.assertIsInstance(claims, dict)
        self.assertIn("c", claims)
        self.assertEqual(claims.get("c"), 3)

    def test_verify_message_with_rekey_keys_only(self):
        message = jwts.make_jws({'d': 4}, [
            self.mock_resetA_keypair,
            self.mock_resetB_keypair,
            self.mock_resetC_keypair,
        ])

        sess = session.DeviceSession(
            self.id_credentials, self.proj_credentials, self.oneid_credentials,
        )

        claims = sess.verify_message(message, rekey_credentials=[
            self.resetA_credentials,
            self.resetB_credentials,
            self.resetC_credentials,
        ])

        self.assertIsInstance(claims, dict)
        self.assertIn("d", claims)
        self.assertEqual(claims.get("d"), 4)


class TestServerSession(unittest.TestCase):
    def setUp(self):
        mock_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.id_key_bytes
        )
        mock_keypair.identity = 'server'
        self.server_credentials = keychain.Credentials(mock_keypair.identity,
                                                       mock_keypair)

        mock_oneid_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.oneid_key_bytes
        )
        mock_oneid_keypair.identity = 'oneID'
        self.oneid_credentials = keychain.Credentials(
            mock_oneid_keypair.identity, mock_oneid_keypair
        )

        mock_project_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.proj_key_bytes
        )
        mock_project_keypair.identity = 'proj'
        self.project_credentials = keychain.Credentials(
            mock_project_keypair.identity, mock_project_keypair
        )
        mock_resetA_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.reset_key_A_bytes
        )
        mock_resetA_keypair.identity = 'resetA-id'
        self.resetA_credentials = keychain.Credentials(
            mock_resetA_keypair.identity, mock_resetA_keypair
        )

        mock_resetB_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.reset_key_B_bytes
        )
        mock_resetB_keypair.identity = 'resetB-id'
        self.resetB_credentials = keychain.Credentials(
            mock_resetB_keypair.identity, mock_resetB_keypair
        )

        mock_resetC_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.reset_key_C_bytes
        )
        mock_resetC_keypair.identity = 'resetC-id'
        self.resetC_credentials = keychain.Credentials(
            mock_resetC_keypair.identity, mock_resetC_keypair
        )

        self.oneid_response = jwts.make_jwt({'a': 1}, mock_oneid_keypair)
        # TODO: JWS with both

        self.fake_config = {
            'GLOBAL': {
                'base_url': 'https://myservice',
            },
            'test_service': {
                'test_method': {
                    'endpoint': '/my/endpoint',
                    'method': 'GET',
                    'arguments': {},
                },
            },
        }

    def test_init_from_config(self):
        sess = session.ServerSession(config={})
        with self.assertRaises(AttributeError):
            getattr(sess, "test_service")

        sess = session.ServerSession(
            identity_credentials=self.server_credentials,
            config=self.fake_config,
        )

        self.assertTrue(hasattr(sess, "test_service"))

    @mock.patch('oneid.session.request', side_effect=mock_request)
    def test_service_request(self, mock_request):
        sess = session.ServerSession(
            identity_credentials=self.server_credentials,
            config=self.fake_config,
        )

        test_method = sess.test_service.test_method()
        self.assertEqual(test_method, "tested")

    def test_prepare_message(self):
        sess = session.ServerSession(
            identity_credentials=self.server_credentials,
            oneid_credentials=self.oneid_credentials,
            project_credentials=self.project_credentials)

        authenticated_data = sess.prepare_message(
            oneid_response=self.oneid_response
        )

        keypairs = [
            self.oneid_credentials.keypair,
            self.project_credentials.keypair,
        ]

        verified = jwts.verify_jws(authenticated_data, keypairs)
        self.assertIsInstance(verified, dict)

    def test_prepare_message_no_project(self):
        sess = session.ServerSession(
            identity_credentials=self.server_credentials,
            oneid_credentials=self.oneid_credentials
        )

        with self.assertRaises(AttributeError):
            sess.prepare_message()

    def test_reset_keys(self):
        sess = session.ServerSession(
            identity_credentials=self.server_credentials,
            oneid_credentials=self.oneid_credentials,
            project_credentials=self.project_credentials
        )

        authenticated_data = sess.prepare_message(
            oneid_response=self.oneid_response,
            rekey_credentials=[
                self.resetA_credentials,
                self.resetB_credentials,
                self.resetC_credentials,
            ]
        )

        keypairs = [
            self.oneid_credentials.keypair,
            self.project_credentials.keypair,
            self.resetA_credentials.keypair,
            self.resetB_credentials.keypair,
            self.resetC_credentials.keypair,
        ]

        verified = jwts.verify_jws(authenticated_data, keypairs)
        self.assertIsInstance(verified, dict)


class TestAdminSession(unittest.TestCase):
    def setUp(self):
        mock_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.id_key_bytes
        )
        self.credentials = keychain.Credentials('me', mock_keypair)
        mock_project_keypair = keychain.Keypair.from_secret_pem(
            key_bytes=TestSession.proj_key_bytes
        )

        self.project_credentials = keychain.Credentials(
            'proj', mock_project_keypair
        )
        self.custom_config = dict()
        global_config = self.custom_config['GLOBAL'] = dict()
        global_config['base_url'] = 'https://myservice'

        test_service = self.custom_config['test_service'] = dict()
        test_method = test_service['test_method'] = dict()
        test_method['endpoint'] = '/my/endpoint'
        test_method['method'] = 'POST'
        test_arguments = test_method['arguments'] = dict()
        test_arguments['my_argument'] = {'location': 'jwt',
                                         'required': True}

    def test_admin_session_defaults(self):
        sess = session.AdminSession(self.credentials)
        self.assertTrue(hasattr(sess, "revoke"))
        self.assertIsInstance(sess.revoke, service.BaseService)
        self.assertEqual(sess.revoke.__class__.__name__, "revoke")

    def test_admin_session_config(self):
        sess = session.AdminSession(self.credentials,
                                    config=self.custom_config)
        self.assertIsInstance(sess.test_service, service.BaseService)
        self.assertEqual(sess.test_service.__class__.__name__, 'test_service')

    def test_project_credentials(self):
        sess = session.AdminSession(self.credentials)
        self.assertIsNone(sess.project_credentials)

        sess = session.AdminSession(
            self.credentials,
            project_credentials=self.project_credentials
        )
        self.assertEqual(sess.project_credentials, self.project_credentials)

    def test_admin_session_missing_arg(self):
        sess = session.AdminSession(self.credentials,
                                    config=self.custom_config)
        self.assertRaises(TypeError, sess.test_service.test_method)

    @mock.patch('oneid.session.request', side_effect=mock_request)
    def test_admin_session_service_request(self, mock_request):
        """
        Revoke a device
        :return:
        """
        sess = session.AdminSession(self.credentials,
                                    config=self.custom_config)
        response = sess.test_service.test_method(my_argument='Hello World')
        self.assertEqual(response, 'hello world')
