# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

import unittest
import mock

from ntdi import service, session, keychain

# TODO: this is starting to look like a fixture
from .test_session import TestSession, mock_request

logger = logging.getLogger(__name__)


class TestServiceCreator(unittest.TestCase):
    def setUp(self):
        mock_keypair = keychain.Keypair.from_private_pem(
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

    def test_service_class_with_fleet_creds(self):
        mock_proj_keypair = keychain.Keypair.from_private_pem(
            key_bytes=TestSession.proj_key_bytes
        )
        proj_credentials = keychain.Credentials('proj-id', mock_proj_keypair)
        sess = session.ServerSession(self.credentials,
                                     fleet_credentials=proj_credentials)
        svc = self.service_creator.create_service_class('svc',
                                                        self.model,
                                                        sess)

        self.assertEqual(svc.__class__.__name__, "svc")
        self.assertTrue(hasattr(svc, "test_method"))

    @mock.patch('ntdi.session.request', side_effect=mock_request)
    def test_call_created_method(self, mock_request):
        test_method = self.service.test_method(in_jwt="a",
                                               in_url="b",
                                               optional=None)
        self.assertEqual(test_method, "tested")

    @mock.patch('ntdi.session.request', side_effect=mock_request)
    def test_call_created_method_with_body(self, mock_request):
        test_method = self.service.test_method(body="hello", in_url='something')
        self.assertEqual(test_method, "tested")

    @mock.patch('ntdi.session.request', side_effect=mock_request)
    def test_call_created_method_missing_args(self, mock_request):
        with self.assertRaises(TypeError):
            self.service.test_method()

    @mock.patch('ntdi.session.request', side_effect=mock_request)
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
