from __future__ import unicode_literals

import os
import json
import yaml
import collections
import logging

from requests import request
from codecs import open

from . import service, jwts, exceptions

logger = logging.getLogger(__name__)


class SessionBase(object):
    """
    Abstract Session Class

    :ivar identity_credentials: oneID identity :class:`~oneid.keychain.Credentials`
    :ivar project_credentials: unique project credentials :class:`~oneid.keychain.Credentials`
    :ivar oneid_credentials: oneID project credentials :class:`~oneid.keychain.Credentials`
    """
    def __init__(self, identity_credentials=None, project_credentials=None,
                 oneid_credentials=None, config=None):
        """

        :param identity_credentials: :py:class:`~oneid.keychain.Credentials`
        :param project_credentials: :py:class:`~oneid.keychain.ProjectCredentials`
        :param oneid_credentials: :py:class:`~oneid.keychain.Credentials`
        :param config: Dictionary or configuration keyword arguments
        :return:
        """
        self.identity_credentials = identity_credentials
        self.project_credentials = project_credentials
        self.oneid_credentials = oneid_credentials

    def _load_config(self, config_file):
        """
        Load configuration from file
        :return: dict()
        """
        # Load params from configuration file
        with open(config_file, mode='r', encoding='utf-8') as config:
            params = yaml.safe_load(config)
            return params

    def _create_services(self, methods, **kwargs):
        """
        Populate session variables and create methods from args

        :return: None
        """
        service_creator = service.ServiceCreator()

        for method in methods:
            if method != 'GLOBAL':
                setattr(self, method,
                        service_creator.create_service_class(method,
                                                             methods[method],
                                                             self,
                                                             **kwargs)
                        )

    def make_http_request(self, http_method, url, headers=None, body=None):
        """
        Generic HTTP request

        :param headers:
        :param body:
        :return:
        """
        valid_http_methods = ['GET', 'PUT', 'POST', 'DELETE']
        if http_method not in valid_http_methods:
            raise TypeError('HTTP method must be %s' %
                            ', '.join(valid_http_methods))

        req = request(http_method, url, headers=headers, data=body)

        logger.debug(
            'making http %s request to %s, headers=%s, data=%s, req=%s',
            http_method, url, headers, body, req,
        )

        # 403 is Forbidden, raise an error if this occurs
        if req.status_code == 403:
            raise exceptions.InvalidAuthentication()

        return req.content

    def service_request(self, http_method, endpoint, body=None):
        """
        Make an API Request

        :param method:
        :param endpoint:
        :param body:
        :return:
        """
        auth_jwt_header = jwts.make_jwt({}, self.identity_credentials.keypair)

        headers = {
            'Content-Type': 'application/jwt',
            'Authorization': 'Bearer %s' % auth_jwt_header
        }
        return self.make_http_request(http_method, endpoint, headers=headers, body=body)

    def prepare_message(self, *args, **kwargs):
        raise NotImplementedError

    def send_message(self, *args, **kwargs):
        raise NotImplementedError

    def verify_message(self, *args, **kwargs):
        raise NotImplementedError


class DeviceSession(SessionBase):
    def __init__(self, identity_credentials=None, project_credentials=None,
                 oneid_credentials=None, config=None):
        super(DeviceSession, self).__init__(identity_credentials,
                                            project_credentials,
                                            oneid_credentials, config)

    def verify_message(self, message, rekey_credentials=None):
        """
        Verify a message received from the server

        :param message: JSON formatted JWS with at least two signatures
        :param rekey_credentials: List of :class:`~oneid.keychain.Credential`
        :return: verified message or False if not valid
        """
        standard_keypairs = [
            self.project_credentials.keypair,
            self.oneid_credentials.keypair,
        ]

        if rekey_credentials:
            keypairs = [credentials.keypair for credentials in rekey_credentials]

            kids = jwts.get_jws_key_ids(message)
            keypairs += [keypair for keypair in standard_keypairs if keypair.identity in kids]
        else:
            keypairs = standard_keypairs

        return jwts.verify_jws(message, keypairs)

    def prepare_message(self, *args, **kwargs):
        """
        Prepare a message before sending

        :return: Signed JWT
        """
        kwargs['iss'] = self.identity_credentials.id

        return jwts.make_jwt(kwargs, self.identity_credentials.keypair)

    def send_message(self, *args, **kwargs):
        raise NotImplementedError


class ServerSession(SessionBase):
    """
    Enable Server to request two-factor Authentication from oneID
    """
    def __init__(self, identity_credentials=None, project_credentials=None,
                 oneid_credentials=None, config=None):
        super(ServerSession, self).__init__(identity_credentials,
                                            project_credentials,
                                            oneid_credentials, config)

        if isinstance(config, dict):
            params = config
        else:
            # Load default
            default_config = os.path.join(os.path.dirname(__file__),
                                          'data', 'oneid_server.yaml')
            params = self._load_config(config if config else default_config)

        self._create_services(params)

    def _create_services(self, params, **kwargs):
        """
        Populate session variables and create methods from
        :return: None
        """
        global_kwargs = params.get('GLOBAL', {})
        if self.project_credentials:
            global_kwargs['project_credentials'] = self.project_credentials

        super(ServerSession, self)._create_services(params, **global_kwargs)

    def prepare_message(self, rekey_credentials=None, **kwargs):
        """
        Build message that has two-factor signatures

        :param rekey_credentials: (optional) rekey credentials
        :type rekey_credentials: list
        :return: Content to be sent to devices
        """
        if self.project_credentials is None:
            raise AttributeError

        keypairs = [
            self.project_credentials.keypair
        ]

        if rekey_credentials:
            keypairs += [credentials.keypair for credentials in rekey_credentials]

        message = kwargs.get('raw_message', json.dumps(kwargs))

        oneid_response = self.authenticate.server(
            project_id=self.project_credentials.keypair.identity,
            identity=self.identity_credentials.keypair.identity,
            message=message
        )

        if not oneid_response:
            logger.debug('oneID refused to co-sign server message')
            raise exceptions.InvalidAuthentication

        stripped_response = jwts.remove_jws_signatures(
            oneid_response, self.identity_credentials.id
        )
        return jwts.extend_jws_signatures(stripped_response, keypairs)

    def send_message(self, *args, **kwargs):
        raise NotImplementedError

    def verify_message(self, message, device_credentials, get_oneid_cosignature=True):
        """
        Verify a message received from/through one or more Devices

        :param message: JSON formatted JWS or JWT signed by the Device
        :param device_credentials: :class:`~oneid.keychain.Credential` (or list of them)
        to verify Device signature(s) against
        :param get_oneid_cosignature: (default: True) verify with oneID first
        :return: verified message or False if not valid
        """

        if not device_credentials:
            raise AttributeError

        if not isinstance(device_credentials, collections.Iterable):
            device_credentials = [device_credentials]

        keypairs = [credential.keypair for credential in device_credentials]

        if get_oneid_cosignature:
            keypairs += [self.oneid_credentials.keypair]

            # TODO: if not already signed by oneID: (for now, do as asked, let caller deal with it)
            message = self.authenticate.edge_device(
                project_id=self.project_credentials.keypair.identity,
                identity=keypairs[0].identity,  # arbitrary choice, for endpoint
                body=message,
            )

            if not message:
                logger.debug('oneID refused to co-sign device message')
                raise exceptions.InvalidAuthentication

        return jwts.verify_jws(message, keypairs)


class AdminSession(SessionBase):
    """
    Admin Users will only interface with oneID service,
    They only need an identity_credentials and oneid_credentials
    to verify responses
    """
    def __init__(self, identity_credentials, project_credentials=None,
                 oneid_credentials=None, config=None):
        super(AdminSession, self).__init__(identity_credentials,
                                           project_credentials,
                                           oneid_credentials, config)

        if isinstance(config, dict):
            params = config
        else:
            default_config = os.path.join(os.path.dirname(__file__),
                                          'data', 'oneid_admin.yaml')
            params = self._load_config(config if config else default_config)

        self._create_services(params)

    def _create_services(self, params, **kwargs):
        """
        Populate session variables and create methods from
        :return: None
        """
        global_kwargs = params.get('GLOBAL', {})
        if self.project_credentials:
            global_kwargs['project_credentials'] = self.project_credentials

        super(AdminSession, self)._create_services(params, **global_kwargs)

    def prepare_message(self, *args, **kwargs):
        raise NotImplementedError

    def send_message(self, *args, **kwargs):
        raise NotImplementedError

    def verify_message(self, *args, **kwargs):
        raise NotImplementedError
