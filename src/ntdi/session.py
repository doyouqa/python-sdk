from __future__ import unicode_literals

import os
import yaml
import collections
import logging

from requests import request
from codecs import open

from . import service, jose, jwts, jwes, exceptions

logger = logging.getLogger(__name__)


class SessionBase(object):
    """
    Abstract Session Class

    :ivar identity_credentials: TDI identity :class:`~ntdi.keychain.Credentials`
    :ivar fleet_credentials: unique Fleet credentials :class:`~ntdi.keychain.Credentials`
    :ivar core_fleet_credentials: TDI Core Fleet credentials :class:`~ntdi.keychain.Credentials`
    :ivar core_fleet_credentials: peer credentials :class:`~ntdi.keychain.Credentials`
    :ivar config: Dictionary or configuration keyword arguments
    """
    def __init__(self, identity_credentials=None, fleet_credentials=None,
                 core_fleet_credentials=None, peer_credentials=None, config=None):
        """

        :param identity_credentials: :py:class:`~ntdi.keychain.Credentials`
        :param fleet_credentials: :py:class:`~ntdi.keychain.FleetCredentials`
        :param core_fleet_credentials: :py:class:`~ntdi.keychain.Credentials`
        :param peer_credentials: list of :py:class:`~ntdi.keychain.Credentials`
            If provided, session will be encrypted to recipients
        :param config: Dictionary or configuration keyword arguments
        :return:
        """
        self.identity_credentials = identity_credentials
        self.fleet_credentials = fleet_credentials
        self.core_fleet_credentials = core_fleet_credentials
        self.peer_credentials = peer_credentials
        if peer_credentials and not isinstance(peer_credentials, collections.Iterable):
            self.peer_credentials = [peer_credentials]

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
        Populate session variables and create methods

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

    def _get_recipient_keypairs(self, encrypt_to_peers, other_recipients):
        recipients = []

        if encrypt_to_peers and self.peer_credentials:
            recipients += self.peer_credentials

        if other_recipients:
            recipients += other_recipients

        return [c.keypair for c in recipients]

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
    def __init__(self, identity_credentials=None, fleet_credentials=None,
                 core_fleet_credentials=None, peer_credentials=None, config=None):
        super(DeviceSession, self).__init__(identity_credentials,
                                            fleet_credentials,
                                            core_fleet_credentials,
                                            peer_credentials, config)

    def verify_message(self, message, rekey_credentials=None):
        """
        Verify a message received from the Fleet

        :param message: JSON formatted JWS with at least two signatures
        :param rekey_credentials: List of :class:`~ntdi.keychain.Credential`
        :return: verified message or False if not valid
        """
        standard_keypairs = [
            self.fleet_credentials.keypair,
            self.core_fleet_credentials.keypair,
        ]

        if rekey_credentials:
            keypairs = [credentials.keypair for credentials in rekey_credentials]

            kids = [sig_params['kid'] for sig_params in jwts.get_jws_key_ids(message)]
            keypairs += [keypair for keypair in standard_keypairs if keypair.identity in kids]
        else:
            keypairs = standard_keypairs

        ret = jwts.verify_jws(message, keypairs)

        if jose.is_jwe(ret):
            ret = jwes.decrypt_jwe(ret, self.identity_credentials.keypair)

        return ret

    def prepare_message(self, encrypt_to_peers=True, other_recipients=None, *args, **kwargs):
        """
        Prepare a message before sending

        :param encrypt_to_peers: If True (default), and peer_credentials available,
            encrypt the message to them
        :type encrypt_to_peers: bool
        :param other_recipients: Additional recipients to encrypt to
        :type other_recipients: list of :class:`~ntdi.keychain.Credential`
        :return: Signed JWS
        """
        claims = kwargs
        claims['iss'] = self.identity_credentials.id

        recipient_keypairs = self._get_recipient_keypairs(encrypt_to_peers, other_recipients)

        if recipient_keypairs:
            claims = jwes.make_jwe(
                claims, self.identity_credentials.keypair, recipient_keypairs, jsonify=False
            )

        return jwts.make_jws(claims, self.identity_credentials.keypair)

    def add_signature(self, message, default_jwt_kid=None):
        """
        Add this Device's signature to a message

        Note that the semantics of this signature are application-specific. If the
        application expects only verified messages to be co-signed, the caller is
        responsible for verifying the message first. Otherwise, the signature only
        indicates that the message was processed by this Device.

        Likewise, this method will not decrypt a JWE. If the message was encrypted
        for this Device, and should be decrypted and re-signed, the caller should
        do that through other means, such as :func:`verify_message` and :func:`prepare_message`.

        :param str message: Previously-signed JWS (Compact or JSON) or JWT
        :param str default_jwt_kid: (optional) value for 'kid' header field if passing a JWT
            without one
        :return: Signed JWS with additional Device signature
        """
        return jwts.extend_jws_signatures(
            message, self.identity_credentials.keypair, default_jwt_kid
        )

    def send_message(self, *args, **kwargs):
        raise NotImplementedError


class ServerSession(SessionBase):
    """
    Enable Server to request two-factor Authentication from TDI Core
    """
    def __init__(self, identity_credentials=None, fleet_credentials=None,
                 core_fleet_credentials=None, peer_credentials=None, config=None):
        super(ServerSession, self).__init__(identity_credentials,
                                            fleet_credentials,
                                            core_fleet_credentials,
                                            peer_credentials, config)

        if isinstance(config, dict):
            params = config
        else:
            # Load default
            default_config = os.path.join(os.path.dirname(__file__),
                                          'data', 'core_cosign.yaml')
            params = self._load_config(config if config else default_config)

        self._create_services(params)

    def _create_services(self, params, **kwargs):
        """
        Populate session variables and create methods
        :return: None
        """
        global_kwargs = params.get('GLOBAL', {})
        if self.fleet_credentials:
            global_kwargs['fleet_credentials'] = self.fleet_credentials

        super(ServerSession, self)._create_services(params, **global_kwargs)

    def prepare_message(self, rekey_credentials=None, encrypt_to_peers=True,
                        other_recipients=None, **kwargs):
        """
        Build message that has two-factor signatures

        :param rekey_credentials: (optional) rekey credentials
        :type rekey_credentials: list
        :param encrypt_to_peers: If True (default), and peer_credentials available,
            encrypt the message to them
        :type encrypt_to_peers: bool
        :param other_recipients: Additional recipients to encrypt to
        :type other_recipients: list of :class:`~ntdi.keychain.Credential`
        :return: Signed JWS to be sent to devices
        """
        if self.fleet_credentials is None:
            raise AttributeError

        keypairs = [
            self.fleet_credentials.keypair
        ]

        if rekey_credentials:
            keypairs += [credentials.keypair for credentials in rekey_credentials]

        claims = kwargs
        claims['iss'] = self.identity_credentials.id

        recipient_keypairs = self._get_recipient_keypairs(encrypt_to_peers, other_recipients)

        if recipient_keypairs:
            claims = jwes.make_jwe(
                claims, self.identity_credentials.keypair, recipient_keypairs, jsonify=False
            )

        jws = jwts.make_jws(claims, self.identity_credentials.keypair)

        core_response = self.authenticate.server(
            fleet_id=self.core_fleet_credentials.keypair.identity,
            identity=self.identity_credentials.keypair.identity,
            body=jws
        )

        if not core_response:
            logger.debug('TDI Core refused to co-sign server message')
            raise exceptions.InvalidAuthentication

        stripped_response = jwts.remove_jws_signatures(
            core_response, self.identity_credentials.id
        )
        return jwts.extend_jws_signatures(stripped_response, keypairs)

    def send_message(self, *args, **kwargs):
        raise NotImplementedError

    def verify_message(self, message, device_credentials, get_core_cosignature=True):
        """
        Verify a message received from/through one or more Devices

        :param message: JSON formatted JWS or JWT signed by the Device
        :param device_credentials: :class:`~ntdi.keychain.Credential` (or list of them)
            to verify Device signature(s) against
        :param get_core_cosignature: (default: True) verify with TDI Core first
        :return: verified message or False if not valid
        """

        if not device_credentials:
            raise AttributeError

        if not isinstance(device_credentials, collections.Iterable):
            device_credentials = [device_credentials]

        keypairs = [credential.keypair for credential in device_credentials]

        if get_core_cosignature:
            keypairs += [self.core_fleet_credentials.keypair]

            # TODO: if not already signed by Core: (for now, do as asked, let caller deal with it)

            if len(device_credentials) == 1:
                message = self.authenticate.edge_device(
                    fleet_id=self.core_fleet_credentials.keypair.identity,
                    identity=keypairs[0].identity,
                    body=message,
                )
            else:
                message = self.authenticate.fleet(
                    fleet_id=self.core_fleet_credentials.keypair.identity,
                    body=message,
                )

            if not message:
                logger.debug('TDI Core refused to co-sign device message')
                raise exceptions.InvalidAuthentication

        ret = jwts.verify_jws(message, keypairs)

        if jose.is_jwe(ret):
            try:
                # the message is most likely intended for the Fleet
                ret = jwes.decrypt_jwe(ret, self.fleet_credentials.keypair)
            except exceptions.InvalidRecipient:
                # but in case it is intended for the Fleet Server itself
                ret = jwes.decrypt_jwe(ret, self.identity_credentials.keypair)

        return ret


class AdminSession(SessionBase):
    """
    Admin Users will only interface with TDI Core service,
    They only need an identity_credentials and core_fleet_credentials
    to verify responses
    """
    def __init__(self, identity_credentials, fleet_credentials=None,
                 core_fleet_credentials=None, config=None):
        super(AdminSession, self).__init__(identity_credentials,
                                           fleet_credentials,
                                           core_fleet_credentials, config)

        if isinstance(config, dict):
            params = config
        else:
            default_config = os.path.join(os.path.dirname(__file__),
                                          'data', 'core_revocation.yaml')
            params = self._load_config(config if config else default_config)

        self._create_services(params)

    def _create_services(self, params, **kwargs):
        """
        Populate session variables and create methods
        :return: None
        """
        global_kwargs = params.get('GLOBAL', {})
        if self.fleet_credentials:
            global_kwargs['fleet_credentials'] = self.fleet_credentials

        super(AdminSession, self)._create_services(params, **global_kwargs)

    def prepare_message(self, *args, **kwargs):
        raise NotImplementedError

    def send_message(self, *args, **kwargs):
        raise NotImplementedError

    def verify_message(self, *args, **kwargs):
        raise NotImplementedError
