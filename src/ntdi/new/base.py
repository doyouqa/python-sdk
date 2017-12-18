# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from .signer import Signer
from .verifier import Verifier
from .message import Message


class NTDIBase(object):

    def __init__(self, config, platform, plugins=None):
        self._config = config
        self._platform = platform
        self._plugins = plugins

        self._default_signer = self.create_signer()

    @property
    def kid(self):
        return self._config.kid

    @property
    def platform(self):
        return self._platform

    def sign(self, payload):
        return self._default_signer.sign(payload)

    def verify(self, jws):
        raise NotImplementedError

    def create_signer(self, kid=None):
        return Signer(self, kid)

    def create_verifier(self, kid_list=None, order=True, fleet_check=True):
        return Verifier(self, kid_list, order, fleet_check)

    def create_message(self, payload):
        return Message(self._config, self._platform, payload, self.kid)
