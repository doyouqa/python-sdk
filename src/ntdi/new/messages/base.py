# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from .. import exceptions
from . import IMessage

logger = logging.getLogger(__name__)


class BaseMessage(IMessage):

    def __init__(self, config, platform, payload=None, kid=None):
        logger.debug('payload=%s', payload)

        self._config = config
        self._platform = platform
        self._payload = payload
        self._kid = kid or config.kid

        self._frozen_payload = None

    # IMessage methods

    @property
    def frozen(self):
        return self._frozen_payload is not None

    def freeze(self):
        if not self.frozen:
            self._frozen_payload = xrx.encode_claims(self.claims)

    @property
    def signed(self):
        return len(self._signatures) > 0

    @property
    def payload(self):
        return self._payload

    @payload.setter
    def payload(self, value):
        if self.frozen:
            raise exceptions.MessageFrozenError
        self._payload = value

    @property
    def claims(self):
        if not self._claims:
            self._generate_standard_claims()

        if not self.frozen:
            self._claims['payload'] = self._payload

        return self._claims

    @property
    def kid_list(self):
        return [sig['header']['kid'] for sig in self._signatures]

    @property
    def jwt(self):
        if not self.signed:
            raise exceptions.MessageNotSignedError
        if len(self._signatures) > 1:
            raise exceptions.MultipleSignaturesNotSupported
        logger.debug('about to call jose.jwt')
        return xrx.jwt(self._frozen_payload, self._signatures)

    @property
    def jws(self):
        if not self.signed:
            raise exceptions.MessageNotSignedError
        return xrx.jws(self._frozen_payload, self._signatures)

    def jwe(self, recipient_kids):
        if not self.signed:
            raise exceptions.MessageNotSignedError
        return xrx.jwe(self._frozen_payload, self._signatures, recipient_kids)

    def sign(self, kid=None):
        if not kid:
            kid = self._config.kid

        self.freeze()

        header = self._create_sig_header(kid)
        frozen_header = xrx.encode_header(header)

        logger.debug('frozen_header=%s, frozen_payload=%s', frozen_header, self._frozen_payload)

        r, s = self._platform.crypto.sign(
            kid,
            '.'.join([frozen_header, self._frozen_payload]),
        )

        self._signatures.append({
            'header': header,
            'frozen_header': frozen_header,
            'r': r,
            's': s,
        })

    # "private" methods

    def _generate_standard_claims(self):
        self._claims = {
            'iss': self._config.kid,
            'jti': self._platform.nonces.create(),
            'nbf': self._platform.time.now() - self._config.nbf_delta,
            'exp': self._platform.time.now() + self._config.exp_delta,
        }

    def _create_sig_header(self, kid):
        sidx = -1
        sidxs = []
        kids = []

        for sig in self._signatures:
            kids.append(sig['header'].get('kid'))
            next_sidx = sig['header'].get('sidx', -1)
            sidxs.append(next_sidx)
            sidx = max(sidx, next_sidx)

        return {
            'kid': kid,
            'kids': kids,
            'sidx': sidx + 1,
            'sidxs': sidxs,
        }
