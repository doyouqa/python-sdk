# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from . import NTDIBase
from .verifier import Verifier

logger = logging.getLogger(__name__)


class NTDIFleet(NTDIBase):

    def __init__(self, config, platform, plugins=None):
        super(NTDIFleet, self).__init__(config, platform, plugins)

        self._fleet_signer = self.create_signer(config.fleet.kid)

    def sign(self, payload):
        msg = self._default_signer.sign(payload)
        # TODO: get the co-sig
        # TODO: remove the server sig
        return self._fleet_signer.sign(msg)

    def verify(self, jws):
        msg = self.create_message(jws)

        kid_list = msg.kid_list
        verifier = self.create_verifier(kid_list)
        return verifier.verify(msg)

    def create_verifier(self, kid_list=None, order=True):
        return FleetVerifier(self, kid_list, order)


class FleetVerifier(Verifier):

    def __init__(self, fleet, kid_list=None, order=True):
        super(FleetVerifier, self).__init__(
            fleet, kid_list + [fleet.config.cosigner.kid], order, False,
        )
        self._fleet = fleet  # duplicates '_entity'

    def verify(self, jws):
        msg = self._fleet.create_message(jws)

        # TODO: if not self._pre_verify_message(msg):
        #     raise BloodyHell
        msg = self._fleet.sign(msg)

        # TODO: get the co-sig
        # TODO: remove the server sig

        msg = super(FleetVerifier, self).verify(msg)

        # ?? msg = self._fleet._fleet_signer.sign(msg)

        return msg
