# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from .import exceptions


class Verifier(object):

    def __init__(self, entity, kid_list=None, order=True, fleet_check=True):
        self._entity = entity
        self._kid_list = kid_list
        self._order = order
        self._fleet_check = fleet_check

    def verify(self, jws):
        msg = self._entity.create_message(jws)

        # want to distinguish between a valid JWS or not
        # sending in an unsigned JWS should still be ok
        #
        if not msg.frozen:
            raise exceptions.NotVerifiableError

        for sig in msg.signatures:
            # or something like this
            self._entity.platform.verify(sig.kid, sig.protected, msg.payload, sig.signature)

        return msg
