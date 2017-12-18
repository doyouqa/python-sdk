# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import six
import logging

logger = logging.getLogger(__name__)


class Signer(object):

    def __init__(self, entity, kid=None):
        self._entity = entity
        self._kid = kid or entity.kid

    @property
    def kid(self):
        return self._kid

    def sign(self, message_in):
        msg = message_in

        if isinstance(msg, (six.string_types, six.binary_type)):
            logger.debug('creating Message from %s', message_in)
            msg = self._entity.create_message(message_in)

        msg.sign(self.kid)

        return msg
