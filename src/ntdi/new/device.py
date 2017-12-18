# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from .base import NTDIBase


class NTDIDevice(NTDIBase):

    def __init__(self, config, platform, plugins=None):
        super(NTDIDevice, self).__init__(config, platform, plugins)

        self._default_verifier = self.create_verifier()

    def verify(self, jws):
        return self._default_verifier.verify(jws)
