# -*- coding: utf-8 -*-
from __future__ import unicode_literals, division

import os
import sys
import yaml
import subprocess
import tempfile
import logging

import unittest

from ..common import (
    VALIDATION_DATA_PATH, VALIDATION_CURATED_FILES_PATH,
    hex2bytes, bytes2hex,
    keypair_from_nist_hex,
)

logger = logging.getLogger(__name__)


class TestECDH(unittest.TestCase):
    IN_FILENAME = os.path.join(VALIDATION_CURATED_FILES_PATH, 'nist_ecdh.in.yaml')

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_existence(self):
        self.assertTrue(os.path.exists(self.IN_FILENAME), self.IN_FILENAME)

    def test_ecdh(self):
        filename = None

        with open(self.IN_FILENAME, 'r') as inf, \
                tempfile.NamedTemporaryFile(mode='w', delete=False) as of:

            outrecs = []
            filename = of.name

            for inrec in yaml.load(inf):
                result = self._do_test_record(inrec)
                outrecs.append(result)

            yaml.dump(outrecs, of)

        ret = 0

        try:
            msgs = subprocess.check_output([
                os.path.join(VALIDATION_DATA_PATH, 'bin', 'verify_ecdh'),
                '--debug', 'DEBUG',
                '-i', self.IN_FILENAME,
                '-t', filename,
            ], stderr=subprocess.STDOUT)
            print(msgs.decode('utf-8'), file=sys.stderr)

        except subprocess.CalledProcessError as e:
            print(e.output.decode('utf-8'), file=sys.stderr)
            ret = e.returncode

        self.assertEqual(ret, 0, 'validation failed at record #{}'.format(ret))

    def _do_test_record(self, inrec):
        curve = inrec['curve']

        if curve != 'P-256':
            result = {
                "fail": True,
                "reason": "invalid ECC curve: {}".format(curve)
            }
            return result

        hash = inrec['hash']

        if hash != 'SHA-256':
            result = {
                "fail": True,
                "reason": "invalid hash function: {}".format(hash)
            }
            return result

        mac = inrec['mac']

        if mac != 'CCM':
            result = {
                "fail": True,
                "reason": "invalid MAC function: {}".format(mac)
            }
            return result

        mac_hash = inrec['machash']

        if mac_hash != 'AES256':
            result = {
                "fail": True,
                "reason": "invalid MAC hash function: {}".format(mac_hash)
            }
            return result

        try:
            otherinfo = hex2bytes(inrec['oi'])

            vx = inrec['qeiutx']
            vy = inrec['qeiuty']
            vd = inrec['deiut']

            u_private_keypair = keypair_from_nist_hex(vx, vy, vd, otherinfo=otherinfo)

            vx = inrec['qscavsx']
            vy = inrec['qscavsy']

            v_public_keypair = keypair_from_nist_hex(vx, vy)

            k = u_private_keypair.ecdh(v_public_keypair)

            result = {
                "dkm": bytes2hex(k)
            }

        except ValueError as ve:
            result = {
                "fail": True,
                "reason": str(ve),
            }

        except:
            result = {
                "fail": True,
                "reason": 'unknown',
            }

        return result
