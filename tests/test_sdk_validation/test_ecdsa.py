# -*- coding: utf-8 -*-
from __future__ import unicode_literals, division

import os
import sys
import yaml
import subprocess
import tempfile
import logging

import unittest

import oneid

from ..common import (
    VALIDATION_DATA_PATH, VALIDATION_CURATED_FILES_PATH,
    hex2bytes, bytes2hex,
    keypair_from_nist_hex,
)

logger = logging.getLogger(__name__)


class ECDSAMixin(object):

    def test_existence(self):
        self.assertTrue(os.path.exists(self.IN_FILENAME), self.IN_FILENAME)

    def test_verification(self):
        filename = None

        with open(self.IN_FILENAME, 'r') as inf, \
                tempfile.NamedTemporaryFile(mode='w', delete=False) as of:

            outrecs = []
            filename = of.name

            for inrec in yaml.load(inf):
                curve = inrec['curve']

                if curve != 'P-256':
                    result = {
                        "fail": True,
                        "reason": "invalid ECC curve: {}".format(curve)
                    }
                    outrecs.append(result)
                    continue

                hash = inrec['hash']

                if hash != 'SHA-256':
                    result = {
                        "fail": True,
                        "reason": "invalid hash function: {}".format(hash)
                    }
                    outrecs.append(result)
                    continue

                try:
                    result = self._do_test_record(inrec)

                except:
                    result = {
                        "fail": True,
                        "reason": 'as specified',
                    }
                outrecs.append(result)

            yaml.dump(outrecs, of)

        ret = 0

        try:
            msgs = subprocess.check_output([
                os.path.join(VALIDATION_DATA_PATH, 'bin', 'verify_ecdsa'),
                '--debug', 'DEBUG', self.OP_FLAG,
                '-i', self.IN_FILENAME,
                '-t', filename,
            ], stderr=subprocess.STDOUT)
            print(msgs.decode('utf-8'), file=sys.stderr)

        except subprocess.CalledProcessError as e:
            print(e.output.decode('utf-8'), file=sys.stderr)
            ret = e.returncode

        self.assertEqual(ret, 0, 'validation failed at record #{}'.format(ret))


class TestGenerateECDSA(ECDSAMixin, unittest.TestCase):
    IN_FILENAME = os.path.join(VALIDATION_CURATED_FILES_PATH, 'nist_ecdsa_gen.in.yaml')
    OP_FLAG = '--sign'

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def _do_test_record(self, inrec):
        keypair = keypair_from_nist_hex(inrec['qx'], inrec['qy'], inrec['d'])

        sig = keypair.sign(hex2bytes(inrec['msg']))

        sig_b = oneid.utils.base64url_decode(sig)
        sp = len(sig_b) // 2

        return {
            "r": bytes2hex(sig_b[:sp]),
            "s": bytes2hex(sig_b[sp:]),
        }


class TestVerifyECDSA(ECDSAMixin, unittest.TestCase):
    IN_FILENAME = os.path.join(VALIDATION_CURATED_FILES_PATH, 'nist_ecdsa_ver.in.yaml')
    OP_FLAG = '--verify'

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def _do_test_record(self, inrec):
        keypair = keypair_from_nist_hex(inrec['qx'], inrec['qy'])

        b_msg = hex2bytes(inrec['msg'])
        b_sig = hex2bytes(inrec['r'] + inrec['s'])
        b64_sig = oneid.utils.base64url_encode(b_sig)

        return {
            "result": keypair.verify(b_msg, b64_sig)
        }
