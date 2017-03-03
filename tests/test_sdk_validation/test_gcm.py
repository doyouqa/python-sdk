# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import sys
import subprocess
import json
import yaml
import tempfile
import logging

import unittest

import oneid

from ..common import VALIDATION_DATA_PATH, VALIDATION_CURATED_FILES_PATH, hex2bytes, bytes2hex

logger = logging.getLogger(__name__)


class TestGCM(unittest.TestCase):
    ENCRYPT_IN_FILENAME = os.path.join(VALIDATION_CURATED_FILES_PATH, 'nist_gcm_encrypt.in.yaml')
    DECRYPT_IN_FILENAME = os.path.join(VALIDATION_CURATED_FILES_PATH, 'nist_gcm_decrypt.in.yaml')

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_existence(self):
        gcm_files = [
            self.ENCRYPT_IN_FILENAME, self.DECRYPT_IN_FILENAME,
        ]

        for f in gcm_files:
            self.assertTrue(os.path.exists(f), f)

    def test_encryption(self):
        filename = None

        with open(self.ENCRYPT_IN_FILENAME, 'r') as inf, \
                tempfile.NamedTemporaryFile(mode='w', delete=False) as of:

            outrecs = []
            filename = of.name

            for inrec in yaml.load(inf):
                iv = hex2bytes(inrec['iv'])

                ivlen = len(iv) * 8  # in bits
                aadlen = len(inrec.get('aad', '')) * 4  # in bits, 2 chars per byte
                taglen = int(inrec.get('taglen', 0))

                result = self._check_params(ivlen, aadlen, taglen)

                if result:
                    outrecs.append(result)
                    continue

                key = hex2bytes(inrec['key'])
                pt = hex2bytes(inrec['pt'])

                try:
                    enc_data = oneid.symcrypt._aes_encrypt_with_iv_for_test(
                        pt, key, legacy_support=False, _iv_for_test=iv
                    )
                    result = {
                        "header": {"alg": "dir", "enc": "A256GCM"},
                    }

                    for k in ('ciphertext', 'iv', 'tag'):
                        result[k] = enc_data[k].decode('utf-8')

                except:
                    result = {
                        "fail": True,
                        "reason": "unknown reason",
                    }
                outrecs.append(result)

            yaml.dump(outrecs, of)

        ret = 0

        try:
            msgs = subprocess.check_output([
                os.path.join(VALIDATION_DATA_PATH, 'bin', 'verify_aes_gcm'),
                '--debug', 'DEBUG', '--encrypt',
                '-i', self.ENCRYPT_IN_FILENAME,
                '-t', filename,
            ], stderr=subprocess.STDOUT)
            print(msgs.decode('utf-8'), file=sys.stderr)

        except subprocess.CalledProcessError as e:
            print(e.output.decode('utf-8'), file=sys.stderr)
            ret = e.returncode

        self.assertEqual(ret, 0, 'validation failed at record #{}'.format(ret))

    def test_decryption(self):
        filename = None

        with open(self.DECRYPT_IN_FILENAME, 'r') as inf, \
                tempfile.NamedTemporaryFile(mode='w', delete=False) as of:

            outrecs = []
            filename = of.name

            for inrec in yaml.load(inf):
                inrec_jwe = json.loads(inrec.get('jwe'))

                ivlen = len(oneid.utils.base64url_decode(inrec_jwe.get('iv', ''))) * 8  # in bits
                aadlen = int(inrec.get('aadlen', 0))
                taglen = len(oneid.utils.base64url_decode(inrec_jwe.get('tag', ''))) * 8  # in bits

                result = self._check_params(ivlen, aadlen, taglen)

                if result:
                    outrecs.append(result)
                    continue

                key = hex2bytes(inrec['key'])

                result = {}

                for mode in ['jwe', 'hybrid', 'legacy']:
                    moderec = json.loads(inrec[mode])

                    try:
                        result[mode] = bytes2hex(
                            oneid.symcrypt.aes_decrypt(moderec, key)
                        )

                    except:
                        result = {
                            "fail": True,
                            "reason": "as specified",
                        }
                        break

                outrecs.append(result)

            yaml.dump(outrecs, of)

        ret = 0

        try:
            msgs = subprocess.check_output([
                os.path.join(VALIDATION_DATA_PATH, 'bin', 'verify_aes_gcm'),
                '--debug', 'DEBUG', '--decrypt',
                '-i', self.DECRYPT_IN_FILENAME,
                '-t', filename,
            ], stderr=subprocess.STDOUT)
            print(msgs.decode('utf-8'), file=sys.stderr)

        except subprocess.CalledProcessError as e:
            print(e.output.decode('utf-8'), file=sys.stderr)
            ret = e.returncode

        self.assertEqual(ret, 0, 'validation failed at record #{}'.format(ret))

    def _check_params(self, ivlen, aadlen, taglen):

        if ivlen != 96:
            return {
                "fail": True,
                "reason": "invalid iv len: {}".format(ivlen)
            }

        if aadlen != 0:
            return {
                "fail": True,
                "reason": "non-zero AAD (len: {})".format(aadlen)
            }

        if taglen != 128:
            return {
                "fail": True,
                "reason": "invalid tag len: {}".format(taglen)
            }
