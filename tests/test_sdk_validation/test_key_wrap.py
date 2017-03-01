# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import sys
import subprocess
import yaml
import tempfile
import logging

import unittest

import oneid

from ..common import VALIDATION_DATA_PATH, VALIDATION_CURATED_FILES_PATH, hex2bytes, bytes2hex

logger = logging.getLogger(__name__)


class TestKeyWrap(unittest.TestCase):
    ENCRYPT_IN_FILENAME = os.path.join(VALIDATION_CURATED_FILES_PATH, 'nist_kw_encrypt.in.yaml')
    DECRYPT_IN_FILENAME = os.path.join(VALIDATION_CURATED_FILES_PATH, 'nist_kw_decrypt.in.yaml')

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_existence(self):
        kw_files = [
            self.ENCRYPT_IN_FILENAME, self.DECRYPT_IN_FILENAME,
        ]

        for f in kw_files:
            self.assertTrue(os.path.exists(f), f)

    def test_encryption(self):
        filename = None

        with open(self.ENCRYPT_IN_FILENAME, 'r') as inf, \
                tempfile.NamedTemporaryFile(mode='w', delete=False) as of:

            outrecs = []
            filename = of.name

            for inrec in yaml.load(inf):
                result = {}

                kek = hex2bytes(inrec['k'])
                cek = hex2bytes(inrec['p'])

                try:
                    result = {
                        'c': bytes2hex(oneid.symcrypt.key_wrap(kek, cek)),
                    }

                except:
                    result = {
                        "fail": True,
                        "reason": "as specified",
                    }
                outrecs.append(result)

            yaml.dump(outrecs, of)

        ret = 0

        try:
            msgs = subprocess.check_output([
                os.path.join(VALIDATION_DATA_PATH, 'bin', 'verify_key_wrap'),
                '--debug', 'DEBUG', '--wrap',
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
                result = {}

                kek = hex2bytes(inrec['k'])
                e_cek = hex2bytes(inrec['c'])

                try:
                    result = {
                        'p': bytes2hex(oneid.symcrypt.key_unwrap(kek, e_cek)),
                    }

                except:
                    result = {
                        "fail": True,
                        "reason": "as specified",
                    }
                outrecs.append(result)

            yaml.dump(outrecs, of)

        ret = 0

        try:
            msgs = subprocess.check_output([
                os.path.join(VALIDATION_DATA_PATH, 'bin', 'verify_key_wrap'),
                '--debug', 'DEBUG', '--unwrap',
                '-i', self.DECRYPT_IN_FILENAME,
                '-t', filename,
            ], stderr=subprocess.STDOUT)
            print(msgs.decode('utf-8'), file=sys.stderr)

        except subprocess.CalledProcessError as e:
            print(e.output.decode('utf-8'), file=sys.stderr)
            ret = e.returncode

        self.assertEqual(ret, 0, 'validation failed at record #{}'.format(ret))
