# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
import pytest

import ntdi.new as ntdi


class TestJOSE(object):

    @pytest.fixture
    def jose(self, platform):
        return ntdi.JOSEUtils(platform)

    @pytest.fixture
    def frozen_header(self, fake):
        return fake.base64jose(10)

    @pytest.fixture
    def frozen_payload(self, fake):
        return fake.base64jose(20)

    @pytest.fixture
    def frozen_signature(self, fake):
        return fake.base64jose(64)

    @pytest.fixture
    def compact_jws(self, frozen_header, frozen_payload, frozen_signature):
        return '.'.join([frozen_header, frozen_payload, frozen_signature])

    @pytest.fixture
    def jws(self, frozen_header, frozen_payload, frozen_signature):
        return {
            'payload': frozen_payload,
            'signatures': [
                {
                    'protected': frozen_header,
                    'signature': frozen_signature,
                },
            ],
        }

    @pytest.fixture
    def jwe(self, fake, frozen_header, frozen_payload, frozen_signature):
        return {
            'protected': frozen_header,
            'ciphertext': fake.base64jose(72),
            'iv': fake.base64jose(16),
            'tag': fake.base64jose(24),
            'recipients': [],
        }

    def test_is_compact_jws(self, jose, compact_jws, jws, jwe):
        assert jose.is_compact_jws(compact_jws)
        assert jose.is_compact_jws(compact_jws.encode('utf-8'))
        assert not jose.is_compact_jws(jws)
        assert not jose.is_compact_jws(jwe)
        assert not jose.is_compact_jws('')
        assert not jose.is_compact_jws(b'..')
        assert not jose.is_compact_jws([])
        assert not jose.is_compact_jws({})

    def test_is_jws(self, jose, compact_jws, jws, jwe):
        assert jose.is_jws(compact_jws)
        assert jose.is_jws(compact_jws.encode('utf-8'))
        assert jose.is_jws(jws)
        assert jose.is_jws(json.dumps(jws))
        assert not jose.is_jws(jwe)
        assert not jose.is_jws(json.dumps(jwe))
        assert not jose.is_jws('')
        assert not jose.is_jws(b'..')
        assert not jose.is_jws([])
        assert not jose.is_jws({})

    def test_is_jwe(self, jose, compact_jws, jws, jwe):
        assert not jose.is_jwe(compact_jws)
        assert not jose.is_jwe(jws)
        assert not jose.is_jwe(json.dumps(jws))
        assert jose.is_jwe(jwe)
        assert jose.is_jwe(json.dumps(jwe))
        assert not jose.is_jwe('')
        assert not jose.is_jwe(b'..')
        assert not jose.is_jwe([])
        assert not jose.is_jwe({})

    def test_compact_jws(self, jose, frozen_header, frozen_payload, signature):
        r, s = signature
        sig_rec = {
            "frozen_header": frozen_header,
            "r": r,
            "s": s,
        }
        assert jose.jws(frozen_payload, [sig_rec], compact=True) is None

    def test_jws(self, jose, frozen_header, frozen_payload, frozen_signature):
        assert jose.jws(frozen_payload, []) is None

    def test_jwe(self, jose, kid, nonce, frozen_payload, kid_list):
        assert jose.jwe(kid, nonce, frozen_payload, kid_list) is None

    def test_uncompact_jws(self, jose, compact_jws):
        assert jose.uncompact_jws(compact_jws) is None

    def test_encode_header(self, jose):
        assert jose.encode_header({}) is None

    def test_decode_header(self, jose, frozen_header):
        assert jose.decode_header(frozen_header) is None

    def test_encode_claims(self, jose):
        assert jose.encode_claims({}) is None

    def test_decode_claims(self, jose, frozen_payload):
        assert jose.decode_claims(frozen_payload) is None

    def test_encode_signature(self, jose):
        assert jose.encode_signature({}) is None

    def test_decode_signature(self, jose, frozen_signature):
        assert jose.decode_signature(frozen_signature) is None

    def test_decrypt_jwe(self, jose, jwe):
        assert jose.decrypt_jwe(jwe) is None
