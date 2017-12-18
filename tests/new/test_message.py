# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import time
import random
import pytest
import logging

import ntdi.new as ntdi

logger = logging.getLogger(__name__)


class TestMessage(object):

    @pytest.fixture
    def platform(self, platform):
        # force everything to be a payload
        platform.json.decode.side_effect = ntdi.exceptions.NotJSONException
        return platform

    @pytest.fixture(autouse=True)
    def jose(self, mocker, fake, platform):
        mocker.patch('ntdi.new.jose.JOSEUtils', autospec=True)

        jose = mocker.MagicMock(autospec=ntdi.jose.JOSEUtils)
        jose.is_compact_jws.return_value = False
        jose.is_jws.return_value = False
        jose.is_jwe.return_value = False
        jose.jwt.return_value = fake.jwt()

        ntdi.jose.JOSEUtils.return_value = jose

        return jose

    @pytest.fixture
    def payload(self, fake):
        return 'payload/' + fake.slug()

    @pytest.fixture
    def claims(self, config, nonce, nbf, exp, payload):
        return {
            'iss': config.kid,
            'jti': nonce,
            'nbf': nbf,
            'exp': exp,
            'payload': payload,
        }

    @pytest.fixture
    def frozen_payload(self, fake):
        return fake.base64jose(random.randint(10, 15))

    @pytest.fixture
    def frozen_header(self, fake):
        return fake.base64jose(random.randint(10, 15))

    @pytest.fixture
    def frozen_headers(self, fake, kid_list):
        return [fake.base64jose(random.randint(10, 15)) for _ in kid_list]

    @pytest.fixture
    def message(self, config, platform, jose, payload):
        ret = ntdi.Message(config, platform, payload)
        assert not ret.frozen
        assert not ret.signed
        return ret

    @pytest.fixture
    def frozen_message(self, config, platform, payload, frozen_payload):
        ret = ntdi.Message(config, platform, payload)
        ret._frozen_payload = frozen_payload
        assert ret.frozen
        assert not ret.signed
        return ret

    @pytest.fixture
    def self_signed_message(self, fake, config, platform, payload, frozen_payload):
        ret = ntdi.Message(config, platform, payload)
        ret._frozen_payload = frozen_payload
        ret._signatures = [{
            'header': {'kid': config.kid},
            'r': fake.bigint(),
            's': fake.bigint(),
        }]
        assert ret.signed
        return ret

    @pytest.fixture
    def multi_signed_message(self, fake, config, platform, payload, frozen_payload, kid_list):
        ret = ntdi.Message(config, platform, payload)
        ret._frozen_payload = frozen_payload
        ret._signatures = [{
            'header': {'kid': kid},
            'r': fake.bigint(),
            's': fake.bigint(),
        } for kid in kid_list]
        assert ret.signed
        return ret

    def test_empty_message(self, config, platform):
        ret = ntdi.Message(config, platform)

        assert not ret.frozen
        assert not ret.signed
        assert ret.payload is None

    def test_string_payload_not_jwx(self, config, platform, jose, payload):
        msg = ntdi.Message(config, platform, payload)

        assert not msg.frozen
        assert msg.payload == payload

        platform.json.decode.assert_called_once_with(payload)

    def test_string_payload_compact_jws(
        self, config, platform, jose, payload, frozen_payload, claims,
    ):
        jwt = 'hdr.payload.sig'
        jws = {
            'payload': payload,
            'signatures': [
                {
                    'protected': 'abc',
                    'signature': 'xyz',
                },
            ],
        }
        jose.is_compact_jws.return_value = True
        jose.uncompact_jws.return_value = jws
        jose.is_jws.return_value = True
        jose.decode_claims.return_value = claims

        msg = ntdi.Message(config, platform, jwt)

        assert msg.frozen
        assert msg.payload == payload

        jose.is_compact_jws.assert_called_once_with(jwt)
        jose.uncompact_jws.assert_called_once_with(jwt)
        jose.is_jws.assert_called_once_with(jws)
        jose.decode_claims.assert_called_once_with(payload)

    def test_string_payload_json_jws(
        self, mocker, config, platform, jose, payload, frozen_payload, claims,
    ):
        headers = ['abc', 'def']
        signatures = ['xyz', 'qrs']
        string_jws = '{payload=payload,sigs=[{hdr=hdr,sig=sig}]}'
        dict_jws = {
            'payload': frozen_payload,
            'signatures': [
                {
                    'protected': headers[n],
                    'signature': signatures[n],
                } for n in range(len(headers))
            ],
        }
        jose.is_jws.return_value = True
        platform.json.decode.side_effect = None
        platform.json.decode.return_value = dict_jws
        jose.decode_header.side_effect = headers
        jose.decode_claims.return_value = claims
        jose.decode_signature.side_effect = signatures

        msg = ntdi.Message(config, platform, string_jws)

        assert msg.frozen
        assert msg.payload == payload

        # kind of cheating, but ok
        jose.decode_signature.assert_has_calls(list([
            mocker.call(sig) for sig in signatures
        ]), any_order=True)
        jose.decode_header.assert_has_calls(list([
            mocker.call(header) for header in headers
        ]), any_order=True)
        jose.decode_claims.assert_called_once_with(frozen_payload)
        platform.json.decode.assert_called_once_with(string_jws)
        jose.is_jws.assert_called_once_with(dict_jws)

    def test_string_payload_jwe(self, config, platform, jose, payload, frozen_payload, claims):
        string_jwe = '{protected:asds,cipher:***,recip:[]}'
        json_jwe = {
            'protected': 'zzz',
            'cipertext': 'secret',
            'recipients': [],
        }
        jws = {
            'payload': frozen_payload,
            'signatures': [
                {
                    'protected': 'abc',
                    'signature': 'xyz',
                },
            ],
        }
        jose.is_jwe.return_value = True
        jose.is_jws.return_value = True
        platform.json.decode.side_effect = None
        platform.json.decode.return_value = json_jwe
        jose.decrypt_jwe.return_value = jws
        jose.decode_claims.return_value = claims

        msg = ntdi.Message(config, platform, string_jwe)

        assert msg.frozen
        assert msg.payload == payload

        jose.is_jwe.assert_called_once_with(json_jwe)
        jose.is_jws.assert_called_once_with(jws)
        platform.json.decode.assert_called_once_with(string_jwe)
        jose.decrypt_jwe.assert_called_once_with(json_jwe)
        jose.decode_claims.assert_called_once_with(frozen_payload)

    def test_dict_payload_not_jwx(self, config, platform, jose):
        payload = {
            'foo': 12,
        }
        msg = ntdi.Message(config, platform, payload)

        assert not msg.frozen
        assert msg.payload == payload

    def test_dict_payload_jws(self, config, platform, jose, payload, frozen_payload, claims):
        jws = {
            'payload': frozen_payload,
            'signatures': [
                {
                    'protected': 'abc',
                    'signature': 'xyz',
                },
            ],
        }
        jose.is_jws.return_value = True
        jose.decode_claims.return_value = claims

        msg = ntdi.Message(config, platform, jws)

        assert msg.frozen
        assert msg.payload == payload

        jose.decode_claims.assert_called_once_with(frozen_payload)
        jose.is_jws.assert_called_once_with(jws)

    def test_dict_payload_jwe(self, config, platform, jose, payload, frozen_payload, claims):
        jwe = {
            'protected': 'zzz',
            'cipertext': 'secret',
            'recipients': [],
        }
        jws = {
            'payload': frozen_payload,
            'signatures': [
                {
                    'protected': 'abc',
                    'signature': 'xyz',
                },
            ],
        }
        jose.is_jwe.return_value = True
        jose.is_jws.return_value = True
        jose.decrypt_jwe.return_value = jws
        jose.decode_claims.return_value = claims

        msg = ntdi.Message(config, platform, jwe)

        assert msg.frozen
        assert msg.payload == payload

        jose.is_jwe.assert_called_once_with(jwe)
        jose.is_jws.assert_called_once_with(jws)
        jose.decrypt_jwe.assert_called_once_with(jwe)
        jose.decode_claims.assert_called_once_with(frozen_payload)

    def test_integer_payload(self, config, platform, jose):
        payload = 12
        msg = ntdi.Message(config, platform, payload)

        assert not msg.frozen
        assert msg.payload == payload

    def test_array_payload(self, config, platform, jose):
        payload = [12, 34]
        msg = ntdi.Message(config, platform, payload)

        assert not msg.frozen
        assert msg.payload == payload

    def test_frozen(self, message, frozen_message):
        assert not message.frozen
        assert frozen_message.frozen

    def test_freeze(self, jose, message, frozen_payload):
        jose.encode_claims.return_value = frozen_payload
        assert not message.frozen

        for _ in range(2):
            message.freeze()
            assert message.frozen

    def test_signed(self, message, frozen_message, self_signed_message, multi_signed_message):
        assert not message.signed
        assert not frozen_message.signed
        assert self_signed_message.signed
        assert multi_signed_message.signed

    def test_payload_get(self, message, payload):
        assert message.payload == payload

    def test_payload_set(self, payload, message):
        new_payload = 'bar'
        message.payload = new_payload
        assert message.payload == new_payload

    def test_payload_set_frozen(self, frozen_message):
        new_payload = 'bar'

        with pytest.raises(ntdi.exceptions.MessageFrozenError):
            frozen_message.payload = new_payload

    def test_claims(self, config, message, now, nbf, exp, nonce):
        assert now == pytest.approx(time.time(), abs=1)

        claims = message.claims

        assert 'iss' in claims and claims['iss'] == config.kid
        assert 'jti' in claims and claims['jti'] == nonce
        assert 'nbf' in claims and claims['nbf'] == nbf
        assert 'exp' in claims and claims['exp'] == exp

        time.sleep(2)

        assert now != pytest.approx(time.time(), abs=1)
        assert claims == message.claims

    def test_kid_list(self, multi_signed_message, kid_list):
        assert multi_signed_message.kid_list == kid_list

    def test_jwt(self, fake, jose, self_signed_message):
        jwt = fake.jwt()
        jose.jwt.return_value = jwt

        assert self_signed_message.jwt == jwt

        jose.jwt.assert_called_once_with(
            self_signed_message._frozen_payload, self_signed_message._signatures,
        )

    def test_jwt_unsigned(self, jose, message):
        jwt = 'hdr.payload.sig'
        jose.jwt.return_value = jwt

        with pytest.raises(ntdi.exceptions.MessageNotSignedError):
            message.jwt

        jose.jwt.assert_not_called()

    def test_jwt_signed(self, jose, self_signed_message):
        jwt = 'hdr.payload.sig'

        jose.jwt.return_value = jwt

        assert self_signed_message.jwt == jwt

        jose.jwt.assert_called_once_with(
            self_signed_message._frozen_payload,
            self_signed_message._signatures,
        )

    def test_jwt_multi_sig(self, jose, multi_signed_message):
        with pytest.raises(ntdi.exceptions.MultipleSignaturesNotSupported):
            multi_signed_message.jwt

        jose.jwt.assert_not_called()

    def test_jws(self, jose, payload, multi_signed_message):
        jws = {
            'payload': payload,
            'signatures': [
                {
                    'protected': 'abc',
                    'signature': 'xyz',
                },
            ],
        }
        jose.jws.return_value = jws

        assert multi_signed_message.jws == jws

        jose.jws.assert_called_once_with(
            multi_signed_message._frozen_payload, multi_signed_message._signatures,
        )

    def test_jws_unsigned(self, jose, payload, message):
        jws = {
            'payload': payload,
            'signatures': [
                {
                    'protected': 'abc',
                    'signature': 'xyz',
                },
            ],
        }
        jose.jws.return_value = jws

        with pytest.raises(ntdi.exceptions.MessageNotSignedError):
            message.jws

        jose.jws.assert_not_called()

    def test_jwe(self, jose, payload, self_signed_message, kid_list):
        jwe = {
            'protected': 'zzz',
            'cipertext': 'secret',
            'recipients': [],
        }
        jose.jwe.return_value = jwe

        assert self_signed_message.jwe(kid_list) == jwe

        jose.jwe.assert_called_once_with(
            self_signed_message._frozen_payload,
            self_signed_message._signatures, kid_list,
        )

    def test_jwe_unsigned(self, jose, payload, message, kid_list):
        jwe = {
            'protected': 'zzz',
            'cipertext': 'secret',
            'recipients': [],
        }
        jose.jwe.return_value = jwe

        with pytest.raises(ntdi.exceptions.MessageNotSignedError):
            message.jwe(kid_list)

        jose.jwe.assert_not_called()

    def test_self_sign(
        self, fake, jose, config, platform, message, frozen_header, frozen_payload, claims,
    ):
        kid = config.kid
        r = fake.bigint()
        s = fake.bigint()

        jose.encode_header.return_value = frozen_header
        jose.encode_claims.return_value = frozen_payload
        platform.crypto.sign.return_value = (r, s)

        message.sign()

        assert message.frozen
        assert message.claims['iss'] == kid
        assert message._signatures[0]['frozen_header'] == frozen_header
        assert message._signatures[0]['header'] == {
            'kid': kid,
            'kids': [],
            'sidx': 0,
            'sidxs': [],
        }
        assert message._signatures[0]['r'] == r
        assert message._signatures[0]['s'] == s

        jose.encode_header.assert_called_once()
        jose.encode_claims.assert_called_once_with(claims)
        platform.crypto.sign.assert_called_once_with(kid, '.'.join([frozen_header, frozen_payload]))

    def test_single_sign(
        self, fake, jose, config, platform, message,
        frozen_header, frozen_payload, claims, other_kid,
    ):
        r = fake.bigint()
        s = fake.bigint()

        jose.encode_header.return_value = frozen_header
        jose.encode_claims.return_value = frozen_payload
        platform.crypto.sign.return_value = (r, s)

        message.sign(other_kid)

        assert message.frozen
        assert message.claims['iss'] == config.kid
        assert message._signatures[0]['frozen_header'] == frozen_header
        assert message._signatures[0]['header'] == {
            'kid': other_kid,
            'kids': [],
            'sidx': 0,
            'sidxs': [],
        }
        assert message._signatures[0]['r'] == r
        assert message._signatures[0]['s'] == s

        jose.encode_header.assert_called_once()
        jose.encode_claims.assert_called_once_with(claims)
        platform.crypto.sign.assert_called_once_with(
            other_kid, '.'.join([frozen_header, frozen_payload]),
        )

    def test_multi_sign(
        self, mocker, fake, jose, config, platform, message, kid_list,
        frozen_headers, frozen_payload, claims,
    ):
        sigs = [fake.signature() for _ in kid_list]

        jose.encode_header.side_effect = frozen_headers
        platform.crypto.sign.side_effect = sigs
        jose.encode_claims.return_value = frozen_payload

        for kid in kid_list:
            message.sign(kid)

        assert message.frozen
        assert message.claims['iss'] == config.kid

        kids = []
        sidx = 0
        sidxs = []

        for kid, f_hdr, sig, sigrec in zip(kid_list, frozen_headers, sigs, message._signatures):
            assert sigrec['frozen_header'] == f_hdr
            assert sigrec['header'] == {
                'kid': kid,
                'kids': kids,
                'sidx': sidx,
                'sidxs': sidxs,
            }
            assert sigrec['r'] == sig[0]
            assert sigrec['s'] == sig[1]

            kids.append(kid)
            sidxs.append(sidx)
            sidx += 1

        jose.encode_claims.assert_called_once_with(claims)

        sign_calls = [
            mocker.call(kid, '.'.join([header, frozen_payload]))
            for kid, header in zip(kid_list, frozen_headers)
        ]

        # TODO: inspect signatures for proper values

        assert jose.encode_header.call_count == len(kid_list)
        platform.crypto.sign.assert_has_calls(sign_calls, any_order=True)
