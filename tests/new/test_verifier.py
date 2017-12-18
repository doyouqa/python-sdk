# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import pytest

import ntdi.new as ntdi


class TestVerifier(object):

    @pytest.fixture
    def verifier(self, mocker, base, kid_list):
        mocker.patch('ntdi.new.base.Message', autospec=True)

        return ntdi.Verifier(base, kid_list=kid_list)

    def test_verify(self, mocker, config, platform, verifier, kid_list):
        jws = 'foo'
        message = mocker.Mock(autospec=ntdi.message.Message)
        message.payload = 'message-payload'
        message.frozen = True

        headers = {kid: 'header-for-{}'.format(kid) for kid in kid_list}
        signatures = {kid: 'sig-for-{}'.format(kid) for kid in kid_list}
        message.signatures = [
            mocker.Mock(kid=kid, protected=headers[kid], signature=signatures[kid])
            for kid in kid_list
        ]

        platform.verify.return_value = True
        ntdi.base.Message.return_value = message

        assert verifier.verify(jws)

        ntdi.base.Message.assert_called_once_with(config, platform, jws, config.kid)
        platform.verify.assert_has_calls(list(
            mocker.call(kid, headers[kid], message.payload, signatures[kid])
            for kid in kid_list
        ), any_order=True)

    def test_verify_not_frozen(self, mocker, verifier):
        jws = 'foo'
        message = mocker.Mock(autospec=ntdi.message.Message)
        message.frozen = False

        ntdi.base.Message.return_value = message

        with pytest.raises(ntdi.exceptions.NotVerifiableError):
            verifier.verify(jws)
