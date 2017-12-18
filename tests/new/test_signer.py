# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import pytest

import ntdi.new as ntdi


class TestSigner(object):

    def test_construct_without_kid(self, base, other_kid):
        signer = ntdi.Signer(base)

        assert signer.kid != other_kid  # and every other kid in the universe, save one

    def test_construct_with_kid(self, base, other_kid):
        signer = ntdi.Signer(base, other_kid)

        assert signer.kid == other_kid

    @pytest.fixture
    def signer(self, mocker, base, other_kid):
        mocker.patch('ntdi.new.base.Message', autospec=True)

        return ntdi.Signer(base, other_kid)

    def test_sign_payload(self, mocker, config, platform, signer):
        payload = 'foo'
        message = mocker.Mock(autospec=ntdi.message.Message)

        ntdi.base.Message.return_value = message

        assert signer.sign(payload) == message

        ntdi.base.Message.assert_called_once_with(config, platform, payload, config.kid)
        message.sign.assert_called_once_with(signer.kid)

    def test_sign_message(self, mocker, signer):
        message = mocker.Mock(autospec=ntdi.message.Message)

        assert signer.sign(message) == message

        message.sign.assert_called_once_with(signer.kid)
