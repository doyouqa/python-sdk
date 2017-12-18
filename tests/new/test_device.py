# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import pytest

import ntdi.new as ntdi


class TestNTDIDevice(object):

    @pytest.fixture
    def device(self, mocker, config, platform):
        mocker.patch('ntdi.new.base.Signer', autospec=True)
        mocker.patch('ntdi.new.base.Verifier', autospec=True)

        ret = ntdi.NTDIDevice(config, platform)

        ntdi.base.Signer.assert_called_once()
        ntdi.base.Verifier.assert_called_once()

        return ret

    def test_verify(self, mocker, device):
        raw_message = 'foo'
        mock_signed_message = mocker.Mock(autospec=ntdi.message.Message)

        device._default_verifier.verify.return_value = mock_signed_message

        assert device.verify(raw_message) == mock_signed_message

        device._default_verifier.verify.assert_called_once_with(raw_message)
