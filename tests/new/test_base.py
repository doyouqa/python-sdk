# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import pytest

import ntdi.new as ntdi


class TestNTDIBase(object):

    def test_kid(self, kid, base):
        assert base.kid == kid

    def test_platform(self, base, platform):
        assert base.platform == platform

    def test_sign(self, mocker, base):
        raw_msg = 'foo'
        message = mocker.Mock(autospec=ntdi.message.Message)

        base._default_signer.sign.return_value = message

        assert base.sign(raw_msg) == message

        base._default_signer.sign.assert_called_once_with(raw_msg)

    def test_verify(self, base):
        with pytest.raises(NotImplementedError):
            base.verify('foo')

    def test_create_verifier(self, mocker, base):
        mocker.patch('ntdi.new.base.Verifier', autospec=True)
        base.create_verifier()
        ntdi.base.Verifier.assert_called_once()

    def test_create_message(self, mocker, base):
        mocker.patch('ntdi.new.base.Message', autospec=True)
        base.create_message('foo')
        ntdi.base.Message.assert_called_once()
