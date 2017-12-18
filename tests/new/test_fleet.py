# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import pytest
import logging

import ntdi.new as ntdi

logger = logging.getLogger(__name__)


class TestNTDIFleet(object):

    @pytest.fixture
    def fleet(self, mocker, config, platform, signature, fleet_signature):
        mocker.patch('ntdi.new.base.Signer', autospec=True)
        mocker.patch('ntdi.new.base.Verifier', autospec=True)
        mocker.patch('ntdi.new.fleet.FleetVerifier', autospec=True)
        mocker.patch('ntdi.new.base.Message', autospec=True)

        ntdi.base.Signer.side_effect = [
            mocker.Mock(autospec=ntdi.signer.Signer) for _ in range(2)
        ]

        ret = ntdi.NTDIFleet(config, platform)

        ntdi.fleet.FleetVerifier.assert_not_called()
        ntdi.base.Verifier.assert_not_called()
        assert ntdi.base.Signer.call_count == 2

        logger.debug('fleet._default_signer=%s', ret._default_signer)
        logger.debug('fleet._fleet_signer=%s', ret._fleet_signer)

        return ret

    def test_sign(self, mocker, fleet, kid_list):
        payload = 'foo'
        half_signed_message = mocker.Mock(autospec=ntdi.message.Message)
        fully_signed_message = mocker.Mock(autospec=ntdi.message.Message)

        fleet._default_signer.sign.return_value = half_signed_message
        fleet._fleet_signer.sign.return_value = fully_signed_message

        assert fleet.sign(payload) == fully_signed_message

        fleet._default_signer.sign.assert_called_once_with(payload)
        fleet._fleet_signer.sign.assert_called_once_with(half_signed_message)

    def test_verify(self, mocker, kid_list, fleet):
        verified_message = mocker.Mock(autospec=ntdi.message.Message, kid_list=kid_list)

        mock_verifier = mocker.Mock(autospec=ntdi.fleet.FleetVerifier)
        mock_verifier.verify.return_value = verified_message
        ntdi.fleet.FleetVerifier.return_value = mock_verifier

        assert fleet.verify('foo') == verified_message


class TestFleetVerifier(object):

    @pytest.fixture
    def fleet(self, mocker):
        mocker.patch('ntdi.new.base.Signer', autospec=True)
        mocker.patch('ntdi.new.base.Verifier', autospec=True)
        mocker.patch('ntdi.new.base.Message', autospec=True)
        return mocker.Mock(autospec=ntdi.fleet.NTDIFleet)

    @pytest.fixture
    def fleet_verifier(self, mocker, fleet, kid_list):
        mocker.patch('ntdi.new.fleet.Verifier', autospec=True)
        return ntdi.FleetVerifier(fleet, kid_list)

    def test_verify(self, mocker, fleet, fleet_verifier, kid_list):
        payload = 'foo'
        unsigned_message = mocker.Mock(autospec=ntdi.message.Message)
        fleet_signed_message = mocker.Mock(autospec=ntdi.message.Message)
        verified_message = mocker.Mock(autospec=ntdi.message.Message, kid_list=kid_list)

        mocker.patch.object(ntdi.verifier.Verifier, 'verify')

        fleet.create_message.return_value = unsigned_message

        fleet.sign.return_value = fleet_signed_message
        ntdi.verifier.Verifier.verify.return_value = verified_message

        fleet_verifier.verify('foo')

        fleet.create_message.assert_called_once_with(payload)
        fleet.sign.assert_called_once_with(unsigned_message)
        ntdi.verifier.Verifier.verify.assert_called_once_with(fleet_signed_message)
