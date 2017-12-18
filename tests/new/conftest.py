# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
import uuid
import random
import six
import pytest

from datetime import datetime, timedelta
from dateutil import tz

import faker

from ntdi import utils
import ntdi.new as ntdi

ALPHA_CHARS = 'abcdefghijklmnopqrstuvwxyz'
NUMBER_CHARS = '0123456890'
WORD_CHARS = ALPHA_CHARS + ' '

ALPHANUMERIC_CHARS = ALPHA_CHARS + ALPHA_CHARS.upper() + NUMBER_CHARS
B64_CHARS = ALPHANUMERIC_CHARS
NONCE_CHARS = ALPHANUMERIC_CHARS

fake_factory = faker.Faker()


class TDIFakerProvider(faker.providers.BaseProvider):
    def kid(self):
        return str(uuid.uuid4())

    def base64jose(self, length):
        return ''.join(random.choice(B64_CHARS) for _ in range(length))

    def bigint(self, minval=0, maxval=2**256):
        return random.randint(minval, maxval)

    def signature(self):
        return (self.bigint(), self.bigint())

    def jwt(self):
        return '.'.join(self.base64jose(l) for l in [10, 20, 64])


fake_factory.add_provider(TDIFakerProvider)


@pytest.fixture(scope="session")
def fake():
    return fake_factory


@pytest.fixture
def kid(fake):
    return fake.kid()


@pytest.fixture
def fleet_kid(fake):
    return fake.kid()


@pytest.fixture
def cosigner_kid(fake):
    return fake.kid()


@pytest.fixture
def other_kid(fake):
    return fake.kid()


@pytest.fixture
def kid_list(fake):
    return [fake.kid() for _ in range(3)]


@pytest.fixture
def now_dt():
    return datetime.utcnow().replace(tzinfo=tz.tzutc())


@pytest.fixture
def now(now_dt):
    return utils.to_timestamp(now_dt)


@pytest.fixture
def nbf(now_dt, config):
    return utils.to_timestamp(now_dt - timedelta(seconds=config.nbf_delta))


@pytest.fixture
def exp_dt(now_dt, config):
    return now_dt + timedelta(seconds=config.exp_delta)


@pytest.fixture
def exp(exp_dt):
    return utils.to_timestamp(exp_dt)


@pytest.fixture
def nonce(exp_dt):
    return '002{time_str}{random_str}'.format(
        time_str=exp_dt.strftime('%Y-%m-%dT%H:%M:%SZ'),
        random_str=''.join(random.choice(NONCE_CHARS) for _ in range(6)),
    )


@pytest.fixture
def config(kid, mocker, fleet_kid, cosigner_kid):
    cosigner_config = mocker.Mock(kid=cosigner_kid)
    fleet_config = mocker.Mock(kid=fleet_kid)
    ret = mocker.Mock(
        kid=kid,
        fleet=fleet_config,
        cosigner=cosigner_config,
        exp_delta=10,
        nbf_delta=2,
    )
    return ret


def simple_json_decode(data):
    try:
        if isinstance(data, six.binary_type):
            data = data.decode('utf-8')
        return json.loads(data)
    except ValueError:
        raise ntdi.exceptions.NotJSONException


@pytest.fixture
def platform(mocker, nonce, now_dt):
    return mocker.Mock(
        json=mocker.Mock(
            decode=mocker.Mock(side_effect=simple_json_decode),
            encode=mocker.Mock(side_effect=json.dumps),
        ),
        nonces=mocker.Mock(
            create=mocker.Mock(return_value=nonce),
            verify_and_burn=mocker.Mock(),
        ),
        time=mocker.Mock(
            now=mocker.Mock(return_value=utils.to_timestamp(now_dt)),
        ),
    )


@pytest.fixture
def base(mocker, config, platform):
    mocker.patch('ntdi.new.base.Signer', autospec=True)

    ret = ntdi.NTDIBase(config, platform)
    ntdi.base.Signer.assert_called_once()

    return ret


@pytest.fixture
def signature(fake):
    return fake.signature()


@pytest.fixture
def fleet_signature(fake):
    return fake.signature()
