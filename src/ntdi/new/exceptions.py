# -*- coding: utf-8 -*-
from __future__ import unicode_literals


class MessageFrozenError(ValueError):
    pass


class MessageNotSignedError(ValueError):
    pass


class NotVerifiableError(RuntimeError):
    pass


class NotJOSEException(ValueError):
    pass


class NotJSONException(ValueError):
    pass


class MultipleSignaturesNotSupported(ValueError):
    pass


class MissingSignatureData(ValueError):
    pass


class MissingSignatures(ValueError):
    pass
