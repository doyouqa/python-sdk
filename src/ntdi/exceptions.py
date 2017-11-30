
from cryptography.exceptions import UnsupportedAlgorithm, InvalidSignature


class InvalidAuthentication(Exception):
    pass


class InvalidFormatError(ValueError):
    pass


class InvalidAlgorithmError(UnsupportedAlgorithm):

    def __init__(self, message="invalid 'alg' specified"):
        super(InvalidAlgorithmError, self).__init__(message)


class InvalidClaimsError(ValueError):
    pass


class InvalidKeyError(InvalidSignature):
    pass


class KeySignatureMismatch(InvalidSignature):
    pass


class InvalidSignatureError(InvalidSignature):
    pass


class KeyHeaderMismatch(Exception):
    pass


class ReservedHeader(Exception):
    pass


class InvalidSignatureIndexes(Exception):
    pass


class IdentityRequired(ValueError):
    pass


class InvalidRecipient(Exception):
    pass


class DecryptionFailed(Exception):
    pass
