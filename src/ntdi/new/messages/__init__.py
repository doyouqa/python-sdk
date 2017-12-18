# -*- coding: utf-8 -*-
from __future__ import unicode_literals


class IMessage(object):

    def from_representation(self, msg_repr, **kwargs):
        """
        Generate a Message from its representation.

        Implementations may require additional keyword parameters, if they can't
        auto-detect excrypted messages, for example.

        :param msg_repr: :py:class:`~ntdi.keychain.Credentials`
        :type msg_repr: implementation-specific
        :returns: :py:class:`~ntdi.Message`
        """
        raise NotImplementedError

    def to_representation(self, msg, encrypt_to_kids=None, **kwargs):
        """
        Render a Message into its representation.

        Implementations may require additional keyword parameters, or ignore optional
        ones that aren't supported.

        :param msg: The message to render
        :type msg: :py:class:`~ntdi.Message`
        :param encrypt_to_kids: If given, the message should be encrypted to the given
               identities
        :type encrypt_to_kids: iterable of str
        """
        raise NotImplementedError
