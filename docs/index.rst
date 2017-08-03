.. python-sdk documentation master file, created by
   sphinx-quickstart on Mon Nov  2 17:57:31 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Neustar Trusted Device Identity (TDI)
=====================================
Release |release|

Neustar TDI (formerly oneID-connect) is an authentication framework for the Internet of Things (IoT), servers and end-users.
By sending messages with digital signatures, you can authenticate the origin of the message and
ensure the message hasn't been tampered with. Neustar TDI makes it simple for projects that need to
send authenticated messages and verify the authentication of messages.

``Neustar-TDI/python-sdk`` can be installed on IoT devices and servers that support python 2.7, 3.4, 3.5 or 3.6.
``Neustar-TDI/python-sdk`` depends on two external libraries: the cryptography.io python package and openSSL.



Introduction
------------
Security for IoT devices can be challenging to implement and difficult to mange at scale.
So Neustar has created a secure two-factor mutual authentication
platform that securely connects users to their IoT devices, while enabling product servers to securely send firmware updates
to those same IoT devices. We do this using state of the art `Elliptical Curve cryptography`_.

Installation
~~~~~~~~~~~~

.. toctree::
   :maxdepth: 3

   installation/index

Tutorials
~~~~~~~~~

.. toctree::
   :maxdepth: 2

   tutorials/index

API
~~~

.. toctree::
   :maxdepth: 2

   api/index

Contributing
~~~~~~~~~~~~

.. toctree::
   :maxdepth: 2

   contributing/index


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. _Elliptical Curve cryptography: https://en.wikipedia.org/wiki/Elliptic_curve_cryptography
