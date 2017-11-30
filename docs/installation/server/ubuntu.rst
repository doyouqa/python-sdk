Installation for Ubuntu
=======================
The Python SDK depends on two external libraries, cryptography.io and openSSL.
cryptography.io is a library that exposes cryptographic primitives from openSSL.

The SDK should build easily on most Linux distributions that have a C compiler,
openSSL headers and the ``libffi`` libraries.

.. code:: console

    $ sudo apt-get install build-essential libssl-dev libffi-dev python-dev

You should now be able to install the SDK with the usual

.. code:: console

    $ pip install ntdi
