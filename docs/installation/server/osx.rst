Installation for Mac OS X
=========================
The cryptography.io requirement is a statically linked build for Yosemite and above.
You only need one step:

.. code:: console

    $ pip install ntdi

If you're using an older version of OS X or want to link to a specific version
of openSSL you will need a C compiler, development headers and possibly
even the openSSL Library. This is all provided by Apple's Xcode development tools.

.. code:: console

    $ xcode-select --install

This will install a compiler and the development libraries required.
