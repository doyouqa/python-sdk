.. image:: https://circleci.com/gh/OneID/oneID-connect-python.svg?style=svg
    :target: https://circleci.com/gh/OneID/oneID-connect-python

oneID Connect
=============
oneID-connect is a Python authentication framework for the Internet of Things (IoT),
servers and end-users. By sending messages with digital signatures, you can authenticate
the origin of the message and ensure the message hasn't been tampered with.
oneID-connect makes it simple for projects that need to securely send messages and verify
the authentication of messages.

For more information, please visit the docs.
`<http://oneid-connect.readthedocs.org/en/latest/>`_

Building the API Docs Locally
=============================
oneid-connect-python uses Sphinx to create documentation. Following these instructions builds the docs locally and outputs them to ``./docs/_build/html``.
You may not need a python virtual environment if python is installed universally on your machine.

#. Create a virtualenv in oneid-connect-python.
#. To install requirements, run ``pip install -r requirements.txt -r docs_requirements.txt`` to install all requirements defined in the repo. This should install sphinx, sphinx_rtd_theme, and more.
#. From the project dir, run ``sphinx-build -b html ./docs ./docs/_build`` OR from ./docs, run ``make html``
#. Run ``make clean`` from ./docs to remove the build.
