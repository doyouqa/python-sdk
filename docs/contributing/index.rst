Contributing
============

If you have improvements to ``Neustar-TDI/python-sdk``, send us your pull requests! ``Neustar-TDI/python-sdk``
is hosted on GitHub at `<https://github.com/Neustar-TDI/python-sdk>`_ and
we welcome contributions of all forms. We use GitHub's `issue tracking`_ and
collaboration tools exclusively for managing development.

.. _issue tracking: https://github.com/Neustar-TDI/python-sdk/issues


Getting Started
---------------
Working on ``Neustar-TDI/python-sdk`` requires additional packages, such as `pytest`_, `mock`_ and `Sphinx`_.

.. code-block:: console

  $ pip install -r dev_requirements
  $ pip install -e .
  $ pip install -r docs_requirements


You are now ready to run tests and build documentation.

.. _pytest: https://docs.pytest.org/en/latest/
.. _mock: https://github.com/testing-cabal/mock
.. _Sphinx: http://sphinx-doc.org/index.html

Running Tests
-------------
Unit tests are found in the ``tests/`` directory and are designed to use python's
``unittest`` library. ``pytest`` will discover the tests automatically.

.. code-block:: console

  $ pytest

Cross-version tests require installing additional Python versions, and setting up the local
``tox`` environment:

.. code-block:: console

  $ pyenv install 3.6.1
  $ pyenv install 3.5.1
  $ pyenv install 3.4.0
  $ pyenv install 2.7.13
  $ pyenv local 3.6.1 3.5.1 3.4.0 2.7.13


Building Documentation
----------------------
Documentation is stored in the ``docs/`` directory. It is written
in `reStructedText`_ and rendered using `Sphinx`_.

.. code-block:: console

  $ make html


.. _reStructedText: http://sphinx-doc.org/rest.html

Submitting Bugs
---------------
.. important::
 Please report security issues only to `security@oneID.com`_. This is a private list
 only open to highly trusted cryptography developers.

* Check that someone hasn't already filed the bug by searching GitHub's `issue tracker`_.
* Don't use GitHub's issue tracker for support questions. Use `Stack Overflow`_ and tag ``Neustar-TDI/python-sdk`` for that.
* Provide information so we can replicate the bug on our end. (Python version, SDK version, OS, code samples, et cetera).


Requesting Features
-------------------
We're always trying to make ``Neustar-TDI/python-sdk`` better, and your feature requests are a key part of that.

* Check that someone hasn't already requested the feature by searching GitHub's `issue tracker`_.
* Clearly and concisely describe the feature and how you would like to see it implemented. Include example code if possible.
* Explain why you would like the feature. Sometimes it's very obvious, other times a use case will help us understand the importance of the requested feature.


.. _security@oneID.com: mailto:security@oneid.com
.. _issue tracker: https://github.com/Neustar-TDI/python-sdk/issues
.. _Stack Overflow: http://stackoverflow.com/questions/tagged/oneid-connect


Contributing Changes
--------------------
.. attention::
 Always make a new branch for your work, no matter how small!

.. warning::
 Don't submit unrelated changes in the same branch/pull request! We would hate to see an amazing
 pull request get rejected because it contains a bug in unrelated code.

* All new functions and classes **MUST** be documented and accompanied with unit tests.
* Our coding style follows `PEP 8`_.
* In docstrings we use reStructedText as described in `PEP 287`_

.. code-block:: python

  def foo(bar):
      """
      Makes input string better.

      :param bar: input to make better
      :return: a better input
      """
      ...


* Patches should be small to facilitate easier review.
* New features should branch off of ``master`` and once finished, submit a pull request into ``develop``.
* ``develop`` branch is used to gather all new features for an upcoming release.
* Bug fixes should be based off the branch named after the oldest supported release the bug affects.

 - If a feature was introduced in 1.1 and the latest release is 1.3, and a bug is found in that feature,
   make your branch based on 1.1. The maintainer will then forward-port it to 1.3 and master.

* You **MUST** have legal permission to distribute any code you contribute to ``Neustar-TDI/python-sdk``.
* Class names which contains acronyms or initials should always be capitalized. i.e. ``AESEncrypt`` not ``AesEncrypt``.

.. _PEP 8: https://www.python.org/dev/peps/pep-0008/
.. _PEP 287: https://www.python.org/dev/peps/pep-0287/
