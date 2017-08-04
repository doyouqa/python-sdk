Installation for Intel Edison
=============================
First update to the latest `Yocto firmware update`_
After you've flashed and configured your Intel Edison, we can setup the Intel Edison with pip.

.. warning::
   Please make sure that your Intel Edison is connected to the internet before continuing.


* Open the base-feeds config file:

.. code:: console

    $ vi /etc/opkg/base-feeds.conf

* Add the following repositories:

.. code:: console

    $ src/gz all http://repo.opkg.net/edison/repo/all
    $ src/gz edison http://repo.opkg.net/edison/repo/edison
    $ src/gz core2-32 http://repo.opkg.net/edison/repo/core2-32

* Update opkg:

.. code:: console

    $ opkg update

* Install python pip:

.. code:: console

    $ opkg install python-pip

* Install the SDK:

.. code:: console

    $ pip install oneid-connect



.. _Yocto firmware update: http://www.intel.com/support/edison/sb/CS-035262.htm
