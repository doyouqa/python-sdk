Sending Two-Factor Authenticated Firmware update to IoT Device
==============================================================
Sending a firmware update to all of your devices should always be secure.
The last thing you want is a malicious update sent to your entire fleet of devices.

For this example, we're going to use Neustar TDI's two-factor authentication service.
Neustar TDI's two-factor authentication service enables you to manage all your servers
and IoT devices. If a server or IoT device has been compromised or taken out of
commission, you can easily revoke it's signing permissions.

Before we begin, you will need ``oneID-cli`` and a `Neustar TDI developer account`_.

.. code-block:: console

   $ pip install oneid-cli



Intro to Neustar TDI's Two-Factor Authentication
------------------------------------------
Two-factor means that there will be two signatures for each message.
**BOTH** signatures must be verified before reading the message.
Since there are two signatures that need to be verified on the IoT device,
the IoT device will need to store two public keys that will be used for message verification.
Neustar TDI will provide you with both of these public keys for the IoT device.

Steps:
~~~~~~
#. Server prepares a message for the IoT device and signs it.
#. Server makes a two-factor authentication request to Neustar TDI with the prepared message.
#. Neustar TDI verifies the server's identity and responds with Neustar TDI's signature for the message.
#. Server then re-signs the message with the shared Project key.
#. Server sends the message with the two signatures to the IoT device.
#. IoT device verifies **BOTH** signatures.



Setup
-----
First we need to configure your terminal.

.. code-block:: console

   oneid-cli configure

This will prompt you for your ``ACCESS_KEY``, ``ACCESS_SECRET``, and ``ONEID_KEY``.
You can find all these in your `Neustar TDI developer console`_


Creating a Project
~~~~~~~~~~~~~~~~~~
All users, servers and edge devices need to be associated with a Project.
Let's create a new Project.

.. code-block:: console

   $ oneid-cli create-project --name "my epic project"

This will prompt you to generate the public/private key pair for the Project.
Answer 'Y' at this step.
You will be given the Project ID and three keys.
The first key is a Neustar TDI verification public key.
The second is the Project verification public key.
The third is your Project **SECRET** key.

.. danger::
  SAVE THE PROJECT SECRET KEY IN A SAFE PLACE.
  If you lose this key, you will lose your ability to send authenticated messages`
  to your devices.

The Neustar TDI verification public key will be given to all your edge devices and used
to verify messages sent from a server.

In the following steps, we will assume a Project ID of "d47fedd0-729f-4941-b4bd-2ec4fe0f9ca9".
You should substitute the one you get back from `oneid-cli create-project`.


Server
~~~~~~
The firmware update message we will send to the IoT devices will be very simple.
The message will be a url to the CDN where the firmware update is hosted
and a checksum the IoT device will use to verify the download.

Before we can sign any messages, we need to give the server an identity
Neustar TDI can verify.

.. code-block:: console

   $ oneid-cli provision --project-id d47fedd0-729f-4941-b4bd-2ec4fe0f9ca9 --name "IoT server" --type server

This will generate a new **SECRET** ``.pem`` file.

.. danger::

   PLEASE STORE SECRET FILES IN A SAFE PLACE. Never post them in a public forum
   or give them to anyone.

If you created the server secret key on your personal computer, we need to copy it over to the
server along with the Project key that was generated when you first created the Project.

.. code-block:: console

    $ scp /Users/me/secret/server_secret.pem ubuntu@10.1.2.3:/home/www/server_secret.pem
    $ scp /Users/me/secret/project_secret.pem ubuntu@10.1.2.3:/home/www/project_secret.pem
    $ scp /Users/me/secret/oneid_public.pem ubuntu@10.1.2.3:/home/www/oneid_public.pem

In Python, we're just going to hardcode the path to these keys for quick access.


.. code-block:: python

    import json
    import logging

    from oneid.keychain import Keypair, Credentials
    from oneid.session import ServerSession

    logging.basicConfig(level=logging.WARNING)

    logger = logging.getLogger('fw_update.py')

    # Unique Project ID provided by Neustar TDI
    PROJECT_ID = 'b7f276d1-6c86-4f57-85e8-70105316225b'
    PROJECT_PROJECT_ID = 'project/' + PROJECT_ID

    # Unique Server ID,
    SERVER_ID = '709ec376-7e8c-40fc-94ee-14887023c885'

    # Secret keys we downloaded from Neustar TDI Developer Portal
    server_secret_key_path = (
        './project-{pid}/server-{sid}/server-{sid}-priv.pem'.format(
            pid=PROJECT_ID, sid=SERVER_ID
        )
    )
    project_secret_key_path = (
        './project-{pid}/project-{pid}-priv.pem'.format(
            pid=PROJECT_ID, sid=SERVER_ID
        )
    )

    server_key = Keypair.from_secret_pem(path=server_secret_key_path)
    server_key.identity = SERVER_ID
    server_credentials = Credentials(SERVER_ID, server_key)

    project_key = Keypair.from_secret_pem(path=project_secret_key_path)
    project_key.identity = PROJECT_PROJECT_ID
    project_credentials = Credentials(PROJECT_ID, project_key)

    server_session = ServerSession(
        identity_credentials=server_credentials,
        project_credentials=project_credentials
    )

    device_msg = server_session.prepare_message(
        download_url='http://mycompany.com/firmwareupdate',
        checksum=0xdeadbeef,
    )
    logger.debug('device_msg=%s', device_msg)

The final step is to send the two-factor ``authenticated_msg``
to the IoT device. You can use any network protocol you want,
or a messaging protocol such as MQTT, RabbitMQ, Redis etc.


IoT Device
~~~~~~~~~~
Just like we did with the server, we need to provision our IoT device.

.. code-block:: console

    $ oneid-cli provision --project-id d47fedd0-729f-4941-b4bd-2ec4fe0f9ca9 --name "my edge device" --type edge_device


Now we need to copy over the Neustar TDI verifier key, Project verifier key and the
new device secret key. The Neustar TDI verifier key can be downloaded
from the `Neustar TDI developer console`_.

You can print out your Project verifier key by adding a snippet to the previous code
example.

.. code-block:: python

   import base64
   project_verifier = base64.b64encode(project_key.public_key_der)
   print(project_verifier)

If you can SSH into your IoT device, you can do the same thing that we did with the server
and copy over the device identity secret key. Since the Neustar TDI and Project verifier keys
are static for all devices in a Project, we can hard code them in.

.. code-block:: console

    $ scp /Users/me/secret/device_secret.pem edison@10.1.2.3:/home/root/device_secret.pem

Now that we have the message that was sent to the IoT device, let's check the message's authenticity
by verifying the digital signatures.

.. code-block:: python

    from oneid.keychain import Keypair, Credentials
    from oneid.session import DeviceSession

    oneid_public_key_path = './oneid-pub.pem'
    oneid_keypair = Keypair.from_public_pem(path=oneid_public_key_path)
    oneid_keypair.identity = PROJECT_ID

    project_public_key_path = './project-pub.pem'
    project_keypair = Keypair.from_public_pem(path=project_public_key_path)
    project_keypair.identity = PROJECT_PROJECT_ID

    device_session = DeviceSession(
        project_credentials=Credentials(
            identity=project_keypair.identity,
            keypair=project_keypair
        ),
        oneid_credentials=Credentials(
            identity=oneid_keypair.identity,
            keypair=oneid_keypair
        )
    )

    try:
        claims = device_session.verify_message(device_msg)
        msg = json.loads(claims.get('message', '{}'))

        logger.debug('claims=%s', claims)
        print('Success!')
        print('  URL={}'.format(msg.get('download_url')))
        print('  checksum=0x{:08x}'.format(msg.get('checksum')))
    except:
        print('Failed.')
        logger.warning('error: ', exc_info=True)


.. _Neustar TDI developer account: https://developer.oneid.com/console
.. _Neustar TDI developer console: https://developer.oneid.com/console
.. _Redis Quick Start: http://redis.io/topics/quickstart
