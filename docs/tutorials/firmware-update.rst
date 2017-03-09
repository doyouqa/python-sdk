Sending Two-Factor Authenticated Firmware update to IoT Device
==============================================================
Sending a firmware update to all of your devices should always be secure.
The last thing you want is a malicious update sent to your entire fleet of devices.

In this tutorial, we will show you how to send a message with verified content and origin from one device to another. We will create a simple server and client to demonstrate how to implement this pattern with oneID.

Our server in pseudo code will essentially do the following:

.. code-block:: console

   keys = acquireKeys()
   message = "some arbitrary message"
   signed message = sign(message,keys)
   saveToFile(signed message)

Our client in pseudo code will look something like this:

.. code-block:: console

   keys = acquireKeys()
   signed message = loadMessageFromFile()
   message = verify(message,keys)
   print(message)


Overview
------------------------------------------
The components of a oneID-enabled IoT applications are below:

**Fleet Project:** The container for your IoT application and all its servers/devices.

**Fleet Server:** A server in your IoT infrastructure.

**OneID Fleet Co-Signer Service:** A centralized authorization point used to manage Project Servers

**EdgeDevices:** This is the identity of your IoT device in the IoT system.

For our demo we will need to create

* server.py - The device that wants to send a message to another device
* device.py - The device that will recieve a message and requires a message to be co-signed by a trusted signatory



Setup Environment
-----------------

Clone the Fleet
~~~~~~~~~~~~~~~~~~
.. code-block:: console

   git clone git@github.com:OneID/oneID-connect-sample-apps.git
   cd oneID-connect-sample-apps
   git checkout feature/jh/auto-configuration

Install the Dependencies
~~~~~~~~~~~~~~~~~~~~~~~~
OPTIONAL: create any virtual environment for python if you use one
NOTE: If you choose not to use a virtual environment be sure to install the latest oneId packages

.. code-block:: console

   pip install -r requirements.txt
   pip install -r requirements_dev.txt


Run the Setup Script
~~~~~~~~~~~~~~~~~~~~
This can be easily done with the oneID cli tool. To get you up and running as quickly as possible, we have automated this with a setup script:

.. code-block:: console

    ENV=dev ./setup.sh

This will generate all the entities needed for the tutorial, create necessary keys for your device and server, and generate a config file.
Now we are ready to get started on the server.

In order to utilize oneID to do message signing with the cosigner service, we need to create a ServerSession. This session will accept as arguments the keys that we want to sign our message with. So our first step will be to load those keys. We can utilize our generated config file to make this a little easier.


The Fleet Server
~~~~~~~~~~~~~~~~
Create a server.py file:

.. code-block:: console

    touch server.py

Edit server.py to include the following lines of code:

.. code-block:: python

    import ConfigParser
    from oneid.keychain import Keypair, Credentials
    from oneid.session import ServerSession
    Config = ConfigParser.ConfigParser()
    Config.read('./config.ini')

This simply includes the dependencies we need and loads in the config file which we will use next.
Now lets build the credentials for our server. We can start with creating a little helper function `build_credentials`. Append the following to your server.py file:

.. code-block:: python

    def build_credentials(identity, key_path):
    keypair = Keypair.from_secret_pem(path=key_path)
    keypair.identity = identity
    return Credentials( identity, keypair)

Here we use the id of an entity and a path to its secret key and we generate a set of credentials. With that boilerplate out of the way, we can focus on the specific case of our servers credentials which will be verified by the cosigning server before it cosigns any message. Add the code below to your growing server file:

.. code-block:: python

    def get_server_credentials():
      # Pull our server ID from the configuration file
      server_id = Config.get('PROJECT_ONE', 'SERVER_ID')
      project_id = Config.get('PROJECT_ONE', 'PROJECT_ID')
      # Build the path to our server's private key
      server_secret_key_path = (
          './projects/project-{pid}/server-{sid}/server-{sid}-priv.pem'.format(
              pid=project_id, sid=server_id
          )
      )
      #Generate credentials
      credentials = build_credentials(server_id, server_secret_key_path)
      return credentials

Our `get_server_credentials()` function simply pulls the server key from our config file and generates a path string to the directory where our setup script stored our server key.
If the cosigning service successfully verifies a message sent from our server to be cosigned, the cosigning service will cosign that message with its own key and send that message back. EdgeDevices have no knowledge of the Fleet Server identities, they only know about the Cosigner key and the Fleet key. In order for us to get a validly signed message from the EdgeDevice's perspective, the oneId SDK will need to sign with the Project key. We will need to build these credentials in order to create our Session, but this is exactly the same process we took when we generated the server credentials.  Add the code below to your growing server file:

.. code-block:: python

    def get_project_credentials():
      # Pull our project ID from the configuration file
      project_id = Config.get('PROJECT_ONE', 'PROJECT_ID')
      # Build the path to our projects's private key
      project_secret_key_path = (
          './projects/project-{pid}/project-{pid}-priv.pem'.format(
              pid=project_id
          )
      )
      #Generate credentials
      credentials = build_credentials(project_id, project_secret_key_path)
      return credentials

This is nearly identical to our server credential generation so we can safely skip the analysis.
We now have everything we need to create a Session and use it to sign a message. Paste the following code at the end of your server.py file.

.. code-block:: python

    server_session = ServerSession(
        identity_credentials=get_server_credentials(),
        project_credentials=get_project_credentials()
    )

In the above snippet, we create our session which allows us to request cosigned messages on behalf of our server.

Now we can build the message we want to send to the device with the following call:

.. code-block:: python

    # Request oneID Co-signature
    device_msg = server_session.prepare_message(
        download_url='http://mycompany.com/firmwareupdate',
        checksum=0xdeadbeef,
    )

If this call succeeds, it means the oneId cosigner still trusts our server and 'device_msg' will contain the signed message to be delivered to the device.
For simplicity, we will just save our message to a file for the device implementation to load.

.. code-block:: python

    with open('signed_message.json', 'w') as outfile:
        outfile.write(device_msg)


Test Your Script
~~~~~~~~~~~~~~~~
Run the following

.. code-block:: console

    ONEID_API_SERVER_BASE_URL=https://api-dev.oneid.com python server.py

It should generate a file called `signed_message.json` that has your signed message in it.

The Device
~~~~~~~~~~
Our device will be very simple. It will
#. Load our signed message
#. Verify message signature
#. Log out the message contents

Create a device.py file:

.. code-block:: console

   touch device.py

Let's initialize our device.py with the following code:

.. code-block:: console

   import ConfigParser
   from oneid.keychain import Keypair, Credentials
   from oneid.session import DeviceSession
   Config = ConfigParser.ConfigParser()
   Config.read('./config.ini')

Much like our server, we need to do the basic imports and load in our config file.
We also will need to generate a Session instance in order to verify a message. Since we are verifying signatures, we wont be using private keys as in the server; we will use public keys.  Note, we are not loading in the Server Public Key, but instead loading the OneId Key. This is an important difference in understanding how oneID maintains access control to the device. Messages must be signed with the OneId Cosigner Key, NOT the Server Key. Let's create functions to load in the public credentials for the oneID cosigner and the Project to which our device belongs with the following code.

.. code-block:: python

    def get_oneid_credentials():
        project_id = Config.get('PROJECT_ONE', 'PROJECT_ID')
        oneid_public_key_path = (
            './projects/project-{pid}/project-{pid}-oneid-pub.pem'.format(
                pid=project_id
            )
        )
        oneid_keypair = Keypair.from_public_pem(path=oneid_public_key_path)
        oneid_keypair.identity = 'project/' + project_id
        return Credentials(
            identity=oneid_keypair.identity,
            keypair=oneid_keypair
        )
    def get_project_credentials():
        project_id = Config.get('PROJECT_ONE', 'PROJECT_ID')
        project_public_key_path = (
            './projects/project-{pid}/project-{pid}-pub.pem'.format(
                pid=project_id
            )
        )
        project_keypair = Keypair.from_public_pem(path=project_public_key_path)
        project_keypair.identity = project_id
        return Credentials(
            identity=project_keypair.identity,
            keypair=project_keypair
        )

You will notice two key differences here. We are calling `Keypair.from_public_pem` instead of `Keypair.from_private_pem` and we are using a path that points to where we are keeping our oneID keypair on file.

With these helper functions, we can now instantiate our DeviceSession with the following code:


.. code-block:: python

    device_session = DeviceSession(
        project_credentials=get_project_credentials(),
        oneid_credentials=get_oneid_credentials()
    )

We are now ready to grab the signed_message our server saved

.. code-block:: python

    message_file = open('signed_message.json','r')
    signed_message = message_file.read()

Now we can verify the message and pull out some of the claims.

.. code-block:: python

    #This will throw an error if its not verified
      claims = device_session.verify_message(signed_message)
      print('Success!')
      print(claims.get('download_url'))
      print(claims.get('checksum'))

If the message had an invalid signature, the SDK will throw an error during the `verify_message` call. Depending on the time between when you first ran the server.py file and your device.py that may infact be the case because the token expiration of the signature. Generate an updated signature by running server.py and then run device.py immediately after.

Test your Script
~~~~~~~~~~~~~~~~

Run the following

.. code-block:: console

    ONEID_API_SERVER_BASE_URL=https://api-dev.oneid.com python device.py

It should generate a file called `signed_message.json' that has your signed message in it.

.. code-block:: console

    Success!
    http://mycompany.com/firmwareupdate
    3735928559


.. _oneID developer account: https://developer.oneid.com/console
.. _oneID developer console: https://developer.oneid.com/console
.. _Redis Quick Start: http://redis.io/topics/quickstart
