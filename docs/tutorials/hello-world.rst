Hello World
===========

Here is a simple "hello world" message with a digital signature and verified.

Before we can sign or verify any messages, we first need to create a private key.

.. code:: python

    from ntdi import service
    # Directory to save the private key (should be secure enclave)
    private_key_pem_path = '/Users/me/my_private_key.pem'
    keychain.create_private_keypair(output=private_key_pem_path)

You should now have a private key pem file that begins with ``-----BEGIN PRIVATE KEY-----``

Now we can create our "hello world" message and sign it.

.. code:: python

    from ntdi.keychain import Keypair

    message = 'hello world'

    my_key = Keypair.from_private_pem(path=private_key_pem_path)
    signature = my_key.sign(message)
    print(signature)

To verify the signature, we need to pass in the message and the signature back into the Keypair.

..  code:: python

    my_key.verify(message, signature)

That's it!

If you want to see what happens if the message has been tampered with, replace ``hello world`` with
something else like ``hello universe``.

.. code:: python

    # raises InvalidSignature
    my_key.verify('hello universe', signature)
