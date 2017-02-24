---
title: 2FA Firmware Update
parent: index
order: 2
object-id: python-2fa
---

Sending Two-Factor Authenticated Firmware update to IoT Device
==============================================================

Sending a firmware update to all of your devices should always be
secure. The last thing you want is a malicious update sent to your
entire fleet of devices.

For this example, we’re going to use oneID’s two-factor authentication
service. oneID’s two-factor authentication service enables you to manage
all your servers and IoT devices. If a server or IoT device has been
compromised or taken out of commission, you can easily revoke its
signing permissions.

Before we begin, you will need `oneID-cli` and a [oneID developer
account].

    $ pip install oneid-cli

Intro to oneID’s Two-Factor Authentication
------------------------------------------

Two-factor means that there will be two signatures for each message.
**BOTH** signatures must be verified before reading the message. Since
there are two signatures that need to be verified on the IoT device, the
IoT device will need to store two public keys that will be used for
message verification. oneID will provide you with both of these public
keys for the IoT device.

### Steps:

1.  Server prepares a message for the IoT device and signs it.
2.  Server makes a two-factor authentication request to oneID with the
    prepared message.
3.  oneID verifies the server’s identity and responds with oneID’s
    signature for the message.
4.  Server then re-signs the message with the shared Project key.
5.  Server sends the message with the two signatures to the IoT device.
6.  IoT device verifies **BOTH** signatures.

Setup
-----

First we need to configure your terminal.

    oneid-cli configure

This will prompt you for your `ACCESS_KEY`, `ACCESS_SECRET`, and
`ONEID_KEY`. You can find all these in your [oneID developer
console][oneID developer account]

### Creating a Project

All users, servers and edge devices need to be associated with a
Project. Let’s create a new Project.

    $ oneid-cli create-project --name "my epic project"

This will prompt you to generate the public/private key pair for the
Project. Answer ‘Y’ at this step. You will be given the Project ID and
three keys. The first key is a oneID verification public key. The second
is the Project verification public key. The third is your Project
**SECRET** key.

> SAVE THE PROJECT SECRET KEY IN A SAFE PLACE. If you lose this key, you
> will lose your ability to send authenticated messages\` to your
> devices.

The oneID verification public key will be given to all your edge devices
and used to verify messages sent from a server.

In the following steps, we will assume a Project ID of
“d47fedd0-729f-4941-b4bd-2ec4fe0f9ca9”. You should substitute the one
you get back from oneid-cli create-project.

### Server

The firmware update message we will send to the IoT devices will be very
simple. The message will be a url to the CDN where the firmware
