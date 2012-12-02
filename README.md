DESCRIPTION
===========

dnsstore is a proof-of-concept tool which can store arbitrary data in a
standard recursive resolver's cache with no special server software by abusing
wildcard domains. It's egregiously slow and inefficient, but it works. Keep in
mind that at best the data will survive only as long as the TTL of the base
domain and in the worst case not at all. The password serves as both a key for
encryption and, combined with the domain, a unique identifier for the data
stored. Using the same domain and password to save different data will cause
corruption.

USAGE
=====

dnsstore.pl _ip-of-recursive-resolver base-domain password [some string of data]_

Storing data:

`dnsstore.pl 8.8.8.8 ph swordfish 'all your cache are belong to us'`

Retreiving that data:

`dnsstore.pl 8.8.8.8 ph swordfish`

SECURITY
========

While the data is MAC'd with the password to prevent modification, anybody who
knows (or is able to guess) any of the hostnames used to store the data can
corrupt it by making lookups.

The password is protected with one million iteration PBKDF2, which should
somewhat deter efforts to crack passwords used.

Data is encrypted with Blowfish-CBC-256 and a static IV. This reduces the
overhead somewhat, and should still be secure. The static IV would allow
decryption of messages if you allow an attaker who can see your DNS requests
to encrypt chosen data under your password, so don't do that.
