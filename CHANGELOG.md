<a name="0.19.0"></a>
# [](https://github.com/Neustar-TDI/python-sdk/compare/0.18.0...0.19.0) (2017-07-28)


### Bug Fixes

* **jwts:** remove_jws_signatures handles bytes ([f6cf363](https://github.com/Neustar-TDI/python-sdk/commit/f6cf363))


### Features

* **ServerSession:** support for multiple sigs ([c1fdb29](https://github.com/Neustar-TDI/python-sdk/commit/c1fdb29))



<a name=0.18.0"></a>
# [0.18.0](https://github.com/OneID/oneID-connect-python/compare/0.17.2...0.18.0) (2017-03-01)


### Bug Fixes

* **keychain:** remove deprecated decryption params ([f3b9705](https://github.com/OneID/oneID-connect-python/commit/f3b9705))
* **symcrypt:** AES-GCM using 96-bit IVs ([18f2d8a](https://github.com/OneID/oneID-connect-python/commit/18f2d8a))
* **symcrypt:** better handling of hybrid mode ([79279a7](https://github.com/OneID/oneID-connect-python/commit/79279a7))


### Features

* **jwts:** include hint of sig state in new sigs ([1ec1127](https://github.com/OneID/oneID-connect-python/commit/1ec1127))


<a name=0.17.2"></a>
# [0.17.2](https://github.com/OneID/oneID-connect-python/compare/0.17.1...0.17.2) (2017-02-21)

* **session:** server gets msgs encrypted to proj ([131c369](https://github.com/OneID/oneID-connect-python/commit/131c369))
* documentation fixes and updates

<a name=0.17.1"></a>
# [0.17.1](https://github.com/OneID/oneID-connect-python/compare/0.17.0...0.17.1) (2017-01-18)

* documentation fixes and updates


<a name=0.17.0"></a>
# [0.17.0](https://github.com/OneID/oneID-connect-python/compare/0.15.0...0.17.0) (2017-01-18)


### Bug Fixes

* **docs:** add required blanks, underscores ([b8c50ae](https://github.com/OneID/oneID-connect-python/commit/b8c50ae))
* **flake8:** update for new requirement (E305) ([a622bb8](https://github.com/OneID/oneID-connect-python/commit/a622bb8))
* reduce unneeded calls to default_backend() ([1c4b89c](https://github.com/OneID/oneID-connect-python/commit/1c4b89c))
* **session:** send JWS/JWT as body from server ([a836251](https://github.com/OneID/oneID-connect-python/commit/a836251))


### Features

* **jws:** added multi signature arbitrary headers ([6eb967f](https://github.com/OneID/oneID-connect-python/commit/6eb967f))
* **keychain:** add support for JWKs ([23a0dd8](https://github.com/OneID/oneID-connect-python/commit/23a0dd8))
* **keychain:** Implement ECDH ([22d749b](https://github.com/OneID/oneID-connect-python/commit/22d749b))
* **service:** support AES KeyWrap mode ([8c3cba8](https://github.com/OneID/oneID-connect-python/commit/8c3cba8))
* **service:** support JWE for encryption ([fa6578b](https://github.com/OneID/oneID-connect-python/commit/fa6578b))
* **session:** add support for encrypted sessions ([628bb55](https://github.com/OneID/oneID-connect-python/commit/628bb55))
* **utils:** add timestamp converters ([de39553](https://github.com/OneID/oneID-connect-python/commit/de39553))



<a name="0.15.0"></a>
# [0.15.0](https://github.com/OneID/oneID-connect-python/compare/0.14.0...0.15.0) (2016-10-10)


### Bug Fixes

* **keypair:** better support for derived Keypairs ([4312b46](https://github.com/OneID/oneID-connect-python/commit/4312b46))
* **utils:** better way to refer to string types ([480ace9](https://github.com/OneID/oneID-connect-python/commit/480ace9))


### Features

* **jwts:** derive exp/jti exp one from the other ([91f47c7](https://github.com/OneID/oneID-connect-python/commit/91f47c7))
* **jwts:** support getting kids from jwt ([df1d589](https://github.com/OneID/oneID-connect-python/commit/df1d589))
* **nonces:** change nonce to include self-expiry ([c3ea5e6](https://github.com/OneID/oneID-connect-python/commit/c3ea5e6))
* **nonces,jwts:** split up verify and burn nonce ([386a9d1](https://github.com/OneID/oneID-connect-python/commit/386a9d1))
* **ServerSession:** Support multiple Device sigs ([8a16277](https://github.com/OneID/oneID-connect-python/commit/8a16277))
