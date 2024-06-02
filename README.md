# starknet-crypto-py

Python binding for the [starknet-crypto](https://github.com/xJonathanLEI/starknet-rs/tree/master/starknet-crypto) rust library.

## Examples

```python
from starknet_crypto_py import get_public_key, pedersen_hash, sign, verify

EC_ORDER = 0x800000000000010FFFFFFFFFFFFFFFFB781126DCAE7B2321E66A241ADC64D2F
PRIVATE_KEY = "0x..." # Enter starknet private key here

public_key = get_public_key(PRIVATE_KEY)
print(public_key)

msg_hash = pedersen_hash(first, second)
print(msg_hash)

r, s = sign(private_key=PRIVATE_KEY, msg_hash=msg_hash)
print(r, s)

is_valid = verify(public_key=public_key, msg_hash=msg_hash, r=r, s=s)
```

## Commands

```bash
make clean
make check
make build
make sdist
make develop
make test
```

## Releasing a new version

- Create an API Token on [Pypi](https://pypi.org/).
- Add the API Token to secrets with the name `PYPI_TOKEN` by visiting [this page](https://github.com/tradeparadex/starknet-crypto-py/settings/secrets/actions/new).
- Create a [new release](https://github.com/tradeparadex/starknet-crypto-py/releases/new) on Github.
- Create a new tag in the form `*.*.*`.

For more details, see [here](https://www.maturin.rs/distribution).
