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

r, s = sign(private_key=PRIVATE_KEY, msg_hash=msg_hash, seed=123)
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

Releases are published to PyPI from GitHub Actions using
[trusted publishing](https://docs.pypi.org/trusted-publishers/), so no API token is stored in the repository.

One-time setup: on the PyPI project page, go to *Manage → Publishing* and add a GitHub publisher with:

- Owner: `tradeparadex`
- Repository: `starknet-crypto-py`
- Workflow name: `CI.yml`
- Environment: leave empty

To release:

- Bump the version in `Cargo.toml` and `pyproject.toml`.
- Create a [new release](https://github.com/tradeparadex/starknet-crypto-py/releases/new) on Github with a new tag in the form `*.*.*`.
- The `CI` workflow builds one abi3 wheel per platform (CPython 3.10+), tests it on Python 3.10–3.14, and publishes the wheels and sdist to PyPI.

For more details, see [here](https://www.maturin.rs/distribution).
