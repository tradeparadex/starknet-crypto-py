# starknet-crypto-py

Python binding for the [starknet-crypto](https://github.com/xJonathanLEI/starknet-rs/tree/master/starknet-crypto) rust library.

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
