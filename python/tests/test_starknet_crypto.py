from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import pytest
from starknet_crypto_py import get_public_key, pedersen_hash, sign, verify
from starknet_crypto_py.starknet_crypto_py import (
    rs_get_public_key,
    rs_pedersen_hash,
    rs_sign,
    rs_verify,
)

TEST_PRIVATE_KEY = (
    2708384690123958484688745363115889726043588718997906908187752842753359350371
)
TEST_PUBLIC_KEY = (
    1673729114437878727516854592246827335452530539480870878860719335128967723895
)
# Starknet field prime: the smallest value that is not a valid field element.
FIELD_PRIME = 2**251 + 17 * 2**192 + 1
# No point on the Stark curve has this x-coordinate.
NOT_ON_CURVE_X = 5


def test_get_public_key() -> None:
    generated_public_key = get_public_key(TEST_PRIVATE_KEY)
    assert generated_public_key == TEST_PUBLIC_KEY


@pytest.mark.parametrize(
    "first, second, msg_hash",
    [
        (
            0,
            13289654017234601382751,
            1606983897751845338544875557254529092665736388485573456407652201602816719974,
        ),
        (
            32108945712395,
            0,
            2286557865806578472402728224133061485859287443532833874408098272076626850762,
        ),
        (
            0,
            0,
            2089986280348253421170679821480865132823066470938446095505822317253594081284,
        ),
        (
            1,
            1,
            1321142004022994845681377299801403567378503530250467610343381590909832171180,
        ),
        (
            132490123765801925,
            19324857132905126,
            351268190682426987433778012669634681582518614860795408913953487271166523161,
        ),
        (
            1321142004022994845681377299801403567378503530250467610343381590909832171180,
            351268190682426987433778012669634681582518614860795408913953487271166523161,
            167060788452737184339236199176292038116565645273096529093530464707363566091,
        ),
    ],
)
def test_pedersen_hash(first: int, second: int, msg_hash: int) -> None:
    assert pedersen_hash(first, second) == msg_hash


def test_sign_and_verify() -> None:
    r, s = sign(private_key=TEST_PRIVATE_KEY, msg_hash=4660, seed=123)
    is_valid = verify(public_key=TEST_PUBLIC_KEY, msg_hash=4660, r=r, s=s)
    assert is_valid


@pytest.mark.parametrize(
    "fn, args",
    [
        (rs_get_public_key, ("0xzz",)),
        (rs_pedersen_hash, ("0xzz", "0x1")),
        (rs_pedersen_hash, ("0x1", "0xzz")),
        (rs_sign, ("0xzz", "0x1234", "0x7b")),
        (rs_sign, ("0x1", "0xzz", "0x7b")),
        (rs_sign, ("0x1", "0x1234", "0xzz")),
        (rs_verify, ("0xzz", "0x1", "0x1", "0x1")),
        (rs_verify, ("0x1", "0x1", "0x1", "0xzz")),
    ],
)
def test_invalid_hex_raises_value_error(
    fn: Callable[..., object], args: tuple[str, ...]
) -> None:
    with pytest.raises(ValueError, match="invalid field element"):
        fn(*args)


def test_sign_is_deterministic() -> None:
    first = sign(private_key=TEST_PRIVATE_KEY, msg_hash=4660, seed=123)
    second = sign(private_key=TEST_PRIVATE_KEY, msg_hash=4660, seed=123)
    assert first == second


def test_verify_rejects_wrong_message() -> None:
    r, s = sign(private_key=TEST_PRIVATE_KEY, msg_hash=4660, seed=123)
    assert not verify(public_key=TEST_PUBLIC_KEY, msg_hash=4661, r=r, s=s)


def test_verify_rejects_tampered_signature() -> None:
    r, s = sign(private_key=TEST_PRIVATE_KEY, msg_hash=4660, seed=123)
    assert not verify(public_key=TEST_PUBLIC_KEY, msg_hash=4660, r=r, s=s + 1)


@pytest.mark.parametrize("value", [-1, FIELD_PRIME])
def test_out_of_range_input_raises_value_error(value: int) -> None:
    with pytest.raises(ValueError, match="invalid field element"):
        pedersen_hash(value, 0)
    with pytest.raises(ValueError, match="invalid field element"):
        get_public_key(value)


def test_invalid_private_key_is_not_echoed_in_error() -> None:
    secret = FIELD_PRIME + 0xC0FFEE
    with pytest.raises(ValueError) as exc_info:
        sign(private_key=secret, msg_hash=4660, seed=123)
    assert hex(secret)[2:] not in str(exc_info.value).lower()


def test_sign_rejects_message_hash_out_of_range() -> None:
    with pytest.raises(ValueError, match="signing failed"):
        sign(private_key=TEST_PRIVATE_KEY, msg_hash=2**251, seed=123)


@pytest.mark.parametrize(
    "field, value",
    [("msg_hash", 2**251), ("r", 0), ("r", 2**251), ("s", 0), ("s", 2**251)],
)
def test_verify_returns_false_for_out_of_range_values(field: str, value: int) -> None:
    r, s = sign(private_key=TEST_PRIVATE_KEY, msg_hash=4660, seed=123)
    args = {"public_key": TEST_PUBLIC_KEY, "msg_hash": 4660, "r": r, "s": s}
    args[field] = value
    assert verify(**args) is False


def test_verify_raises_for_public_key_not_on_curve() -> None:
    r, s = sign(private_key=TEST_PRIVATE_KEY, msg_hash=4660, seed=123)
    with pytest.raises(ValueError, match="verification failed"):
        verify(public_key=NOT_ON_CURVE_X, msg_hash=4660, r=r, s=s)


def test_concurrent_calls_match_serial_results() -> None:
    # Results must be unaffected when the module is used from several threads.
    msg_hashes = list(range(1, 33))
    expected = [sign(TEST_PRIVATE_KEY, m, 123) for m in msg_hashes]
    with ThreadPoolExecutor(max_workers=8) as pool:
        actual = list(pool.map(lambda m: sign(TEST_PRIVATE_KEY, m, 123), msg_hashes))
    assert actual == expected
    assert all(
        verify(TEST_PUBLIC_KEY, m, r, s)
        for m, (r, s) in zip(msg_hashes, actual, strict=True)
    )
