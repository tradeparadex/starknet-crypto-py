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
# Order of the Stark curve and x-coordinate of its generator G.
EC_ORDER = 0x800000000000010FFFFFFFFFFFFFFFFB781126DCAE7B2321E66A241ADC64D2F
GENERATOR_X = 0x1EF15C18599971B7BECED415A40F0C7DEACFD9B0D1819E03D723D8BC943CFCA


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


# Inputs below make an intermediate point the point at infinity, where
# starknet-crypto 0.8 panics. A panic would abort the interpreter.


def test_get_public_key_of_zero_is_zero() -> None:
    assert get_public_key(0) == 0


def test_get_public_key_of_curve_order_is_zero() -> None:
    assert get_public_key(EC_ORDER) == 0


def test_get_public_key_of_one_is_generator() -> None:
    assert get_public_key(1) == GENERATOR_X


@pytest.mark.parametrize(
    "msg_hash, r",
    [
        # zw*G + rw*G is the point at infinity when z + r == EC_ORDER.
        (2**251 - 1, EC_ORDER - (2**251 - 1)),
        # zw*G - rw*G is the point at infinity when z == r.
        (12345, 12345),
    ],
)
def test_verify_returns_false_when_point_is_at_infinity(msg_hash: int, r: int) -> None:
    assert verify(public_key=GENERATOR_X, msg_hash=msg_hash, r=r, s=1) is False


def test_verify_accepts_valid_signature_on_zero_message_hash() -> None:
    # 0.6 mishandled zw*G at infinity and rejected these valid signatures.
    r, s = sign(private_key=TEST_PRIVATE_KEY, msg_hash=0, seed=123)
    assert verify(public_key=TEST_PUBLIC_KEY, msg_hash=0, r=r, s=s)


# Golden values produced by the 0.6.1 build, to pin exact output across upgrades.
@pytest.mark.parametrize(
    "private_key, msg_hash, seed, expected",
    [
        (
            TEST_PRIVATE_KEY,
            4660,
            123,
            (
                519954340796798709389420412224809586699420776092214144792443430147221530330,
                93916682931860496191050746278580021036734662482950828485346033469730204720,
            ),
        ),
        (
            TEST_PRIVATE_KEY,
            2**251 - 1,
            0,
            (
                820147907895988122687105228248783052293289348641117452145689349642217172758,
                3193568497867130552538666399940185969619396731828625147570557011124482309257,
            ),
        ),
        (
            TEST_PRIVATE_KEY,
            0,
            1,
            (
                3039344394958314298845852776274163987770634592192561427479999657603816324108,
                1995473322069631996547678752694997057189488801506630923756235976935538059553,
            ),
        ),
        (
            1,
            1,
            1,
            (
                157235303071910294139060624268655589164242055649545942031945585824084192665,
                208591895414547763458798776218880012956582335382598014154224872903688963238,
            ),
        ),
        (
            0x3C1E9550E66958296D11B60F8E8E7A7AD990D07FA65D5F7652C4A6C87D4E3CC,
            0x397E76D1667C4454BFB83514E120583AF836F8E32A516765497823EB127E6C1,
            0,
            (
                127529825374065179669621538970924143444783804395809193203459309736860744181,
                2053960128673257686131093969749614899266368482171611311908894743419558641850,
            ),
        ),
    ],
)
def test_sign_matches_known_vectors(private_key: int, msg_hash: int, seed: int, expected: tuple[int, int]) -> None:
    assert sign(private_key=private_key, msg_hash=msg_hash, seed=seed) == expected
    public_key = get_public_key(private_key)
    assert verify(public_key=public_key, msg_hash=msg_hash, r=expected[0], s=expected[1])


@pytest.mark.parametrize(
    "private_key, public_key",
    [
        (2, 3324833730090626974525872402899302150520188025637965566623476530814354734325),
        (3, 1839793652349538280924927302501143912227271479439798783640887258675143576352),
        (0xDEADBEEF, 2683315318760845674681526434086635785256194249937109290242750274563664560518),
        (EC_ORDER - 1, 874739451078007766457464989774322083649278607533249481151382481072868806602),
        (FIELD_PRIME - 1, 12842572803556059137564977444027983770110736029043973018710475811260460175),
    ],
)
def test_get_public_key_matches_known_vectors(private_key: int, public_key: int) -> None:
    assert get_public_key(private_key) == public_key


@pytest.mark.parametrize("private_key", [*range(1, 17), TEST_PRIVATE_KEY, EC_ORDER - 1])
def test_sign_and_verify_across_keys(private_key: int) -> None:
    # The public key carries only x, so verify picks one of two y values; across
    # several keys both the zw*G + rw*Q and zw*G - rw*Q checks get exercised.
    public_key = get_public_key(private_key)
    r, s = sign(private_key=private_key, msg_hash=4660, seed=123)
    assert verify(public_key=public_key, msg_hash=4660, r=r, s=s)
    assert not verify(public_key=public_key, msg_hash=4661, r=r, s=s)


def test_verify_returns_false_when_inverse_of_s_is_out_of_range() -> None:
    # w = s^-1 mod EC_ORDER must be below 2**251; this s has w == 2**251.
    s = pow(2**251, -1, EC_ORDER)
    r, _ = sign(private_key=TEST_PRIVATE_KEY, msg_hash=4660, seed=123)
    assert verify(public_key=TEST_PUBLIC_KEY, msg_hash=4660, r=r, s=s) is False


# Hex parsing must match starknet-ff's `from_hex_be`, which the 0.6 build used.
@pytest.mark.parametrize(
    "text, value",
    [
        ("0x", 0),
        ("", 0),
        ("0x0x5", 5),
        ("5", 5),
        ("0xABCDEF", 0xABCDEF),
        ("0xabcdef", 0xABCDEF),
        ("0x" + "0" * 63 + "1", 1),
        (hex(FIELD_PRIME - 1), FIELD_PRIME - 1),
    ],
)
def test_hex_parsing_accepts(text: str, value: int) -> None:
    assert rs_pedersen_hash(text, "0x1") == rs_pedersen_hash(hex(value), "0x1")


@pytest.mark.parametrize(
    "text, reason",
    [
        ("0X5", "invalid character"),
        (" 0x1", "invalid character"),
        ("0x1 ", "invalid character"),
        ("-0x1", "invalid character"),
        ("0x" + chr(0x661), "invalid character"),
        (hex(FIELD_PRIME), "number out of range"),
        (hex(2**256 - 1), "number out of range"),
        ("0x" + "0" * 65, "number out of range"),
        (hex(2**256), "number out of range"),
    ],
)
def test_hex_parsing_rejects(text: str, reason: str) -> None:
    with pytest.raises(ValueError, match=f"^invalid field element: {reason}$"):
        rs_pedersen_hash(text, "0x1")
