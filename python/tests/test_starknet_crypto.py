import pytest
from starknet_crypto_py import get_public_key, pedersen_hash, sign, verify

TEST_PRIVATE_KEY = (
    2708384690123958484688745363115889726043588718997906908187752842753359350371
)
TEST_PUBLIC_KEY = (
    1673729114437878727516854592246827335452530539480870878860719335128967723895
)


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
    (r, s) = sign(private_key=TEST_PRIVATE_KEY, msg_hash=4660)
    is_valid = verify(public_key=TEST_PUBLIC_KEY, msg_hash=4660, r=r, s=s)
    assert is_valid
