import json
import string
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "py"))
import core  # noqa: E402


# ---------------------------- generate_password ----------------------------
def test_default_password_follows_original_rules():
    for _ in range(300):
        pw = core.generate_password()
        letters = [c for c in pw if c in string.ascii_letters]
        symbols = [c for c in pw if c in core.SYMBOLS]
        digits = [c for c in pw if c in string.digits]
        assert 12 <= len(pw) <= 18
        assert 8 <= len(letters) <= 10
        assert 2 <= len(symbols) <= 4
        assert 2 <= len(digits) <= 4
        assert len(letters) + len(symbols) + len(digits) == len(pw)
        assert any(c.islower() for c in pw)
        assert any(c.isupper() for c in pw)


@pytest.mark.parametrize("length", [8, 12, 20, 64])
def test_password_with_custom_length(length):
    pw = core.generate_password(length)
    assert len(pw) == length
    assert any(c.islower() for c in pw) and any(c.isupper() for c in pw)
    assert any(c in core.SYMBOLS for c in pw) and any(c.isdigit() for c in pw)


@pytest.mark.parametrize("length", [0, 7, 65])
def test_password_length_out_of_range(length):
    with pytest.raises(ValueError):
        core.generate_password(length)


def test_passwords_are_not_repeated():
    assert len({core.generate_password() for _ in range(200)}) == 200


# ---------------------------- password_strength ----------------------------
@pytest.mark.parametrize(
    "password, expected",
    [
        ("", 0),
        ("password", 0),
        ("aaaaaaaaaaaa", 0),
        ("abc", 0),
        ("abcdefgh", 1),
        ("Abcdefg1", 2),
        ("Tr0ub4dor&3", 3),
        ("Xk9#mPq2$vLw", 4),
    ],
)
def test_strength_scores(password, expected):
    assert core.password_strength(password)["score"] == expected


def test_strength_label_matches_score():
    result = core.password_strength("Xk9#mPq2$vLw")
    assert result == {"score": 4, "label": "Strong"}


def test_generated_passwords_are_strong():
    assert all(core.password_strength(core.generate_password())["score"] >= 3 for _ in range(200))


# ---------------------------- vault entries ----------------------------
def test_add_entry_returns_new_vault_and_keeps_original():
    original = {}
    updated = core.add_entry(original, "  Ebay ", " me@example.com ", "S3cret!")
    assert original == {}
    assert updated == {"Ebay": {"email": "me@example.com", "password": "S3cret!"}}


def test_add_entry_replaces_same_site_ignoring_case():
    vault = core.add_entry({}, "Ebay", "a@example.com", "old")
    vault = core.add_entry(vault, "ebay", "b@example.com", "new")
    assert list(vault) == ["ebay"]
    assert vault["ebay"] == {"email": "b@example.com", "password": "new"}


def test_add_entry_requires_website_and_password():
    with pytest.raises(ValueError, match="website"):
        core.add_entry({}, "   ", "a@example.com", "x")
    with pytest.raises(ValueError, match="password"):
        core.add_entry({}, "Ebay", "a@example.com", "")


def test_password_is_not_trimmed():
    vault = core.add_entry({}, "Site", "a@example.com", " spaced ")
    assert vault["Site"]["password"] == " spaced "


def test_find_entry_exact_and_case_insensitive():
    vault = core.add_entry({}, "Ebay", "a@example.com", "pw")
    assert core.find_entry(vault, "Ebay") == {"website": "Ebay", "email": "a@example.com", "password": "pw"}
    assert core.find_entry(vault, " EBAY ")["website"] == "Ebay"
    assert core.find_entry(vault, "Amazon") is None


def test_remove_entry():
    vault = core.add_entry({}, "Ebay", "a@example.com", "pw")
    assert core.remove_entry(vault, "ebay") == {}
    assert vault  # original untouched
    with pytest.raises(ValueError, match="No details for Amazon"):
        core.remove_entry(vault, "Amazon")


def test_list_websites_sorted_ignoring_case():
    vault = {}
    for site in ["zeta", "Alpha", "beta"]:
        vault = core.add_entry(vault, site, "e", "p")
    assert core.list_websites(vault) == ["Alpha", "beta", "zeta"]


# ---------------------------- importing ----------------------------
LEGACY = json.dumps({
    "Example": {"email": "you@example.com", "password": "Ex@mple1"},
    "Other": {"email": "you@example.com", "password": "Oth3r#pw"},
})


def test_parse_legacy_data_json():
    data = core.parse_vault_text(LEGACY)
    assert set(data) == {"Example", "Other"}


@pytest.mark.parametrize(
    "text",
    ["", "   ", "not json", "[]", '{"a": 1}', '{"a": {"email": "x"}}', '{"": {"email": "x", "password": "y"}}'],
)
def test_parse_rejects_bad_input(text):
    with pytest.raises(ValueError):
        core.parse_vault_text(text)


def test_merge_vaults_incoming_wins():
    existing = core.add_entry({}, "Example", "old@example.com", "old")
    merged = core.merge_vaults(existing, core.parse_vault_text(LEGACY))
    assert merged["Example"]["email"] == "you@example.com"
    assert set(merged) == {"Example", "Other"}


# ---------------------------- JSON bridge used by app.js ----------------------------
def test_bridge_round_trip():
    vault_json = core.add_entry_json("{}", "Ebay", "a@example.com", "pw")
    assert json.loads(core.find_entry_json(vault_json, "ebay"))["password"] == "pw"
    assert json.loads(core.list_websites_json(vault_json)) == ["Ebay"]
    assert json.loads(core.find_entry_json(vault_json, "nope")) is None
    assert json.loads(core.remove_entry_json(vault_json, "Ebay")) == {}


def test_bridge_import_reports_count():
    result = json.loads(core.import_json("{}", LEGACY))
    assert result["imported"] == 2
    assert set(result["vault"]) == {"Example", "Other"}


def test_bridge_strength():
    assert json.loads(core.strength_json("Xk9#mPq2$vLw")) == {"score": 4, "label": "Strong"}


def test_bridge_rejects_damaged_vault():
    with pytest.raises(ValueError):
        core.list_websites_json('{"a": 1}')
