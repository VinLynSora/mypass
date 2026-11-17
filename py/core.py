"""MyPass core logic.

Plain Python with no browser dependency, so the same file runs in CPython
(for the tests) and in Pyodide (inside the web page).

The vault is a dict in the same format the original desktop version saved in
data.json:

    {"website": {"email": "...", "password": "..."}}

Functions that change the vault never modify the dict they receive; they
return a new one. The ``*_json`` functions at the bottom are the thin bridge
that app.js calls: they take and return JSON strings, which is the simplest
safe way to cross the JavaScript <-> Python boundary.
"""
from __future__ import annotations

import json
import secrets
import string

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!#$%&()*+"
_ALL_LETTERS = LOWERCASE + UPPERCASE

MIN_LENGTH = 8
MAX_LENGTH = 64

STRENGTH_LABELS = ("Very weak", "Weak", "Fair", "Good", "Strong")

_COMMON_PASSWORDS = {
    "password", "password1", "passw0rd", "123456", "12345678", "123456789",
    "qwerty", "qwerty123", "abc123", "letmein", "iloveyou", "admin",
    "welcome", "monkey", "dragon", "senha", "senha123", "mudar123",
}


# ---------------------------- PASSWORD GENERATOR ------------------------------- #
def generate_password(length: int | None = None) -> str:
    """Return a random password using the system's secure random source.

    Without ``length`` it follows the original course project: 8-10 letters
    (at least one lowercase and one uppercase), 2-4 symbols and 2-4 digits.
    With ``length`` it builds a password of exactly that size.
    """
    rng = secrets.SystemRandom()

    if length is None:
        n_letters = rng.randint(8, 10)
        n_symbols = rng.randint(2, 4)
        n_digits = rng.randint(2, 4)
    else:
        if not MIN_LENGTH <= length <= MAX_LENGTH:
            raise ValueError(f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}.")
        n_symbols = max(2, length // 6)
        n_digits = max(2, length // 6)
        n_letters = length - n_symbols - n_digits

    chars = [secrets.choice(LOWERCASE), secrets.choice(UPPERCASE)]
    chars += [secrets.choice(_ALL_LETTERS) for _ in range(n_letters - 2)]
    chars += [secrets.choice(SYMBOLS) for _ in range(n_symbols)]
    chars += [secrets.choice(DIGITS) for _ in range(n_digits)]
    rng.shuffle(chars)
    return "".join(chars)


# ---------------------------- PASSWORD STRENGTH ------------------------------- #
def password_strength(password: str) -> dict:
    """Score a password from 0 (very weak) to 4 (strong).

    This is a simple educational heuristic (length, variety of characters,
    repeated characters and a short list of very common passwords). It is not
    a replacement for a real estimator such as zxcvbn.
    """
    length = len(password)
    if length == 0:
        return {"score": 0, "label": STRENGTH_LABELS[0]}

    if password.lower() in _COMMON_PASSWORDS or len(set(password)) == 1:
        return {"score": 0, "label": STRENGTH_LABELS[0]}

    classes = sum([
        any(c in LOWERCASE for c in password),
        any(c in UPPERCASE for c in password),
        any(c in DIGITS for c in password),
        any(c not in _ALL_LETTERS + DIGITS for c in password),
    ])

    points = 0
    points += 1 if length >= 8 else 0
    points += 1 if length >= 12 else 0
    points += 1 if length >= 16 else 0
    points += 1 if classes >= 3 else 0
    points += 1 if classes == 4 else 0
    if len(set(password)) < length / 2:
        points -= 1

    score = max(0, min(4, points))
    return {"score": score, "label": STRENGTH_LABELS[score]}


# ---------------------------- VAULT (ENTRIES) ------------------------------- #
def validate_vault(data) -> dict:
    """Check that ``data`` has the vault shape and return it, or raise ValueError."""
    if not isinstance(data, dict):
        raise ValueError("The data must be an object like {\"website\": {\"email\": ..., \"password\": ...}}.")
    for website, entry in data.items():
        if not isinstance(website, str) or not website.strip():
            raise ValueError("Every entry needs a website name.")
        if not isinstance(entry, dict):
            raise ValueError(f"The entry for {website!r} is not valid.")
        if not isinstance(entry.get("email"), str) or not isinstance(entry.get("password"), str):
            raise ValueError(f"The entry for {website!r} needs text fields 'email' and 'password'.")
    return data


def _find_key(vault: dict, website: str) -> str | None:
    """Exact match first, then a case-insensitive one."""
    if website in vault:
        return website
    wanted = website.strip().lower()
    for key in vault:
        if key.strip().lower() == wanted:
            return key
    return None


def add_entry(vault: dict, website: str, email: str, password: str) -> dict:
    """Return a new vault with the entry added (or replaced if the site exists)."""
    website = (website or "").strip()
    if not website:
        raise ValueError("Please type the website.")
    if not password:
        raise ValueError("Please type or generate a password.")

    updated = dict(vault)
    existing = _find_key(vault, website)
    if existing is not None:
        updated.pop(existing)
    updated[website] = {"email": (email or "").strip(), "password": password}
    return updated


def find_entry(vault: dict, website: str) -> dict | None:
    """Return {"website", "email", "password"} for the site, or None."""
    key = _find_key(vault, (website or "").strip())
    if key is None:
        return None
    return {"website": key, **vault[key]}


def remove_entry(vault: dict, website: str) -> dict:
    """Return a new vault without the site; raise ValueError if it isn't there."""
    key = _find_key(vault, (website or "").strip())
    if key is None:
        raise ValueError(f"No details for {website} exist.")
    updated = dict(vault)
    del updated[key]
    return updated


def list_websites(vault: dict) -> list[str]:
    """Website names in alphabetical order (ignoring case)."""
    return sorted(vault, key=str.lower)


def merge_vaults(existing: dict, incoming: dict) -> dict:
    """Return a new vault with ``incoming`` merged in; incoming wins on conflicts."""
    merged = dict(existing)
    for website, entry in incoming.items():
        merged = add_entry(merged, website, entry["email"], entry["password"])
    return merged


def parse_vault_text(text: str) -> dict:
    """Parse JSON text (for example the old data.json) into a valid vault."""
    if not text or not text.strip():
        raise ValueError("The file is empty.")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        raise ValueError("The file is not valid JSON.") from None
    return validate_vault(data)


# ---------------------------- BRIDGE FOR app.js ------------------------------- #
def _load(vault_json: str) -> dict:
    return validate_vault(json.loads(vault_json)) if vault_json else {}


def _dump(value) -> str:
    return json.dumps(value, ensure_ascii=False)


def add_entry_json(vault_json: str, website: str, email: str, password: str) -> str:
    return _dump(add_entry(_load(vault_json), website, email, password))


def find_entry_json(vault_json: str, website: str) -> str:
    return _dump(find_entry(_load(vault_json), website))


def remove_entry_json(vault_json: str, website: str) -> str:
    return _dump(remove_entry(_load(vault_json), website))


def list_websites_json(vault_json: str) -> str:
    return _dump(list_websites(_load(vault_json)))


def import_json(vault_json: str, text: str) -> str:
    """Merge the entries in ``text`` into the vault.

    Returns JSON like {"vault": {...}, "imported": 3}.
    """
    incoming = parse_vault_text(text)
    merged = merge_vaults(_load(vault_json), incoming)
    return _dump({"vault": merged, "imported": len(incoming)})


def strength_json(password: str) -> str:
    return _dump(password_strength(password))
