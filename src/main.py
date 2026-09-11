"""
My Regex Data Extraction and secure Validation
ALU frontend Web development - Regex onboard Hackathon

Reads a raw data export and extracts eight types of
structured data using regular expressions, validating
each match before it is reported
"""

import json
import re
import sys
from pathlib import Path

# ----------------------------------------------
# Built fromm this file's location rather than from the current
# working dir, so the program behaves same whether it is run as
# "python src/main.py" from the project root or "python main.py"
# from inside src/. BASE_DIR is the project root: this file's
# parent is src/,   so one more .parent gets us up to the repo root
# ----------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = BASE_DIR / "input" / "raw-text.txt"
OUTPUT_FILE = BASE_DIR / "output" / "sample-output.json"


MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_LINE_LENGTH = 200


def load_raw_text(path):
    if not path.exists():
        print(f"[FATAL] Input file not found: {path}")
        sys.exit(1)

    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        print(
            f"[FATAL] Input file is {size} bytes, over the {MAX_FILE_BYTES} byte limit."
        )
        sys.exit(1)

    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


MAX_EMAIL_LENGTH = 254
MAX_LOCAL_LENGTH = 64

ALU_OFFICIAL = "alueducation.com"
ALU_ALUMNI = "alumni.alueducation.com"
ALU_SI = "si.alueducation.com"

EMAIL_CANDIDATE_RE = re.compile(r"[\w.%+\-@]+")

EMAIL_RE = re.compile(
    r"""
    ^
    [A-Za-z0-9]
    (?: [A-Za-z0-9_%+\-]
      | \. (?! [.@] )
    ){0,62}
    [A-Za-z0-9]
    @
    (?: [A-Za-z0-9] [A-Za-z0-9\-]{0,61} [A-Za-z0-9] \.)+
    [A-Za-z]{2,24}
    $
""",
    re.VERBOSE,
)


def classify_email(address):
    """Filters a valid address into one the three ALU domains described, or external."""
    domain = address.rsplit("@", 1)[1].lower()
    if domain == ALU_OFFICIAL:
        return "alu_official"
    if domain == ALU_ALUMNI:
        return "alu_alumni"
    if domain == ALU_SI:
        return "alu_si"
    return "external"


def validate_email(token):
    """This returns (category, None) if valid, or (None, reason if not.)"""
    if len(token) > MAX_EMAIL_LENGTH:
        return None, "exceeds 254 characters"
    if not token.isascii():
        return None, "contains non ASCII characters"
    if token.count("@") != 1:
        return None, "must contain just one @"
    if len(token.split("@")[0]) > MAX_LOCAL_LENGTH:
        return None, "local part exceeds 64 characters"
    if not EMAIL_RE.match(token):
        return None, "malformed local part or domain"
    return classify_email(token), None


def extract_emails(text):
    """Find all email-like tokens and sort them into valid categories or rejections."""
    valid = {
        "alu_official": set(),
        "alu_alumni": set(),
        "alu_si": set(),
        "external": set(),
    }
    rejected = []

    for match in EMAIL_CANDIDATE_RE.finditer(text):
        token = match.group(0).rstrip(".")
        if "@" not in token:
            continue
        category, reason = validate_email(token)
        if category:
            valid[category].add(token.lower())
        else:
            rejected.append({"value": token[:60], "reason": reason})

    return valid, rejected




CARD_CANDIDATE_RE = re.compile(r"(?<![\d.+])(?:\d[ -]?){12,18}\d(?![\d.])")


def luhn_is_valid(digits):
    """Check a card number against the Luhn algorithm."""
    total = 0
    for position, character in enumerate(reversed(digits)):
        value = int(character)
        if position % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def card_brand(digits):
    """Identify the issuer from the leading digits."""
    if digits.startswith("4"):
        return "Visa"
    if digits[:2] in {"34", "37"}:
        return "American Express"
    if digits[:2] in {"51", "52", "53", "54", "55"}:
        return "Mastercard"
    if digits.startswith("6011"):
        return "Discover"
    return "Unknown"


def mask_card(digits):
    """Hide everything but the last four digits."""
    return "*" * (len(digits) - 4) + digits[-4:]


def validate_card(token):
    """Return (digits, None) if valid, or (None, reason) if not."""
    digits = re.sub(r"[ -]", "", token)
    if not digits.isdigit():
        return None, "contains non-digit characters"
    if len(digits) < 13:
        return None, f"too short ({len(digits)} digits)"
    if len(digits) > 19:
        return None, f"too long ({len(digits)} digits)"
    if not luhn_is_valid(digits):
        return None, "fails Luhn checksum"
    return digits, None


def extract_cards(text):
    """Find card-like numbers, validate them, and mask every value on the way out."""
    valid = {}
    rejected = []

    for match in CARD_CANDIDATE_RE.finditer(text):
        token = match.group(0)
        digits, reason = validate_card(token)
        if digits:
            valid[digits] = card_brand(digits)
        else:
            stripped = re.sub(r"[ -]", "", token)
            shown = mask_card(stripped) if stripped.isdigit() else token[:20]
            rejected.append({"value": shown, "reason": reason})

    return valid, rejected

def main():
    raw_text = load_raw_text(INPUT_FILE)
    print(f"loaded {len(raw_text)} characters")

    emails, email_rejects = extract_emails(raw_text)
    for group, addresses in sorted(emails.items()):
        print(f"   {group}: {len(addresses)}")
    print(f"   rejected: {len(email_rejects)}")

    cards, card_rejects = extract_cards(raw_text)
    print(f"  cards valid: {len(cards)}")
    print(f"  cards rejected: {len(card_rejects)}")


if __name__ == "__main__":
    main()

