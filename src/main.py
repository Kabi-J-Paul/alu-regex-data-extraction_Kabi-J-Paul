"""
Regex Data Extraction & Validation
ALU Frontend Web Dev - Regex Hackathon

Reads raw-text.txt, extracts emails / cards / phones / times
using regex, validates everything, and writes sample-output.json.

Kabi Paul
"""

import json
import re
import sys
from datetime import datetime
from pathlib import Path

# paths are built from the files own location and
# not from the folder the command is run in.
# Thus this program runs from the project root
# or from inside src/.

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = BASE_DIR / "input" / "raw-text.txt"
OUTPUT_FILE = BASE_DIR / "output" / "sample-output.json"


def load_raw_text(path):
    """Just read the input file as normal text, handling the ways that fail."""
    if not path.exists():
        print(f"[FATAL] Input file not found: {path}")
        sys.exit(1)

    # size is checked even before the file is read
    # asking the file system how big someting is cost nothing
    # Reading it to memory and discovering it was two gigabytes
    # is too late.
    if path.stat().st_size > 5 * 1024 * 1024:
        print("[FATAL] Input file exceeds 5 MB limit.")
        sys.exit(1)

    # the encoding is stated outright because if not, python
    # guesses from the platfrom and the same bytes end up decoding
    # differently on different computers
    # errors = "replace" and not "strict": strict raises on the 1st invalid
    # bite, so anyone who can feed this program 1 malformed byte can stop it
    # from running. Replace keeps program running and leafces damage visible

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


# Email extraction ────────

# The 3 domains the assignment names. Everything else is external
# which includes alustudent.com, which is not
# one of the listed main listed 3. The lookup compares teh whole domain exactly
# instead of testing only how it ends.


ALU_DOMAINS = {
    "alueducation.com": "alu_official",
    "alumni.alueducation.com": "alu_alumni",
    "si.alueducation.com": "alu_si",
}

# 2 patterns instead on just one. THis loose patter Grabs anything
# that could be an address so it can then be judged; the strict one
# below then decided whether it is. This way malformed addresses can
# be reported and not just ignored.
# \w is unicode aware so that a spoofed cyrillic address is captured
# as a candidate and rejected by name instead on silently dissapearing
EMAIL_CANDIDATE_RE = re.compile(r"[\w.%+\-@]+")

EMAIL_RE = re.compile(
    r"""
    ^                               #must account for the whole token and not part of it
                          
                                                
                                                                                            
    [A-Za-z0-9]                     #local parts must start with a letter or digit,
                                    # rejecting .startsdot@ and %20attacker@
    (?: [A-Za-z0-9_%+\-]            #a local part character or dot not followed by         
      | \. (?! [.@] )               #another dot or @, which rejects things like
                                    #first..last@ and also addresses ending with a dot

    
    
    
    ){0,62}                          # caps the local part at 64 which is the official 
                                    #RCF limit. this stops the 223 character address.
    [A-Za-z0-9]                        #local part cannot end with a dot
    @
    (?: [A-Za-z0-9] [A-Za-z0-9\-]{0,61} [A-Za-z0-9] \.)+
                                        #the domain label starts and ends
                                        #alphanumeric while hypens are only 
                                        #inside and are followed by a dot.
                                        #empty labels are not possible, so
                                        #something like @.com failes.

    [A-Za-z]{2,24}                         #letters only, kills unusual header injection
    $                                      
    #all alternatives above take only one character, and each doamin
    #label ends with a dot(.), so no suspicious input is left for the
    #engine to backtrack through.


""",
    re.VERBOSE,
)


def validate_email(token):
    """Return (category, None) if valid or (None, reason) when not

    THe check runs the cheapest first. Lenght and ASCII are free
    and standard solarge or spoofed strings will not reach the regex engine;
    The Pattern match comes last because it is the most expensie test to run
    """

    if len(token) > 254:
        return None, "too long"
    if not token.isascii():
        return None, "non-ASCII"
    if token.count("@") != 1:
        return None, "must contain only 1 @"
    local = token.split("@")[0]
    if len(local) > 64:
        return None, "local part too long"
    if not EMAIL_RE.match(token):
        return None, "invalid format"
    domain = token.rsplit("@", 1)[1].lower()
    category = ALU_DOMAINS.get(domain, "external")
    return category, None


def extract_emails(text):
    """finds all email-like patterns and sort them into a category or rejection"""
    valid = {
        "alu_official": set(),
        "alu_alumni": set(),
        "alu_si": set(),
        "external": set(),
    }
    rejected = []
    for match in EMAIL_CANDIDATE_RE.finditer(text):
        # we use rstrip only and not just strip because a leading dot makes
        # an address invalid and stripping might rescue it, eg (.startsdot@alustudent.com)
        token = match.group(0).rstrip(".")
        if "@" not in token:
            continue
        category, reason = validate_email(token)
        if category:
            valid[category].add(token.lower())
        else:
            # truncated so hostile payloads will not flood the Console or JSON file.
            rejected.append({"value": token[:60], "reason": reason})
    return valid, rejected


# ── Credit card extraction ───
# 13 to 19 digits with optional single spaces or hyphens, covers all card
# formats in the input. The lookbehind is import because it excludes a starting
# digit, dot or plus. The plus is useful because without it, +234 803 123 4567
# will be read as a card and reported as one with a bad checksum.

CARD_CANDIDATE_RE = re.compile(r"(?<![\d.+])(?:\d[ -]?){12,18}\d(?![\d.])")


def luhn_is_valid(digits):
    """Checks card numbers against the Luhn checksum

    regex can't do arithmetic, which is why this is a function
    and not a pattern
    """

    total = 0
    for i, ch in enumerate(reversed(digits)):
        v = int(ch)
        if i % 2 == 1:
            v *= 2
            if v > 9:
                v -= 9
        total += v
    return total % 10 == 0


def card_brand(digits):
    """This helps Identify the issuer from the leading digits"""

    if digits.startswith("4"):
        return "Visa"
    if digits[:2] in ("34", "37"):
        return "Amex"
    if digits[:2] in ("51", "52", "53", "54", "55"):
        return "Mastercard"
    if digits.startswith("6011"):
        return "Discover"
    return "Unknown"


def mask_card(digits):
    """THis helps hide everyting except the last four digits, grouped
    like a printed card.

    Masking takes place the moment the card is found and not at output time,
    thus the raw number does not travel through the rest of the program exposed
    """

    hidden = "*" * (len(digits) - 4) + digits[-4:]
    # group from right in chunks of 4
    chunks, i = [], len(hidden)
    while i > 0:
        chunks.append(hidden[max(0, i - 4) : i])
        i -= 4
    return " ".join(reversed(chunks))


def validate_card(token):
    """Return (digits, None) if valid, or (None, reason) if not valid."""

    digits = re.sub(r"[ -]", "", token)
    if not digits.isdigit():
        return None, "This contains non-digit characters"
    if len(digits) < 13:
        return None, f"too short ({len(digits)} digits)"
    if len(digits) > 19:
        return None, f"too long ({len(digits)} digits)"
    if not luhn_is_valid(digits):
        return None, "Luhn checksum fail"
    return digits, None


def extract_cards(text):
    """Find card-like numbers, validate them, and mask all the values onthe way out"""
    valid = {}
    rejected = []
    for match in CARD_CANDIDATE_RE.finditer(text):
        token = match.group(0)
        digits, reason = validate_card(token)
        if digits:
            # the same card written with spaces, hyphens
            # or with nothing is counted only one time.
            valid[digits] = card_brand(digits)
        else:
            # rejected cards are also masked
            stripped = re.sub(r"[ -]", "", token)
            shown = mask_card(stripped) if stripped.isdigit() else token[:20]
            rejected.append({"value": shown, "reason": reason})
    return valid, rejected


# ── Phone extraction ─────────────────

# Only International format is accepted. The + keeps card number, dates
# and ID Numbers out of the phone results. The parenthesized area code is
# is optional and numbers are treated the same with or without parenthesis

PHONE_RE = re.compile(
    r"""
    (?<!\d)
    \+\d{1,3}                         # country code
    (?: [ -]? \( \d{1,4} \) )?        # optional area code
    (?: [ -]? \d{2,4} ){2,4}          # 2-4 digit groups
    (?!\d)
""",
    re.VERBOSE,
)


def validate_phone(token):
    """Strips away dashes or spaces so that +233 24 456 7890
    and +233-24-456-7890 collapse to the same entry.
    """
    digits = re.sub(r"\D", "", token)
    if len(digits) < 8:
        return None, f"too few digits ({len(digits)})"
    if len(digits) > 15:
        return None, f"too many digits ({len(digits)})"
    return "+" + digits, None


def extract_phones(text):
    """Finds the international Phone numbers and normalise them so the format collapses"""
    valid = {}
    rejected = []
    for match in PHONE_RE.finditer(text):
        token = match.group(0)
        normalised, reason = validate_phone(token)
        if normalised:
            # setdefault keeps the first spelling visible, so report
            # shows exactly what the user wrote.
            valid.setdefault(normalised, token)
        else:
            rejected.append({"value": token, "reason": reason})
    return valid, rejected


# ── Time extraction ─────────────────────────────────────

TIME_CANDIDATE_RE = re.compile(
    r"""
    (?<![\d:.])
    (?:
        \d{1,2} : \d{1,2} (?: : \d{1,2} )?  #hh:mm set optionally with seconds
        (?: \s? [AaPp][Mm] )?               # optional am/pm
      | \d{1,2} \s? [AaPp][Mm]              # bare hours with am/pm
    )
    (?![\d:])
""",
    re.VERBOSE,
)


def validate_time(token):
    """Return (kind, normalised, None) if valid, or (None, None, reason) when it's not

    The hour and minutes ranges are checked here and not inside the pattern.
    """

    text = token.strip()
    has_meridiem = bool(re.search(r"[AaPp][Mm]\s*$", text))
    clock = re.sub(r"\s*[AaPp][Mm]\s*$", "", text)
    parts = clock.split(":")

    if has_meridiem:
        hour, minute = int(parts[0]), int(parts[1]) if len(parts) > 1 else 0
        if len(parts) > 1 and len(parts[1]) != 2:
            return None, None, "minutes must be two digits"
        if not 1 <= hour <= 12:
            return None, None, f"hour {hour} out of range (12h)"
        if not 0 <= minute <= 59:
            return None, None, f"minute {minute} out of range"
        return "12-hour", text.upper(), None

    if len(parts) < 2:
        return None, None, "missing minutes"
    if len(parts[1]) != 2:
        return None, None, "minutes must be two digits"
    h, m = int(parts[0]), int(parts[1])
    if not 0 <= h <= 23:
        return None, None, f"hour {h} out of range (24h)"
    if not 0 <= m <= 59:
        return None, None, f"minute {m} out of range"
    if len(parts) == 3:
        s = int(parts[2])
        if not 0 <= s <= 59:
            return None, None, f"second {s} out of range"
    return "24-hour", text, None


def extract_times(text):
    """Finds clock times in either format and then range check them"""

    valid = {"12-hour": set(), "24-hour": set()}
    rejected = []
    for match in TIME_CANDIDATE_RE.finditer(text):
        token = match.group(0)
        kind, normalised, reason = validate_time(token)
        if kind:
            valid[kind].add(normalised)
        else:
            rejected.append({"value": token, "reason": reason})
    return valid, rejected


# ─ Threat scanning ───────────────────────

# Lines matching these patterns are flagged and reported instead of
# silently deleting. This is because deleting a line would also delete
# any legitimate data sitting in it.
# Also, a program the silently Deletes hostile input cannot demostrate
# clearly that it caught anything. The scanner only says what it saw
# and does not do any clean up.

THREAT_PATTERNS = [
    (
        "SQL injection",
        re.compile(
            r"""(?: \bUNION\s+SELECT\b | \bDROP\s+TABLE\b | \bDELETE\s+FROM\b
             | \bINSERT\s+INTO\b | \bSELECT\b .*? \bFROM\b
             | '\s*OR\s+'?1'?\s*=\s*'?1 | ;\s*-- )""",
            re.IGNORECASE | re.VERBOSE,
        ),
    ),
    (
        "XSS",
        re.compile(
            r"""(?: <\s*script\b | javascript\s*: | \bon(?:error|load|click|mouseover)\s*= )""",
            re.IGNORECASE | re.VERBOSE,
        ),
    ),
    ("Path traversal", re.compile(r"(?:\.\./|\.\.\\|%2e%2e|%252e)", re.IGNORECASE)),
    (
        "Template/JNDI injection",
        re.compile(r"(?:\{\{.{0,40}?\}\}|\$\{jndi:)", re.IGNORECASE),
    ),
    (
        "Header injection",
        re.compile(r"(?:%0a|%0d)\s*(?:bcc|cc|to|from)\s*:", re.IGNORECASE),
    ),
    ("Null byte", re.compile(r"%00|\x00")),
]


def scan_for_threats(text):
    """Flag lines matching known attacks patterns without changiing the text."""

    flagged = []
    for num, line in enumerate(text.splitlines(), start=1):
        for label, pattern in THREAT_PATTERNS:
            if pattern.search(line):
                flagged.append(
                    {"line": num, "threat": label, "preview": line.strip()[:60]}
                )

                # Each line is reported once, Under the first family it matches
                # this prevents counting same attack line twice
                break
    return flagged


# ── Output ─────────────────────────────────────────


def mask_email(address):
    """Hide the local part on the addresses, keeping the domain visible.

    Domain has to remain readable, otherwise we can't check that the ALU
    classification worked
    """
    local, domain = address.rsplit("@", 1)
    if len(local) <= 2:
        return "*" * len(local) + "@" + domain
    return local[0] + "*" * (len(local) - 2) + local[-1] + "@" + domain


def print_summary(results):
    """prints the Headline counts to be read first after a run"""

    e = results["emails"]
    t = results["times"]
    total_valid = (
        sum(len(v) for v in e.values())
        + len(results["cards"])
        + len(results["phones"])
        + sum(len(v) for v in t.values())
    )
    total_rejected = sum(
        len(results[k])
        for k in ("email_rejects", "card_rejects", "phone_rejects", "time_rejects")
    )

    print("-" * 68)
    print("  ALU REGEX EXTRACTOR")
    print("-" * 68)
    print(f"  Source : {INPUT_FILE.name}")
    print(f"  Run at : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 68)
    print(
        f"  Emails   official {len(e['alu_official'])}   alumni {len(e['alu_alumni'])}"
        f"   SI {len(e['alu_si'])}   external {len(e['external'])}"
    )
    print(f"  Cards    {len(results['cards'])} valid")
    print(f"  Phones   {len(results['phones'])} valid")
    print(
        f"  Times    {len(t['12-hour'])} twelve-hour, {len(t['24-hour'])} twenty-four-hour"
    )
    print("-" * 68)
    print(
        f"  {total_valid} values extracted, {total_rejected} rejected, "
        f"{len(results['threats'])} hostile lines flagged"
    )
    print("-" * 68)


def print_detail(results):
    """Print all extracted values, with the sensitive ones hidden."""

    print("\n=== EXTRACTED DATA (sensitive values masked) ===\n")

    for key, label in [
        ("alu_official", "ALU OFFICIAL"),
        ("alu_alumni", "ALU ALUMNI"),
        ("alu_si", "ALU SI"),
        ("external", "EXTERNAL"),
    ]:
        print(f"[EMAILS - {label}]")
        for addr in sorted(results["emails"][key]):
            print(f"   {mask_email(addr)}")
        if not results["emails"][key]:
            print("   (none found)")
        print()

    print("[CREDIT CARDS]")
    for digits, brand in sorted(results["cards"].items()):
        print(f"   {mask_card(digits):22} {brand}")

    print("\n[PHONE NUMBERS]")
    for normalised, original in sorted(results["phones"].items()):
        print(f"   {original}")

    print("\n[TIMES - 12 HOUR]")
    print("   " + ", ".join(sorted(results["times"]["12-hour"])))

    print("\n[TIMES - 24 HOUR]")
    print("   " + ", ".join(sorted(results["times"]["24-hour"])))

    # Rejections are printed with the reason for their rejection
    print("\n[REJECTED VALUES]")
    for group in ("email_rejects", "card_rejects", "phone_rejects", "time_rejects"):
        for item in results[group]:
            print(f"   {item['value'][:40]:42} {item['reason']}")

    print("\n[HOSTILE LINES FLAGGED]")
    for item in results["threats"]:
        print(f"   line {item['line']:>4}  {item['threat']:<26} {item['preview'][:40]}")
    print()


def write_json_output(results, path):
    """Writes the results to a  JSON file. No raw sensitive data is stored"""

    payload = {
        "metadata": {
            "source": INPUT_FILE.name,
            "processed_at": datetime.now().isoformat(timespec="seconds"),
            "note": "Card numbers and email local parts are masked.",
        },
        "emails": {
            cat: sorted(mask_email(a) for a in addrs)
            for cat, addrs in results["emails"].items()
        },
        "emails_rejected": results["email_rejects"],
        "credit_cards": {
            "count": len(results["cards"]),
            "masked": [
                {"number": mask_card(d), "brand": b}
                for d, b in sorted(results["cards"].items())
            ],
            "rejected": results["card_rejects"],
        },
        "phone_numbers": {
            "count": len(results["phones"]),
            "numbers": sorted(results["phones"].values()),
            "rejected": results["phone_rejects"],
        },
        "times": {
            "12_hour": sorted(results["times"]["12-hour"]),
            "24_hour": sorted(results["times"]["24-hour"]),
            "rejected": results["time_rejects"],
        },
        "security": {
            "hostile_lines_flagged": len(results["threats"]),
            "details": results["threats"],
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"  JSON written to {path}")


def main():
    """Run the pipeline: load, extract, validate, report"""

    raw_text = load_raw_text(INPUT_FILE)
    emails, email_rejects = extract_emails(raw_text)
    cards, card_rejects = extract_cards(raw_text)
    phones, phone_rejects = extract_phones(raw_text)
    times, time_rejects = extract_times(raw_text)
    threats = scan_for_threats(raw_text)

    # One structure containing everything, so each printer takes
    # just one argument and not nine.
    results = {
        "emails": emails,
        "email_rejects": email_rejects,
        "cards": cards,
        "card_rejects": card_rejects,
        "phones": phones,
        "phone_rejects": phone_rejects,
        "times": times,
        "time_rejects": time_rejects,
        "threats": threats,
    }

    print_summary(results)
    print_detail(results)
    write_json_output(results, OUTPUT_FILE)


if __name__ == "__main__":
    main()
