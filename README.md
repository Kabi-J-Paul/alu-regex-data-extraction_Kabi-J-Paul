# alu-regex-data-extraction_Kabi-J-Paul

A regex-based data extractor for raw text from an external API.
Pulls structured data, validates it, and handles hostile input without crashing.

Uses Python

---

## Overview

Reads `input/raw-text.txt` and extracts four data types:

**Email addresses** — Classifies by ALU domain (`alueducation.com`, `alumni.alueducation.com`, `si.alueducation.com`) or marks as external. Malformed addresses are rejected with the reason for their rejection.

**Credit card numbers** — Extracts, verifies with Luhn checksum, and masks immediately and not later. Only last 4 digits are Stored; raw values do not pass through the programm. 

**Phone numbers** — International format with `+` country code. Different representations of the same number are still seen as one.

**Times** — Both 12-hour (`9:15 AM`) and 24-hour (`14:33`) formats, range-checked and deduplicated.

---

## ALU email domains

Three domains are recognised as official according to instructions given in the assignment:

- `@alueducation.com`
- `@alumni.alueducation.com`
- `@si.alueducation.com`

Everything else is external — including `@alustudent.com`, which looks like an ALU domain but is not one of the three the assignment names.

The Domain comparison is exact, not suffix-based. An "ends with" check would file `@alumni.alueducation.com` as official (since it ends with `alueducation.com`) and would accept `payments@alueducation.com.secure-billing.ru`, which is external.

Failed addresses are reported with a reason: leading dot, consecutive dots, missing TLD, multiple `@` signs, oversized local part, or non-ASCII characters. All this makes reason for rejected input very clear and Precise.

---

## Security

Hostile lines are flagged and reported, never deleted.

Deleting them would also delete legitimate data on the same line.For example, The spam ticket in the input carries a real phone number and amount alongside its injection payload. A program that silently drops hostile input can't show that it caught anything.

The scanner reports each flagged line by number and attack type: SQL injection, XSS, path traversal, template/JNDI injection, header injection, and null bytes. The text passes through untouched — every value is validated individually, so a Hostile line can't sneak anything past the extractors.

Other defensive choices:

- File size is checked before reading
- Encoding is explicit (`errors="replace"`) so one bad byte cannot crash the program
- Length caps run before pattern matching, so oversized strings do not reach the regex engine
- No unbounded quantifiers or ambiguous inner groups — long hostile input can't cause catastrophic backtracking
- Nothing from input is executed, evaluated, or used to build paths or queries

Credit card raw values are never stored. They're masked at match time, and rejected cards are masked too. Email local parts Are masked on output, with domains visible so classification can be verified.

---

## Where regex stops

Regex matches patterns. It is not able to do do arithmetic, compare values, or spot identical-looking characters. So the regex decides shape and Python decides validity.

`1234 5678 9012 3456` matches any card pattern but fails Luhn instantly. `25:61` has the shape of a time, and integer comparison rejects it. `аdmin@alueducation.com` starts with a Cyrillic "а" that looks identical to Latin "a" — no regex catches that, but a single `.isascii()` call does.

---

## Project structure

```
alu-regex-data-extraction_Kabi-J-Paul/
├── input/
│   └── raw-text.txt           raw export from a simulated ALU community portal
├── src/
│   └── main.py                all extraction and validation logic
├── output/
│   └── sample-output.json    what the program produces on the sample input
└── README.md                 explains the program and how to run it
```

---

## Running it

```bash
python src/main.py
```

Runs from the project root or from inside `src/` — paths are built from the script's own location, not the working directory.

What happens:

1. Loads `input/raw-text.txt` (size checked first)
2. Extracts and validates all four data types
3. Scans for hostile content and flags it
4. Prints a console summary with masked sensitive values
5. Writes structured JSON to `output/sample-output.json`

---

## Sample output

With the included input file:

```
  Emails   official 7   alumni 2   SI 1   external 9
  Cards    5 valid
  Phones   10 valid
  Times    11 twelve-hour, 22 twenty-four-hour

  67 values extracted, 18 rejected, 10 hostile lines flagged
```

The 18 rejections: 11 malformed emails, 4 card numbers, 3 impossible times. Each carries its reason:

```
  аdmin@alueducation.com              non-ASCII
  first..last@alustudent.com          invalid format
  **** **** **** 9010                 Luhn checksum fail
  25:61                               hour 25 out of range (24h)
```

10 flagged lines from a spam ticket and an unvalidated contact form: SQL injection, script tags, HTML event handler, JNDI lookup, path traversal with null byte, and CRLF header injection.

Full output in `output/sample-output.json`.

---

## Input file

`input/raw-text.txt` simulates a raw batch export from an ALU community portal:

- Support tickets with user-submitted data in inconsistent formats
- Staff directory with international phone numbers (Rwanda, Kenya, Nigeria, Senegal, Ghana)
- Alumni forum posts with timestamps, contact details, event event times
- Spam ticket carrying SQL injection, XSS, and path traversal payloads
- Unvalidated contact form with more injection attempts
- Newsletter bounce report with malformed addresses and SMTP codes
- Payment processor log with card numbers in Several separator formats
- Finance reconciliation with amounts in four currencies

The payment log is internally consistent — the two transactions marked as declined for checksum failure are exactly the two numbers that fail Luhn, so the data and validation logic agree.

Deliberate traps included: Cyrillic spoof, domain suffix attack, a 223-character address, several malformed emails, and impossible times.

---

## Limitations

The phone pattern requires international format. A bare local number like `0788 123 456` won't match — this trades coverage to keep card numbers and dates out of phone results.

Luhn confirms a number is internally consistent. It doesn't mean the card exists or belongs to anyone.

The homoglyph check rejects any address with non-ASCII characters. A legitimate internationalized address would be refused, which is correct for this program but not for a general-purpose mail system.

---

## AI use

AI use was permitted for this assignment only for the raw input.
