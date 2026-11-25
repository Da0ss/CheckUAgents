"""Text normalization used by the defense scanner and the reference agent.

Attackers hide instructions with encodings and invisible characters. This module
produces "views" of a text: each view undoes one obfuscation technique.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

INVISIBLE_RE = re.compile("[​-‏⁠-⁤﻿­]")
B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def strip_invisible(text: str) -> str:
    return INVISIBLE_RE.sub("", text)


def fold(text: str) -> str:
    """NFKC fold (fullwidth, some homoglyphs) and remove invisible characters."""
    return strip_invisible(unicodedata.normalize("NFKC", text))


def decode_base64_blobs(text: str) -> list[str]:
    out = []
    for blob in B64_RE.findall(text):
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded.isprintable() and sum(c.isalpha() for c in decoded) > len(decoded) // 2:
            out.append(decoded)
    return out


def views(text: str) -> list[str]:
    """Return the original text plus every decoded variant."""
    base = fold(text)
    result = [base]
    result.extend(decode_base64_blobs(base))
    if "rot13" in base.lower():
        result.append(codecs.decode(base, "rot13"))
    if re.search(r"\d[a-z]|[a-z]\d", base, re.I):
        result.append(re.sub(r"\S+", lambda m: m.group() if "@" in m.group() else m.group().translate(LEET), base))
    return result


def typo_match(word: str, vocabulary: set[str]) -> str | None:
    """Typoglycemia: same first and last letter, same multiset of letters."""
    w = word.lower()
    if len(w) < 4:
        return None
    for v in vocabulary:
        if len(v) == len(w) and v[0] == w[0] and v[-1] == w[-1] and sorted(v) == sorted(w):
            return v
    return None


def unscramble(text: str, vocabulary: set[str]) -> str:
    def fix(m: re.Match) -> str:
        return typo_match(m.group(), vocabulary) or m.group()

    return re.sub(r"[A-Za-z]+", fix, text)
