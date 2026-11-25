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

INVISIBLE_RE = re.compile(
    "[\u200b-\u200f\u2060-\u2064\ufeff\u00ad\u202a-\u202e\u2066-\u2069"
    "\ufe00-\ufe0f\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)
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


# ---------------------------------------------------------------- smuggling
# Invisible-character encodings. They must be decoded before strip_invisible().
TAG_RUN_RE = re.compile("[\U000e0000-\U000e007f]+")
VS_RUN_RE = re.compile("(.?)([\ufe00-\ufe0f\U000e0100-\U000e01ef]{2,})", re.S)
SNEAKY_RUN_RE = re.compile("[\u2062\u2064]{8,}")
BIDI_RE = re.compile("\u202e([^\u202c]*)\u202c?")


def decode_tags(text: str) -> str:
    """Unicode Tags block (U+E0000-U+E007F) mirrors ASCII: decode it inline."""
    return TAG_RUN_RE.sub(lambda m: "".join(chr(ord(c) - 0xE0000) for c in m.group()), text)


def _vs_byte(c: str) -> int:
    o = ord(c)
    return o - 0xFE00 if o <= 0xFE0F else o - 0xE0100 + 16


def decode_variation_selectors(text: str) -> str:
    """Bytes hidden as variation selectors after a base character (emoji smuggling)."""

    def dec(m: re.Match) -> str:
        data = bytes(_vs_byte(c) for c in m.group(2)).decode("utf-8", errors="ignore")
        return m.group(1) + data if data.isprintable() else m.group()

    return VS_RUN_RE.sub(dec, text)


def decode_sneaky_bits(text: str) -> str:
    """Bits as invisible math operators: U+2062 = 0, U+2064 = 1, 8 bits per byte."""

    def dec(m: re.Match) -> str:
        bits = "".join("1" if c == "\u2064" else "0" for c in m.group())
        if len(bits) % 8:
            return m.group()
        data = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)).decode("utf-8", errors="ignore")
        return data if data.isprintable() else m.group()

    return SNEAKY_RUN_RE.sub(dec, text)


def decode_bidi(text: str) -> str:
    """Text shown reversed by a right-to-left override: put it back in logical order."""
    return BIDI_RE.sub(lambda m: m.group(1)[::-1], text)


def decode_smuggled(text: str) -> str:
    for decoder in (decode_tags, decode_variation_selectors, decode_sneaky_bits, decode_bidi):
        text = decoder(text)
    return text


# ----------------------------------------------------------- visible ciphers
HEX_RE = re.compile(r"\b[0-9A-Fa-f]{2}(?: [0-9A-Fa-f]{2}){3,}\b")
MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.",
    "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..", "M": "--", "N": "-.",
    "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-", "U": "..-",
    "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--", "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....",
    "6": "-....", "7": "--...", "8": "---..", "9": "----.", "-": "-....-", ".": ".-.-.-",
}
MORSE_DECODE = {v: k for k, v in MORSE.items()}
MORSE_RE = re.compile(r"(?<![\w.-])[.-]{1,7}(?:(?: / | )[.-]{1,7}){2,}(?![\w.-])")
HOMOGLYPHS = {
    "a": "\u0430", "c": "\u0441", "e": "\u0435", "i": "\u0456", "o": "\u043e", "p": "\u0440",
    "x": "\u0445", "y": "\u0443", "A": "\u0410", "E": "\u0415", "O": "\u041e",
}
UNHOMOGLYPH = str.maketrans({v: k for k, v in HOMOGLYPHS.items()})


def atbash(text: str) -> str:
    out = []
    for c in text:
        if "a" <= c <= "z":
            out.append(chr(ord("z") - (ord(c) - ord("a"))))
        elif "A" <= c <= "Z":
            out.append(chr(ord("Z") - (ord(c) - ord("A"))))
        else:
            out.append(c)
    return "".join(out)


def _mostly_text(s: str) -> bool:
    return bool(s) and s.isprintable() and sum(c.isalpha() for c in s) > len(s) // 2


def decode_hex_runs(text: str) -> list[str]:
    out = []
    for run in HEX_RE.findall(text):
        try:
            decoded = bytes.fromhex(run.replace(" ", "")).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _mostly_text(decoded):
            out.append(decoded)
    return out


def decode_morse_runs(text: str) -> list[str]:
    out = []
    for run in MORSE_RE.findall(text):
        words = []
        for word in run.split(" / "):
            letters = [MORSE_DECODE.get(tok) for tok in word.split(" ")]
            if None in letters:
                break
            words.append("".join(letters))
        else:
            decoded = " ".join(words)
            if _mostly_text(decoded):
                out.append(decoded)
    return out


def _keep_addresses(text: str, fn) -> str:
    """Apply fn to every token except e-mail addresses and URLs (kept verbatim)."""
    return re.sub(r"\S+", lambda m: m.group() if "@" in m.group() or "://" in m.group() else fn(m.group()), text)


def views(text: str) -> list[str]:
    """Return the original text plus every decoded variant."""
    bases = [fold(text)]
    smuggled = decode_smuggled(text)
    if smuggled != text:
        bases.append(fold(smuggled))
    result: list[str] = []
    for base in bases:
        result.append(base)
        result.extend(decode_base64_blobs(base))
        result.extend(decode_hex_runs(base))
        result.extend(decode_morse_runs(base))
        if "rot13" in base.lower():
            result.append(codecs.decode(base, "rot13"))
        if "atbash" in base.lower():
            result.append(_keep_addresses(base, atbash))
        if re.search(r"\d[a-z]|[a-z]\d", base, re.I):
            result.append(_keep_addresses(base, lambda w: w.translate(LEET)))
        unglyphed = base.translate(UNHOMOGLYPH)
        if unglyphed != base:
            result.append(unglyphed)
    return list(dict.fromkeys(result))


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
