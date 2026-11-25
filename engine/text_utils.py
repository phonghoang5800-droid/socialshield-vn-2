"""Vietnamese text normalization and anti-obfuscation utilities for SocialShield-VN 2.0."""

from __future__ import annotations

import re
import unicodedata

# Common Vietnamese shorthand / obfuscation expansions used in SMS phishing
ABBREV_MAP = {
    "tk": "tai khoan",
    "nh": "ngan hang",
    "ck": "chuyen khoan",
    "xm": "xac minh",
    "vcb": "vietcombank",
    "tcb": "techcombank",
    "ctv": "cong tac vien",
    "csgt": "canh sat giao thong",
    "bhxh": "bao hiem xa hoi",
    "cccd": "can cuoc cong dan",
    "sdt": "so dien thoai",
    "lh": "lien he",
    "kh": "khach hang",
}

URL_PATTERN = re.compile(
    r"(?:(?:https?|hxxps?|ftp)://|www\.)[^\s<>\"']+|"
    r"\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.(?:com|vn|net|org|top|xyz|vip|info|cc|click|site|online|app|apk|io|me|co)(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)

PHONE_PATTERN = re.compile(r"(?:\+84|84|0)(?:3|5|7|8|9|2\d)\d{7,8}\b")
AMOUNT_PATTERN = re.compile(
    r"\b\d{1,3}(?:[.,]\d{3})+\s*(?:d|đ|vnd|vnđ)?\b|\b\d+\s*(?:trieu|tr|ty|k|nghin|ngan|vnd|vnđ|dong)\b",
    re.IGNORECASE,
)


def strip_accents(text: str) -> str:
    """Remove Vietnamese diacritics reliably (including đ/Đ)."""
    text = text.replace("đ", "d").replace("Đ", "D")
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in nfkd if not unicodedata.combining(ch))


def deobfuscate_spaced_letters(text: str) -> str:
    """Collapse spam-spaced words like 'T a i  k h o a n' -> 'Tai khoan'."""
    def _collapse(match: re.Match[str]) -> str:
        return re.sub(r"\s+", "", match.group(0))

    # Match sequences of >=3 single letters separated by single spaces
    collapsed = re.sub(r"\b(?:[A-Za-zÀ-ỹ]\s){2,}[A-Za-zÀ-ỹ]\b", _collapse, text)
    return collapsed


def normalize_vi(text: str, expand_abbrev: bool = False) -> str:
    """Normalize Vietnamese text into lowercase ASCII for robust lexical matching."""
    if not text:
        return ""
    cleaned = deobfuscate_spaced_letters(text)
    cleaned = cleaned.replace("hxxp://", "http://").replace("hxxps://", "https://")
    cleaned = strip_accents(cleaned).lower()
    cleaned = re.sub(r"[^a-z0-9:/._+\-\s]", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if expand_abbrev:
        tokens = [ABBREV_MAP.get(tok, tok) for tok in cleaned.split()]
        return " ".join(tokens)
    return cleaned


def tokenize_vi_dual(text: str) -> list[str]:
    """Return dual tokens (accented lowercase + accent-stripped + expanded abbrev) for BM25."""
    if not text:
        return []
    deob = deobfuscate_spaced_letters(text).lower()
    raw_tokens = re.findall(r"[a-zà-ỹ0-9]+", deob)
    ascii_norm = normalize_vi(text, expand_abbrev=True)
    ascii_tokens = re.findall(r"[a-z0-9]+", ascii_norm)
    # Preserve order while deduplicating exact duplicates per position loosely
    return raw_tokens + [t for t in ascii_tokens if t not in raw_tokens]


def extract_urls(text: str) -> list[str]:
    """Extract normalized URLs including hxxp obfuscated links."""
    if not text:
        return []
    raw = text.replace("hxxp://", "http://").replace("hxxps://", "https://")
    found = URL_PATTERN.findall(raw)
    cleaned: list[str] = []
    for u in found:
        u = u.rstrip(".,;:!?)\"'")
        if u and u not in cleaned:
            cleaned.append(u)
    return cleaned
