"""URL Trust & Phishing Domain Analyzer for SocialShield-VN 2.0."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from .text_utils import extract_urls

OFFICIAL_DOMAINS = {
    # Banks
    "vietcombank.com.vn", "bidv.com.vn", "techcombank.com", "techcombank.com.vn",
    "mbbank.com.vn", "vietinbank.vn", "acb.com.vn", "vpbank.com.vn", "tpb.vn",
    "sacombank.com.vn", "agribank.com.vn", "vib.com.vn", "hdbank.com.vn", "shb.com.vn",
    # E-Wallets
    "momo.vn", "zalopay.vn", "vnpay.vn", "viettelmoney.vn",
    # Government & NCSC
    "dichvucong.gov.vn", "bocongan.gov.vn", "gdt.gov.vn", "csgt.vn",
    "canhbao.ncsc.gov.vn", "khonggianmang.vn", "baohiemxahoi.gov.vn", "sbv.gov.vn",
    # E-commerce & Delivery
    "shopee.vn", "lazada.vn", "tiki.vn", "ghn.vn", "giaohangtietkiem.vn",
    "viettelpost.com.vn", "vnpost.vn",
    # Major safe global domains
    "google.com", "google.com.vn", "facebook.com", "youtube.com", "zalo.me",
}

SUSPICIOUS_TLDS = {".top", ".xyz", ".vip", ".cc", ".click", ".site", ".online", ".club", ".icu", ".buzz", ".tk", ".ml"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "shorturl.at", "cutt.ly", "s.id", "rebrand.ly"}

BRAND_TOKENS = [
    "vcb", "vietcombank", "bidv", "techcombank", "tcb", "mbbank", "vietinbank", "acb", "vpbank",
    "momo", "zalopay", "vnpay", "viettel",
    "vneid", "dichvucong", "csgt", "phatnguoi", "thue", "hoanthue", "bhxh", "congan",
    "shopee", "lazada", "tiki", "tiktok", "ghn", "ghtk", "giaohang",
]

SENSITIVE_URL_KEYWORDS = [
    "verify", "login", "secure", "update", "confirm", "account", "unlock",
    "xacminh", "capnhat", "dangnhap", "nhanqu", "nhanqua", "mienphi", "khachhang", "apk", "download",
]


def _extract_host(raw_url: str) -> tuple[str, str, str]:
    normalized = raw_url if re.match(r"^https?://", raw_url, re.I) else f"http://{raw_url}"
    parsed = urlparse(normalized)
    scheme = (parsed.scheme or "http").lower()
    host = (parsed.hostname or "").lower().lstrip("www.")
    path = (parsed.path or "").lower()
    return scheme, host, path


def _is_official_host(host: str) -> bool:
    if not host:
        return False
    if host.endswith(".gov.vn"):
        return True
    for dom in OFFICIAL_DOMAINS:
        if host == dom or host.endswith("." + dom):
            return True
    return False


def analyze_url(raw_url: str) -> dict:
    """Analyze a single URL and return normalized risk score (0-100) + human-readable reasons."""
    scheme, host, path = _extract_host(raw_url)
    reasons: list[str] = []
    score = 0

    official = _is_official_host(host)
    if official:
        if scheme != "https" and raw_url.lower().startswith("http://"):
            score += 10
            reasons.append("Liên kết thuộc tên miền chính thức nhưng không dùng HTTPS")
        return {
            "url": raw_url,
            "domain": host,
            "is_official": True,
            "risk_score": score,
            "risk_level": "An toàn" if score <= 20 else "Rủi ro thấp",
            "reasons": reasons or ["Thuộc danh sách tên miền chính thức đã xác minh"],
        }

    # Unofficial domain checks
    if raw_url.lower().startswith("http://"):
        score += 18
        reasons.append("Không sử dụng giao thức mã hóa HTTPS")

    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        score += 35
        reasons.append("Sử dụng địa chỉ IP trực tiếp thay vì tên miền hợp lệ")

    if host in SHORTENERS:
        score += 24
        reasons.append("Sử dụng dịch vụ rút gọn liên kết, ẩn tên miền đích thực")

    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 22
            reasons.append(f"Tên miền sử dụng đuôi rủi ro cao ({tld})")
            break

    matched_brands = [b for b in BRAND_TOKENS if b in host]
    if matched_brands:
        score += 36
        reasons.append(f"Tên miền không chính thức nhưng chứa tên thương hiệu/cơ quan ({', '.join(matched_brands[:2])})")

    matched_kw = [k for k in SENSITIVE_URL_KEYWORDS if k in host or k in path]
    if matched_kw:
        score += 20
        reasons.append(f"URL chứa từ khóa nhạy cảm ({', '.join(matched_kw[:3])})")

    if path.endswith(".apk") or ".apk" in raw_url.lower():
        score += 35
        reasons.append("Liên kết trỏ tới tệp cài đặt Android (.apk) ngoài kho ứng dụng chính thức")

    if not reasons:
        score = 18
        reasons.append("Tên miền không nằm trong danh sách chính thức đã xác minh")

    score = min(100, score)
    if score >= 75:
        level = "Rất nguy hiểm"
    elif score >= 55:
        level = "Nguy hiểm"
    elif score >= 35:
        level = "Cần kiểm tra"
    else:
        level = "Rủi ro thấp"

    return {
        "url": raw_url,
        "domain": host,
        "is_official": False,
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
    }


def analyze_urls_in_text(text: str) -> dict:
    """Extract and analyze all URLs in text, returning list and max risk score (0-100)."""
    urls = extract_urls(text)
    results = [analyze_url(u) for u in urls]
    max_risk = max((r["risk_score"] for r in results), default=0)
    return {
        "url_count": len(results),
        "max_url_risk": max_risk,
        "urls": results,
    }
