"""SocialShield-VN v1 Core Engine (X-HRS-MTSD+ faithful implementation).

Implements:
- 22 domain-specific Vietnamese fraud rule features (Table 2 of SocialShield-VN report)
- Hybrid Word TF-IDF + Character TF-IDF + Rule Features -> One-vs-Rest Logistic Regression
- Calibrated 0-100 risk score (Equation 1) + Local XAI explanation signals
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.preprocessing import StandardScaler

from .text_utils import AMOUNT_PATTERN, PHONE_PATTERN, normalize_vi
from .url_analyzer import analyze_urls_in_text

BRAND_GROUPS: dict[str, list[str]] = {
    "bank_impersonation": [
        "vietcombank", "vcb", "bidv", "techcombank", "tcb", "mbbank", "mb bank",
        "vietinbank", "acb", "vpbank", "tpbank", "sacombank", "agribank", "ngan hang", "internet banking",
    ],
    "gov_impersonation": [
        "vneid", "cong an", "csgt", "canh sat giao thong", "phat nguoi", "tong cuc thue",
        "hoan thue", "bhxh", "bao hiem xa hoi", "dich vu cong", "toa an", "vien kiem sat", "vssid",
    ],
    "ewallet_impersonation": [
        "momo", "zalopay", "vnpay", "viettel money", "vi dien tu", "vi tra sau",
    ],
    "delivery_impersonation": [
        "shipper", "ghn", "ghtk", "viettel post", "vietnam post", "buu cuc", "giao hang", "phi luu kho", "don cod",
    ],
    "ecommerce_impersonation": [
        "shopee", "lazada", "tiki", "tiktok shop", "diem thuong", "voucher sap het han",
    ],
    "loan_investment_scam": [
        "duyet vay", "phe duyet vay", "goi vay", "giai ngan", "phi ho so", "dau tu", "loi nhuan", "chung khoan", "crypto",
    ],
    "job_task_scam": [
        "tuyen ctv", "cong tac vien", "viec lam online", "nhiem vu", "hoa hong", "kich hoat nhiem vu", "viec nhe luong cao",
    ],
}

SCAM_CATEGORY_LABELS = {
    "bank_impersonation": "Mạo danh ngân hàng",
    "gov_impersonation": "Mạo danh cơ quan nhà nước / VNeID / CSGT",
    "ewallet_impersonation": "Mạo danh ví điện tử (MoMo / ZaloPay / VNPAY)",
    "delivery_impersonation": "Mạo danh giao hàng / bưu cục",
    "ecommerce_impersonation": "Mạo danh sàn thương mại điện tử",
    "loan_investment_scam": "Lừa đảo vay tiền / đầu tư tài chính",
    "job_task_scam": "Lừa đảo tuyển CTV / nhiệm vụ online",
    "unknown_scam": "Lừa đảo trực tuyến (chưa rõ nhóm)",
    "safe": "Không phát hiện dấu hiệu lừa đảo",
    "promo": "Tin nhắn quảng cáo / khuyến mãi",
}

OTP_KEYWORDS = ["otp", "ma xac thuc", "ma xac nhan", "verification code"]
MONEY_KEYWORDS = ["chuyen tien", "chuyen khoan", "thanh toan phi", "phi luu kho", "phi ho so", "nop phat", "nap tien", "dong truoc", "phi bao hiem"]
URGENCY_KEYWORDS = ["24h", "24 gio", "khan cap", "ngay lap tuc", "cap nhat ngay", "bi khoa", "tam ngung", "sap het han", "gap", "trong hom nay"]
VERIFY_KEYWORDS = ["xac minh", "cap nhat", "dinh danh", "sinh trac hoc", "xac nhan thong tin", "dong bo", "mo khoa"]
INSTALL_KEYWORDS = ["tai app", "cai app", "cai dat", "tai ung dung", ".apk", "tro nang", "accessibility"]
SENSITIVE_KEYWORDS = ["mat khau", "password", "cccd", "so the", "tai khoan", "thong tin ca nhan", "ma pin"]
SAFE_OTP_GUARD = ["khong chia se", "khong cung cap", "khong bao gio yeu cau", "tuyet doi khong"]


class RuleFeatureExtractor:
    """Extracts 22 structured binary & continuous fraud signals for Vietnamese SMS."""

    def extract(self, text: str) -> tuple[np.ndarray, dict[str, Any], list[str]]:
        norm = normalize_vi(text, expand_abbrev=True)
        url_info = analyze_urls_in_text(text)
        phones = PHONE_PATTERN.findall(text)
        amounts = AMOUNT_PATTERN.findall(norm)

        has_url = int(url_info["url_count"] > 0)
        url_count = url_info["url_count"]
        has_unofficial_url = int(any(not u["is_official"] for u in url_info["urls"]))
        has_phone = int(len(phones) > 0)
        phone_count = len(phones)
        has_otp = int(any(k in norm for k in OTP_KEYWORDS))
        has_safe_otp_guard = int(any(k in norm for k in SAFE_OTP_GUARD))
        has_amount = int(len(amounts) > 0)
        has_money_request = int(any(k in norm for k in MONEY_KEYWORDS))
        has_urgency = int(any(k in norm for k in URGENCY_KEYWORDS))
        has_verify = int(any(k in norm for k in VERIFY_KEYWORDS))
        has_install_request = int(any(k in norm for k in INSTALL_KEYWORDS))
        has_sensitive_info = int(any(k in norm for k in SENSITIVE_KEYWORDS))

        # Brand / category matching across 7 Vietnamese scam domains
        matched_categories: list[str] = []
        cat_flags: list[int] = []
        for cat, kws in BRAND_GROUPS.items():
            hit = int(any(kw in norm for kw in kws))
            cat_flags.append(hit)
            if hit:
                matched_categories.append(cat)

        has_brand = int(len(matched_categories) > 0)
        top_category = matched_categories[0] if matched_categories else None

        # Detect spacing obfuscation like "T a i  k h o a n"
        has_obfuscation = int(bool(re.search(r"\b(?:[A-Za-zÀ-ỹ]\s){2,}[A-Za-zÀ-ỹ]\b", text)) or ("hxxp" in text.lower()))

        words = norm.split()
        text_len = min(len(text), 600) / 600.0
        word_count = min(len(words), 120) / 120.0
        digit_count = min(sum(ch.isdigit() for ch in text), 40) / 40.0

        # 22 numerical features
        vec = np.array(
            [
                has_url, url_count, has_unofficial_url, has_phone, phone_count,
                has_otp, has_safe_otp_guard, has_amount, has_money_request, has_urgency,
                has_verify, has_install_request, has_sensitive_info, has_brand, has_obfuscation,
                text_len, word_count, digit_count,
            ]
            + cat_flags[:4],
            dtype=np.float32,
        )

        # Human-readable rule explanations
        reasons: list[str] = []
        if has_unofficial_url:
            reasons.append("Chứa đường link không nằm trong danh sách tên miền chính thức")
        if has_install_request:
            reasons.append("Có yêu cầu tải hoặc cài đặt ứng dụng lạ / tệp .APK")
        if has_otp and not has_safe_otp_guard:
            reasons.append("Đề cập đến mã OTP / xác thực giao dịch theo hướng rủi ro")
        if has_money_request:
            reasons.append("Có yêu cầu chuyển tiền, đóng phí hồ sơ, phí lưu kho hoặc nộp tiền")
        if has_verify:
            reasons.append("Có yêu cầu xác minh, cập nhật thông tin hoặc định danh tài khoản")
        if has_urgency:
            reasons.append("Sử dụng ngôn ngữ khẩn cấp, đe dọa khóa tài khoản hoặc tạo áp lực thời gian")
        if has_brand and (has_unofficial_url or has_money_request or has_install_request or has_urgency):
            reasons.append(f"Có dấu hiệu mạo danh tổ chức/nhóm: {SCAM_CATEGORY_LABELS.get(top_category or 'unknown_scam')}")
        if has_obfuscation:
            reasons.append("Phát hiện kỹ thuật viết né bộ lọc (giãn chữ hoặc hxxp)")
        if has_safe_otp_guard and not has_unofficial_url and not has_install_request and not has_money_request:
            reasons.append("Có lời nhắc bảo mật chính thống (không chia sẻ OTP) và không kèm link giả mạo")

        signals = {
            "has_url": bool(has_url),
            "has_unofficial_url": bool(has_unofficial_url),
            "url_info": url_info,
            "has_phone": bool(has_phone),
            "has_otp": bool(has_otp),
            "has_safe_otp_guard": bool(has_safe_otp_guard),
            "has_money_request": bool(has_money_request),
            "has_urgency": bool(has_urgency),
            "has_verify": bool(has_verify),
            "has_install_request": bool(has_install_request),
            "has_sensitive_info": bool(has_sensitive_info),
            "has_brand_impersonation": bool(has_brand),
            "has_obfuscation": bool(has_obfuscation),
            "matched_categories": matched_categories,
            "top_category": top_category,
        }
        return vec, signals, reasons


class XHRSMTSDv1:
    """Faithful SocialShield-VN v1 hybrid model (Word TF-IDF + Char TF-IDF + 22 Rules -> OvR LR)."""

    CLASSES = ["normal", "promo", "scam"]

    def __init__(self, train_data_path: str | Path) -> None:
        self.train_data_path = Path(train_data_path)
        self.rule_extractor = RuleFeatureExtractor()
        self.word_vec = TfidfVectorizer(ngram_range=(1, 2), max_features=3000, sublinear_tf=True)
        self.char_vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=3000, sublinear_tf=True)
        self.scaler = StandardScaler()
        self.clf = OneVsRestClassifier(LogisticRegression(max_iter=1000, C=1.8))
        self._fit()

    def _fit(self) -> None:
        rows = json.loads(self.train_data_path.read_text(encoding="utf-8"))
        texts = [r["text"] for r in rows]
        labels = [r["label"] for r in rows]
        norms = [normalize_vi(t, expand_abbrev=True) for t in texts]

        xw = self.word_vec.fit_transform(norms).toarray()
        xc = self.char_vec.fit_transform(norms).toarray()
        xr = np.vstack([self.rule_extractor.extract(t)[0] for t in texts])
        xr_s = self.scaler.fit_transform(xr)

        X = np.hstack([xw, xc, xr_s * 0.45])
        self.clf.fit(X, labels)
        self._classes = list(self.clf.classes_)

    def predict(self, text: str) -> dict[str, Any]:
        norm = normalize_vi(text, expand_abbrev=True)
        xw = self.word_vec.transform([norm]).toarray()
        xc = self.char_vec.transform([norm]).toarray()
        r_vec, signals, reasons = self.rule_extractor.extract(text)
        xr_s = self.scaler.transform(r_vec.reshape(1, -1))
        X = np.hstack([xw, xc, xr_s * 0.45])

        probs = self.clf.predict_proba(X)[0]
        prob_map = {cls: float(p) for cls, p in zip(self._classes, probs)}
        p_scam = prob_map.get("scam", 0.0)
        p_promo = prob_map.get("promo", 0.0)

        # Equation 1 (calibrated 0-100 risk score combining ML probability + URL + rule signals)
        url_risk_norm = signals["url_info"]["max_url_risk"] / 100.0
        otp_risk = 1 if (signals["has_otp"] and not signals["has_safe_otp_guard"]) else 0
        raw_score = (
            52.0 * p_scam
            + 20.0 * url_risk_norm
            + 12.0 * otp_risk
            + 14.0 * int(signals["has_money_request"])
            + 16.0 * int(signals["has_install_request"])
            + 10.0 * int(signals["has_brand_impersonation"] and (signals["has_unofficial_url"] or signals["has_urgency"] or signals["has_money_request"]))
            + 8.0 * int(signals["has_urgency"])
            + 6.0 * int(signals["has_verify"])
            + 6.0 * int(signals["has_obfuscation"])
        )

        # Guard against false positives on legitimate official OTP alerts
        if signals["has_safe_otp_guard"] and not signals["has_unofficial_url"] and not signals["has_install_request"] and not signals["has_money_request"]:
            raw_score = min(raw_score, 18.0)

        risk_score = int(round(max(0.0, min(100.0, raw_score))))
        if risk_score >= 81:
            risk_level = "Rất nguy hiểm"
        elif risk_score >= 61:
            risk_level = "Nguy hiểm"
        elif risk_score >= 41:
            risk_level = "Cần kiểm tra"
        elif risk_score >= 21:
            risk_level = "Rủi ro thấp"
        else:
            risk_level = "An toàn"

        if risk_score >= 45:
            predicted_label = "scam"
            scam_category = signals["top_category"] or "unknown_scam"
        elif p_promo >= 0.45 and risk_score < 35:
            predicted_label = "promo"
            scam_category = "promo"
        else:
            predicted_label = "normal"
            scam_category = "safe"

        return {
            "predicted_label": predicted_label,
            "scam_probability": round(p_scam, 4),
            "probabilities": {k: round(v, 4) for k, v in prob_map.items()},
            "risk_score": risk_score,
            "risk_level": risk_level,
            "scam_category": scam_category,
            "scam_category_label": SCAM_CATEGORY_LABELS.get(scam_category, "Chưa phân loại"),
            "reasons": reasons or ["Chưa phát hiện dấu hiệu lừa đảo rõ ràng"],
            "signals": signals,
        }
