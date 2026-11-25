"""Automated pytest suite for SocialShield-VN 2.0 (Rules, URLs, Hybrid RAG, Grounding & API)."""

from pathlib import Path
import sys

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import app
from engine.text_utils import deobfuscate_spaced_letters, normalize_vi
from engine.url_analyzer import analyze_url
from rag.retriever import HybridThreatRetriever

client = TestClient(app)


def test_vietnamese_deobfuscation():
    raw = "T a i  k h o a n  cua ban bi khoa, x m ngay"
    assert "taikhoan" in deobfuscate_spaced_letters(raw).lower().replace(" ", "")
    norm = normalize_vi("tk cua ban sap bi khoa", expand_abbrev=True)
    assert "tai khoan" in norm


def test_url_analyzer_distinguishes_official_vs_spoofed():
    safe = analyze_url("https://www.momo.vn/huong-dan")
    spoof = analyze_url("http://vcb-secure-verify-login.com/update.apk")
    assert safe["is_official"] is True
    assert safe["risk_score"] == 0
    assert spoof["is_official"] is False
    assert spoof["risk_score"] >= 80


def test_hybrid_rag_retrieves_expected_playbook():
    retriever = HybridThreatRetriever(ROOT / "data" / "threat_kb.json", use_remote_embeddings=False)
    hits = retriever.retrieve("MoMo thong bao khoa vi yeu cau nhap OTP", top_k=3)
    ids = [h["id"] for h in hits]
    assert "KB-02" in ids


def test_api_detects_bank_scam_and_protects_legit_otp():
    scam_resp = client.post(
        "/api/analyze",
        json={
            "text": "VCB thong bao tai khoan bi khoa trong 24h. Xac minh tai http://vcb-secure-verify-login.com",
            "channel": "SMS",
            "situation": "Chưa bấm link",
        },
    )
    assert scam_resp.status_code == 200
    scam_data = scam_resp.json()
    assert scam_data["predicted_label"] == "scam"
    assert scam_data["risk_score"] >= 75
    assert scam_data["grounding_audit"]["passed"] is True
    assert len(scam_data["agent_trace"]) >= 4

    legit_resp = client.post(
        "/api/analyze",
        json={
            "text": "MoMo: Ma OTP cua ban la 582910. Tuyet doi KHONG chia se ma OTP cho bat ky ai.",
            "channel": "SMS",
            "situation": "Chưa bấm link",
        },
    )
    assert legit_resp.status_code == 200
    legit_data = legit_resp.json()
    assert legit_data["predicted_label"] == "normal"
    assert legit_data["risk_score"] <= 20
