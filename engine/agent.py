"""SocialShield-VN 2.0 — Multimodal Agentic Anti-Scam Orchestrator.

Explicit Tool-Calling Pipeline with Live Execution Trace & Anti-Hallucination Guard:
  1. [Optional] vision_inspector  -> VLM OCR + visual spoofing cues on uploaded screenshots (Gemini / OpenAI Vision)
  2. ml_risk_scorer               -> v1 X-HRS-MTSD+ hybrid classifier + 22 Vietnamese fraud rules
  3. url_trust_analyzer           -> Official domain allowlist, brand typosquatting, .apk & TLD analysis
  4. threat_kb_rag                -> Hybrid BM25 + Dense Vector + RRF over Vietnamese Anti-Scam KB
  5. agent_synthesis              -> Grounded LLM synthesis (Gemini 2.5 Flash / OpenAI) + citation verification
                                     (with deterministic hybrid fallback when running without an API key)
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
from typing import Any

import httpx

from rag.retriever import HybridThreatRetriever

from .ml_v1 import SCAM_CATEGORY_LABELS, XHRSMTSDv1
from .text_utils import normalize_vi
from .url_analyzer import analyze_urls_in_text

SITUATION_DEFAULT_STEPS = {
    "Chưa bấm link": [
        "Không bấm vào đường link, không quét mã QR và không trả lời tin nhắn.",
        "Tự kiểm tra trực tiếp trên ứng dụng chính thức hoặc gọi tổng đài chính thức in mặt sau thẻ.",
        "Chụp màn hình lưu bằng chứng, chặn số gửi và phản ánh tới đầu số 156 hoặc canhbao.ncsc.gov.vn.",
    ],
    "Đã bấm link": [
        "Đóng ngay trang web vừa mở, tuyệt đối không nhập thêm thông tin hay tải bất kỳ tệp nào.",
        "Nếu đã nhập mật khẩu, đổi mật khẩu tài khoản ngân hàng/ví điện tử và email ngay lập tức.",
        "Kiểm tra lịch sử đăng nhập và đăng xuất toàn bộ thiết bị lạ.",
    ],
    "Đã nhập OTP": [
        "Gọi NGAY tổng đài chính thức của ngân hàng/ví điện tử (VD: MoMo 1900 5454 41, VCB 1900 5454 13) để khóa tạm thời tài khoản và thẻ.",
        "Đổi ngay mật khẩu ngân hàng, ví điện tử và email liên kết trên một thiết bị khác.",
        "Lưu giữ toàn bộ ảnh chụp màn hình, số điện thoại và đường link làm bằng chứng.",
    ],
    "Đã gửi thông tin": [
        "Liên hệ ngay tổng đài chính thức của ngân hàng/ví điện tử để khóa thẻ và bật cảnh báo giao dịch.",
        "Đổi toàn bộ mật khẩu tài khoản tài chính và bật xác thực hai lớp (2FA).",
        "Cảnh giác cuộc gọi giả danh tiếp theo khai thác thông tin CCCD bạn vừa cung cấp.",
    ],
    "Đã chuyển tiền": [
        "Gọi NGAY tổng đài ngân hàng/ví điện tử để yêu cầu tra soát khẩn cấp và ghi nhận giao dịch lừa đảo.",
        "Tuyệt đối KHÔNG chuyển thêm bất kỳ khoản phí nào để 'lấy lại tiền' (bẫy lừa đảo vòng 2).",
        "Lưu sao kê, số tài khoản nhận, nội dung chat và trình báo ngay Công an phường/xã gần nhất.",
    ],
    "Đã cài app lạ": [
        "NGẮT NGAY Wi-Fi, 4G/5G (bật Chế độ máy bay) để cắt kết nối điều khiển từ xa của mã độc.",
        "Dùng một điện thoại KHÁC gọi ngay tổng đài ngân hàng/ví điện tử khóa tạm thời tài khoản.",
        "Sao lưu dữ liệu quan trọng không phải ứng dụng rồi Khôi phục cài đặt gốc (Factory Reset) máy trước khi đổi lại mật khẩu.",
    ],
}


class SocialShieldAgentV2:
    """Multimodal Agentic Anti-Scam Copilot combining v1 ML + Hybrid RAG + VLM/LLM + Grounding Guard."""

    def __init__(self, ml_v1: XHRSMTSDv1, retriever: HybridThreatRetriever) -> None:
        self.ml_v1 = ml_v1
        self.retriever = retriever

    @property
    def llm_provider(self) -> str:
        if os.getenv("GEMINI_API_KEY"):
            return "gemini-2.5-flash"
        if os.getenv("OPENAI_API_KEY"):
            return os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        return "hybrid_offline_synthesizer"

    def _call_gemini(self, prompt: str, image_bytes: bytes | None = None, mime_type: str = "image/png") -> str | None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return None
        model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        parts: list[dict[str, Any]] = [{"text": prompt}]
        if image_bytes is not None:
            parts.append({
                "inline_data": {
                    "mime_type": mime_type,
                    "data": base64.b64encode(image_bytes).decode("ascii"),
                }
            })
        payload = {
            "contents": [{"parts": parts}],
            "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"},
        }
        try:
            with httpx.Client(timeout=25.0) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception:
            return None

    def _call_openai(self, prompt: str, image_bytes: bytes | None = None, mime_type: str = "image/png") -> str | None:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            return None
        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        content: list[dict[str, Any]] = [{"type": "text", "text": prompt}]
        if image_bytes is not None:
            b64 = base64.b64encode(image_bytes).decode("ascii")
            content.append({"type": "image_url", "image_url": {"url": f"data:{mime_type};base64,{b64}"}})
        payload = {
            "model": model,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [{"role": "user", "content": content}],
        }
        try:
            with httpx.Client(timeout=25.0) as client:
                resp = client.post(
                    f"{base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}"},
                    json=payload,
                )
                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]["content"]
        except Exception:
            return None

    def _call_llm_json(self, prompt: str, image_bytes: bytes | None = None, mime_type: str = "image/png") -> dict[str, Any] | None:
        raw = self._call_gemini(prompt, image_bytes, mime_type) if os.getenv("GEMINI_API_KEY") else self._call_openai(prompt, image_bytes, mime_type)
        if not raw:
            return None
        try:
            cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip(), flags=re.IGNORECASE)
            return json.loads(cleaned)
        except Exception:
            return None

    def _inspect_image_vlm(self, image_bytes: bytes, mime_type: str) -> dict[str, Any]:
        prompt = (
            "Bạn là chuyên gia phân tích an ninh mạng tài chính Việt Nam. "
            "Hãy đọc toàn bộ văn bản trong ảnh chụp màn hình (tin nhắn SMS/Zalo/email hoặc biên lai chuyển khoản) "
            "và kiểm tra dấu hiệu giả mạo trực quan (chỉnh sửa phông chữ, số tiền lệch hàng, link lạ, logo nhòe, yêu cầu OTP/cài app). "
            "Trả về DUY NHẤT JSON đúng cấu trúc: "
            '{"extracted_text": "...", "image_type": "sms_chat|bank_transfer_bill|link_page|other", '
            '"visual_red_flags": ["..."], "visual_risk_boost": 0-30}'
        )
        parsed = self._call_llm_json(prompt, image_bytes=image_bytes, mime_type=mime_type)
        if parsed and isinstance(parsed.get("extracted_text"), str):
            return {
                "status": "vlm_analyzed",
                "extracted_text": parsed.get("extracted_text", ""),
                "image_type": parsed.get("image_type", "other"),
                "visual_red_flags": parsed.get("visual_red_flags", []),
                "visual_risk_boost": int(min(30, max(0, parsed.get("visual_risk_boost", 0)))),
            }
        return {
            "status": "vlm_api_key_required",
            "extracted_text": "",
            "image_type": "unknown",
            "visual_red_flags": [
                "Chưa cấu hình GEMINI_API_KEY hoặc OPENAI_API_KEY — hãy thêm API key trong tệp .env để kích hoạt VLM đọc ảnh chụp màn hình trực tiếp."
            ],
            "visual_risk_boost": 0,
        }

    @staticmethod
    def _verify_grounding(citations: list[str], retrieved_docs: list[dict[str, Any]]) -> dict[str, Any]:
        """Anti-Hallucination Guard: verify every cited KB ID actually exists in retrieved evidence."""
        valid_ids = {d["id"] for d in retrieved_docs}
        verified = [c for c in citations if c in valid_ids]
        ungrounded = [c for c in citations if c not in valid_ids]
        return {
            "passed": len(ungrounded) == 0 and len(verified) > 0,
            "verified_citations": verified,
            "ungrounded_citations": ungrounded,
            "grounding_ratio": round(len(verified) / max(1, len(citations)), 3),
        }

    def analyze(
        self,
        text: str = "",
        channel: str = "SMS",
        situation: str = "Chưa bấm link",
        image_bytes: bytes | None = None,
        mime_type: str = "image/png",
        use_llm: bool = True,
    ) -> dict[str, Any]:
        """Run full v2 Multimodal Agentic RAG pipeline and return structured verdict + tool trace."""
        t0 = time.perf_counter()
        trace: list[dict[str, Any]] = []
        working_text = (text or "").strip()
        vision_result: dict[str, Any] | None = None

        # STEP 1: Optional Multimodal Vision Inspector
        if image_bytes is not None:
            ts = time.perf_counter()
            vision_result = self._inspect_image_vlm(image_bytes, mime_type)
            if vision_result["extracted_text"]:
                working_text = (
                    f"{working_text}\n[Trích xuất từ ảnh]: {vision_result['extracted_text']}".strip()
                    if working_text
                    else vision_result["extracted_text"]
                )
            trace.append({
                "step": 1,
                "tool": "vision_inspector",
                "latency_ms": round((time.perf_counter() - ts) * 1000, 1),
                "summary": f"status={vision_result['status']}, type={vision_result['image_type']}, red_flags={len(vision_result['visual_red_flags'])}",
            })

        # STEP 2: Tool Call — v1 X-HRS-MTSD+ ML + 22 Rule Scorer
        ts = time.perf_counter()
        v1_out = self.ml_v1.predict(working_text)
        trace.append({
            "step": len(trace) + 1,
            "tool": "ml_risk_scorer (X-HRS-MTSD+ v1)",
            "latency_ms": round((time.perf_counter() - ts) * 1000, 1),
            "summary": f"label={v1_out['predicted_label']}, score={v1_out['risk_score']}/100, p_scam={v1_out['scam_probability']}",
        })

        # STEP 3: Tool Call — URL Trust Analyzer
        ts = time.perf_counter()
        url_out = analyze_urls_in_text(working_text)
        trace.append({
            "step": len(trace) + 1,
            "tool": "url_trust_analyzer",
            "latency_ms": round((time.perf_counter() - ts) * 1000, 1),
            "summary": f"urls={url_out['url_count']}, max_url_risk={url_out['max_url_risk']}/100",
        })

        # STEP 4: Tool Call — Hybrid RAG Retrieval (BM25 + Dense Vector + RRF)
        ts = time.perf_counter()
        sig = v1_out["signals"]
        norm_text = normalize_vi(working_text, expand_abbrev=True)
        has_prepaid_trap = any(k in norm_text for k in ("nap ", "dat coc", "dong phi", "phi kich hoat", "kich hoat nhiem vu", "chuyen truoc"))

        cat_hint = v1_out["scam_category"]
        if vision_result and vision_result.get("image_type") == "bank_transfer_bill":
            cat_hint = "fake_bill_visual"
        elif sig["has_obfuscation"]:
            cat_hint = "obfuscation_evasion"
        elif sig["top_category"] in ("job_task_scam", "loan_investment_scam") and (has_prepaid_trap or sig["has_money_request"]):
            cat_hint = sig["top_category"]
        elif v1_out["predicted_label"] == "normal" and not sig["has_unofficial_url"]:
            cat_hint = "legitimate_reference"

        retrieved_kb = self.retriever.retrieve(
            query=working_text or "cảnh báo lừa đảo tài chính",
            top_k=3,
            category_hint=cat_hint,
            situation=situation if cat_hint != "legitimate_reference" else None,
        )
        trace.append({
            "step": len(trace) + 1,
            "tool": f"threat_kb_rag ({self.retriever.embedding_backend} + BM25 + RRF)",
            "latency_ms": round((time.perf_counter() - ts) * 1000, 1),
            "summary": f"retrieved={[d['id'] for d in retrieved_kb]}",
        })

        # STEP 5: Grounded LLM Synthesis (with deterministic fallback + anti-hallucination guard)
        ts = time.perf_counter()
        llm_used = False
        final_score = v1_out["risk_score"]
        final_label = v1_out["predicted_label"]
        final_cat = v1_out["scam_category"]
        reasons = list(v1_out["reasons"])
        if vision_result:
            final_score = min(100, final_score + vision_result.get("visual_risk_boost", 0))
            reasons.extend(vision_result.get("visual_red_flags", []))

        # v2 Semantic Context & RAG-aligned Adjustments (fixes known v1 failure modes: obfuscated/OTP/no-URL prepaid traps)
        if (sig["has_obfuscation"] or (sig["has_otp"] and not sig["has_safe_otp_guard"]) or sig["has_install_request"]) and (
            sig["has_urgency"] or sig["has_verify"] or sig["has_money_request"] or sig["has_brand_impersonation"]
        ):
            final_score = max(final_score, 74)
            final_label = "scam"
            if final_cat in ("safe", "promo"):
                final_cat = sig["top_category"] or "unknown_scam"

        if (sig["has_money_request"] or has_prepaid_trap) and (
            sig["top_category"] in ("loan_investment_scam", "job_task_scam", "gov_impersonation", "delivery_impersonation")
        ):
            final_score = max(final_score, 78)
            final_label = "scam"
            final_cat = sig["top_category"]
            if has_prepaid_trap:
                reasons.append("Phát hiện mô thức yêu cầu nạp tiền/đặt cọc kích hoạt nhiệm vụ hoặc hồ sơ không qua kênh chính thống")

        # Protect legitimate bank/e-wallet OTP or security reminder SMS from false positives
        if sig["has_safe_otp_guard"] and not sig["has_unofficial_url"] and not sig["has_install_request"] and not sig["has_money_request"]:
            final_score = min(final_score, 15)
            final_label = "normal"
            final_cat = "safe"

        citations = [d["id"] for d in retrieved_kb[:2]]
        explanation = self._build_offline_explanation(final_label, final_score, final_cat, reasons, retrieved_kb)
        recommended_actions = list(SITUATION_DEFAULT_STEPS.get(situation, SITUATION_DEFAULT_STEPS["Chưa bấm link"]))
        if final_label != "scam":
            recommended_actions = [
                "Chưa thấy dấu hiệu lừa đảo rõ ràng, tuy nhiên vẫn nên cảnh giác nếu có yêu cầu cung cấp OTP hoặc chuyển tiền phát sinh sau đó.",
                "Luôn tự kiểm tra trực tiếp trên ứng dụng chính thức khi nghi ngờ.",
            ]

        if use_llm and (os.getenv("GEMINI_API_KEY") or os.getenv("OPENAI_API_KEY")):
            kb_context = "\n".join(
                f"[{d['id']}] ({d['title']}): {d['content']} | Kênh chính thức: {d['official_channels']}"
                for d in retrieved_kb
            )
            synth_prompt = f"""Bạn là SocialShield-VN 2.0 — AI Agent chống lừa đảo tài chính tại Việt Nam.
QUY TẮC BẮT BUỘC (CHỐNG BỊA / ANTI-HALLUCINATION):
1. CHỈ trích dẫn mã [KB-xx] và số tổng đài có trong NGỮ CẢNH TRI THỨC bên dưới. Tuyệt đối không tự bịa hotline hay tên miền.
2. Phân biệt rõ tin nhắn OTP chính thống (có lời nhắc 'không chia sẻ OTP', không link lạ) là AN TOÀN (normal, risk_score <= 20).
3. Trả về DUY NHẤT JSON hợp lệ đúng schema:
{{
  "predicted_label": "scam|promo|normal",
  "risk_score": 0-100,
  "scam_category": "bank_impersonation|gov_impersonation|ewallet_impersonation|delivery_impersonation|ecommerce_impersonation|loan_investment_scam|job_task_scam|safe|promo|unknown_scam",
  "explanation": "Giải thích ngắn gọn, rõ ràng bằng tiếng Việt có trích dẫn [KB-xx]",
  "key_indicators": ["dấu hiệu 1", "dấu hiệu 2"],
  "citations": ["KB-01"],
  "recommended_actions": ["bước 1", "bước 2", "bước 3"]
}}

DỮ LIỆU ĐẦU VÀO:
- Kênh: {channel} | Tình huống người dùng: {situation}
- Nội dung: {working_text}
- Kết quả Tool ML v1: score={v1_out['risk_score']}/100, label={v1_out['predicted_label']}, p_scam={v1_out['scam_probability']}, signals={reasons}
- Kết quả Tool URL: {json.dumps(url_out, ensure_ascii=False)}
- Ngữ cảnh tri thức truy xuất (Hybrid RAG):
{kb_context}
"""
            llm_out = self._call_llm_json(synth_prompt)
            if llm_out and isinstance(llm_out.get("risk_score"), (int, float)):
                llm_used = True
                final_score = int(round(max(0, min(100, llm_out["risk_score"]))))
                final_label = llm_out.get("predicted_label", final_label)
                final_cat = llm_out.get("scam_category", final_cat)
                explanation = llm_out.get("explanation", explanation)
                if isinstance(llm_out.get("key_indicators"), list) and llm_out["key_indicators"]:
                    reasons = llm_out["key_indicators"]
                if isinstance(llm_out.get("citations"), list) and llm_out["citations"]:
                    citations = [str(c).strip("[]") for c in llm_out["citations"]]
                if isinstance(llm_out.get("recommended_actions"), list) and llm_out["recommended_actions"]:
                    recommended_actions = llm_out["recommended_actions"]

        grounding = self._verify_grounding(citations, retrieved_kb)
        if not grounding["passed"]:
            # Enforce grounding: drop ungrounded citations & replace with verified top KB IDs
            citations = [d["id"] for d in retrieved_kb[:2]]
            grounding = self._verify_grounding(citations, retrieved_kb)

        trace.append({
            "step": len(trace) + 1,
            "tool": f"agent_synthesis ({self.llm_provider if llm_used else 'hybrid_offline_synthesizer'})",
            "latency_ms": round((time.perf_counter() - ts) * 1000, 1),
            "summary": f"llm_active={llm_used}, grounding_passed={grounding['passed']}, citations={citations}",
        })

        risk_level = self._score_to_level(final_score)
        total_ms = round((time.perf_counter() - t0) * 1000, 1)

        return {
            "version": "2.0",
            "mode": "llm_agent" if llm_used else "hybrid_offline",
            "model_provider": self.llm_provider if llm_used else "hybrid_ml_rag_v2",
            "channel": channel,
            "situation": situation,
            "analyzed_text": working_text,
            "predicted_label": final_label,
            "risk_score": final_score,
            "risk_level": risk_level,
            "scam_category": final_cat,
            "scam_category_label": SCAM_CATEGORY_LABELS.get(final_cat, "Chưa phân loại"),
            "explanation": explanation,
            "key_indicators": reasons,
            "recommended_actions": recommended_actions,
            "urls": url_out["urls"],
            "vision_analysis": vision_result,
            "retrieved_kb": retrieved_kb,
            "citations": citations,
            "grounding_audit": grounding,
            "v1_baseline": {
                "predicted_label": v1_out["predicted_label"],
                "risk_score": v1_out["risk_score"],
                "scam_probability": v1_out["scam_probability"],
            },
            "agent_trace": trace,
            "total_latency_ms": total_ms,
        }

    @staticmethod
    def _score_to_level(score: int) -> str:
        if score >= 81:
            return "Rất nguy hiểm"
        if score >= 61:
            return "Nguy hiểm"
        if score >= 41:
            return "Cần kiểm tra"
        if score >= 21:
            return "Rủi ro thấp"
        return "An toàn"

    @staticmethod
    def _build_offline_explanation(
        label: str,
        score: int,
        category: str,
        reasons: list[str],
        retrieved_kb: list[dict[str, Any]],
    ) -> str:
        top_kb = retrieved_kb[0] if retrieved_kb else None
        ref = f" [{top_kb['id']}]" if top_kb else ""
        if label == "scam":
            cat_name = SCAM_CATEGORY_LABELS.get(category, "lừa đảo trực tuyến")
            top_reasons = "; ".join(reasons[:3])
            extra = f" Kênh xác minh chính thức tham khảo{ref}: {top_kb['official_channels']}" if top_kb and top_kb.get("official_channels") else ""
            return f"Phát hiện dấu hiệu nguy cơ cao thuộc nhóm '{cat_name}' (điểm rủi ro {score}/100). Bằng chứng chính: {top_reasons}.{extra}"
        if label == "promo":
            return f"Nội dung mang đặc trưng tin nhắn quảng cáo/khuyến mãi thông thường (điểm rủi ro {score}/100){ref}, chưa phát hiện dấu hiệu giả mạo tài chính."
        return f"Nội dung hiện ở mức rủi ro thấp ({score}/100){ref}. Không phát hiện tên miền giả mạo, yêu cầu cài app lạ hay bẫy chuyển tiền."
