"""SocialShield-VN 2.0 — FastAPI Application & SQLite Audit Store."""

from __future__ import annotations

import csv
import io
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from engine.agent import SocialShieldAgentV2
from engine.ml_v1 import XHRSMTSDv1
from rag.retriever import HybridThreatRetriever

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "socialshield_v2.db"

ml_v1 = XHRSMTSDv1(ROOT / "data" / "train_sms_vn.json")
retriever = HybridThreatRetriever(ROOT / "data" / "threat_kb.json")
agent = SocialShieldAgentV2(ml_v1, retriever)


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel TEXT NOT NULL,
                situation TEXT NOT NULL,
                content TEXT NOT NULL,
                predicted_label TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                scam_category TEXT NOT NULL,
                mode TEXT NOT NULL,
                citations TEXT NOT NULL,
                latency_ms REAL NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def log_analysis(res: dict[str, Any]) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO analyses (
                channel, situation, content, predicted_label, risk_score,
                risk_level, scam_category, mode, citations, latency_ms, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                res["channel"],
                res["situation"],
                res["analyzed_text"][:1000],
                res["predicted_label"],
                res["risk_score"],
                res["risk_level"],
                res["scam_category"],
                res["mode"],
                json.dumps(res["citations"]),
                res["total_latency_ms"],
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()


init_db()

app = FastAPI(
    title="SocialShield-VN 2.0 API",
    description="Multimodal Agentic Anti-Scam Copilot: X-HRS-MTSD+ v1 + Hybrid BM25/Dense RAG + VLM Vision + Citation Grounding Guard",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=2, max_length=4000)
    channel: str = Field(default="SMS")
    situation: str = Field(default="Chưa bấm link")


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "version": "2.0.0",
        "llm_provider": agent.llm_provider,
        "embedding_backend": retriever.embedding_backend,
        "kb_chunks": len(retriever.docs),
    }


@app.post("/api/analyze")
def analyze_text(req: AnalyzeRequest) -> dict[str, Any]:
    result = agent.analyze(text=req.text, channel=req.channel, situation=req.situation)
    log_analysis(result)
    return result


@app.post("/api/analyze-image")
async def analyze_image(
    file: UploadFile = File(...),
    note: str = Form(default=""),
    channel: str = Form(default="Zalo / Screenshot"),
    situation: str = Form(default="Chưa bấm link"),
) -> dict[str, Any]:
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Vui lòng tải lên tệp ảnh hợp lệ (PNG, JPG, WEBP).")
    raw_bytes = await file.read()
    if len(raw_bytes) > 8 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Ảnh vượt quá giới hạn 8MB.")
    result = agent.analyze(
        text=note,
        channel=channel,
        situation=situation,
        image_bytes=raw_bytes,
        mime_type=file.content_type,
    )
    log_analysis(result)
    return result


@app.post("/api/batch-scan")
async def batch_scan(file: UploadFile = File(...)) -> dict[str, Any]:
    raw = (await file.read()).decode("utf-8-sig", errors="ignore")
    lines: list[str] = []
    if (file.filename or "").lower().endswith(".csv"):
        reader = csv.DictReader(io.StringIO(raw))
        if reader.fieldnames:
            target_col = next(
                (c for c in reader.fieldnames if c.strip().lower() in {"message_text", "text", "content", "sms", "noi_dung"}),
                reader.fieldnames[0],
            )
            for row in reader:
                val = (row.get(target_col) or "").strip()
                if val:
                    lines.append(val)
    else:
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]

    lines = lines[:200]
    items = []
    for idx, msg in enumerate(lines, start=1):
        res = agent.analyze(text=msg, channel="Batch", situation="Chưa bấm link", use_llm=False)
        items.append({
            "row": idx,
            "content": msg,
            "predicted_label": res["predicted_label"],
            "risk_score": res["risk_score"],
            "risk_level": res["risk_level"],
            "scam_category_label": res["scam_category_label"],
            "citations": res["citations"],
        })
    scam_count = sum(1 for i in items if i["predicted_label"] == "scam")
    return {"total_scanned": len(items), "scam_detected": scam_count, "items": items}


@app.get("/api/history")
def get_history(limit: int = 12) -> dict[str, Any]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM analyses ORDER BY id DESC LIMIT ?", (min(limit, 50),)
        ).fetchall()
    return {"items": [dict(r) for r in rows]}


@app.get("/api/benchmark")
def get_benchmark() -> dict[str, Any]:
    report_path = ROOT / "eval" / "benchmark_report.json"
    if not report_path.exists():
        from eval.run_eval import run_benchmark
        return run_benchmark(use_llm=False)
    return json.loads(report_path.read_text(encoding="utf-8"))


app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@app.get("/")
def serve_home() -> FileResponse:
    return FileResponse(ROOT / "static" / "index.html")
