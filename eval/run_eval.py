"""Automated v1 (ML+Rules) vs. v2 (Hybrid Agentic RAG) Evaluation Harness.

Computes:
- Classification Accuracy, Macro F1, Scam Recall, Scam Precision, False Positive Rate
- Hybrid RAG Retrieval Recall@3 and MRR@3 against ground-truth threat KB IDs
- Citation Grounding Pass Rate (anti-hallucination verification)
- Latency p50 & p95 (ms)
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.agent import SocialShieldAgentV2
from engine.ml_v1 import XHRSMTSDv1
from rag.retriever import HybridThreatRetriever


def compute_metrics(y_true: list[str], y_pred: list[str], latencies: list[float]) -> dict:
    acc = accuracy_score(y_true, y_pred)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    y_true_bin = [1 if y == "scam" else 0 for y in y_true]
    y_pred_bin = [1 if y == "scam" else 0 for y in y_pred]
    scam_prec = precision_score(y_true_bin, y_pred_bin, zero_division=0)
    scam_rec = recall_score(y_true_bin, y_pred_bin, zero_division=0)
    fp = sum(1 for yt, yp in zip(y_true_bin, y_pred_bin) if yt == 0 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true_bin, y_pred_bin) if yt == 0 and yp == 0)
    fpr = fp / max(1, fp + tn)
    lat_sorted = sorted(latencies)
    p50 = statistics.median(lat_sorted) if lat_sorted else 0.0
    p95 = lat_sorted[min(len(lat_sorted) - 1, int(len(lat_sorted) * 0.95))] if lat_sorted else 0.0
    return {
        "accuracy": round(acc, 4),
        "macro_f1": round(macro_f1, 4),
        "scam_precision": round(scam_prec, 4),
        "scam_recall": round(scam_rec, 4),
        "false_positive_rate": round(fpr, 4),
        "latency_p50_ms": round(p50, 2),
        "latency_p95_ms": round(p95, 2),
    }


def run_benchmark(use_llm: bool = False) -> dict:
    ml_v1 = XHRSMTSDv1(ROOT / "data" / "train_sms_vn.json")
    retriever = HybridThreatRetriever(ROOT / "data" / "threat_kb.json", use_remote_embeddings=use_llm)
    agent_v2 = SocialShieldAgentV2(ml_v1, retriever)
    dataset = json.loads((ROOT / "eval" / "benchmark_dataset.json").read_text(encoding="utf-8"))

    y_true: list[str] = []
    v1_preds: list[str] = []
    v2_preds: list[str] = []
    v1_lats: list[float] = []
    v2_lats: list[float] = []

    recall_hits = 0
    mrr_sum = 0.0
    grounding_passes = 0
    case_diffs: list[dict] = []

    for row in dataset:
        text = row["text"]
        label = row["label"]
        expected_kb = set(row["expected_kb"])
        y_true.append(label)

        # v1 baseline
        t0 = time.perf_counter()
        out1 = ml_v1.predict(text)
        v1_lats.append((time.perf_counter() - t0) * 1000)
        v1_preds.append(out1["predicted_label"])

        # v2 agentic RAG
        t0 = time.perf_counter()
        out2 = agent_v2.analyze(text=text, channel="SMS", situation="Chưa bấm link", use_llm=use_llm)
        v2_lats.append((time.perf_counter() - t0) * 1000)
        v2_preds.append(out2["predicted_label"])

        # RAG Recall@3 & MRR@3
        ret_ids = [d["id"] for d in out2["retrieved_kb"]]
        if any(r in expected_kb for r in ret_ids):
            recall_hits += 1
        for rank, rid in enumerate(ret_ids, start=1):
            if rid in expected_kb:
                mrr_sum += 1.0 / rank
                break

        if out2["grounding_audit"]["passed"]:
            grounding_passes += 1

        if out1["predicted_label"] != out2["predicted_label"] or out2["predicted_label"] != label:
            case_diffs.append({
                "id": row["id"],
                "difficulty": row["difficulty"],
                "true_label": label,
                "v1_pred": out1["predicted_label"],
                "v1_score": out1["risk_score"],
                "v2_pred": out2["predicted_label"],
                "v2_score": out2["risk_score"],
                "retrieved_kb": ret_ids,
                "text_preview": text[:80],
            })

    n = len(dataset)
    report = {
        "dataset_size": n,
        "mode": "llm_agent" if (use_llm and agent_v2.llm_provider != "hybrid_offline_synthesizer") else "hybrid_offline",
        "embedding_backend": retriever.embedding_backend,
        "v1_baseline": compute_metrics(y_true, v1_preds, v1_lats),
        "v2_agentic_rag": compute_metrics(y_true, v2_preds, v2_lats),
        "rag_retrieval": {
            "recall_at_3": round(recall_hits / n, 4),
            "mrr_at_3": round(mrr_sum / n, 4),
            "citation_grounding_rate": round(grounding_passes / n, 4),
        },
        "notable_cases": case_diffs,
    }

    (ROOT / "eval" / "benchmark_report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    v1 = report["v1_baseline"]
    v2 = report["v2_agentic_rag"]
    rag = report["rag_retrieval"]
    md = f"""# SocialShield-VN Evaluation Report — v1 (ML+Rules) vs. v2 (Hybrid Agentic RAG)

- **Evaluation Dataset:** {n} unseen Vietnamese messages (7 scam categories, obfuscated text, no-URL scams, legitimate OTPs & promos)
- **Mode:** `{report['mode']}` | **Retrieval Backend:** `{report['embedding_backend']} + BM25 + RRF`

## 1. Classification & Latency Comparison

| Metric | SocialShield v1 (ML + 22 Rules) | SocialShield v2 (Agentic RAG) | Delta |
|---|---:|---:|---:|
| **Accuracy** | {v1['accuracy']*100:.2f}% | **{v2['accuracy']*100:.2f}%** | {(v2['accuracy']-v1['accuracy'])*100:+.2f}% |
| **Macro F1** | {v1['macro_f1']*100:.2f}% | **{v2['macro_f1']*100:.2f}%** | {(v2['macro_f1']-v1['macro_f1'])*100:+.2f}% |
| **Scam Recall** | {v1['scam_recall']*100:.2f}% | **{v2['scam_recall']*100:.2f}%** | {(v2['scam_recall']-v1['scam_recall'])*100:+.2f}% |
| **Scam Precision** | {v1['scam_precision']*100:.2f}% | **{v2['scam_precision']*100:.2f}%** | {(v2['scam_precision']-v1['scam_precision'])*100:+.2f}% |
| **False Positive Rate** | {v1['false_positive_rate']*100:.2f}% | **{v2['false_positive_rate']*100:.2f}%** | {(v2['false_positive_rate']-v1['false_positive_rate'])*100:+.2f}% |
| **Latency p50 / p95 (ms)** | {v1['latency_p50_ms']} / {v1['latency_p95_ms']} | {v2['latency_p50_ms']} / {v2['latency_p95_ms']} | — |

## 2. Hybrid RAG Retrieval & Anti-Hallucination Audit

| Metric | Result |
|---|---:|
| **Hybrid RAG Recall@3** | **{rag['recall_at_3']*100:.2f}%** |
| **Hybrid RAG MRR@3** | **{rag['mrr_at_3']:.4f}** |
| **Citation Grounding Pass Rate** | **{rag['citation_grounding_rate']*100:.2f}%** |
"""
    (ROOT / "eval" / "benchmark_report.md").write_text(md, encoding="utf-8")
    return report


if __name__ == "__main__":
    use_llm_flag = "--llm" in sys.argv
    res = run_benchmark(use_llm=use_llm_flag)
    print(json.dumps(res, indent=2, ensure_ascii=False))
