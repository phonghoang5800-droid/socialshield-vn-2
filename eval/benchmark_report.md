# SocialShield-VN Evaluation Report — v1 (ML+Rules) vs. v2 (Hybrid Agentic RAG)

- **Evaluation Dataset:** 28 unseen Vietnamese messages (7 scam categories, obfuscated text, no-URL scams, legitimate OTPs & promos)
- **Mode:** `hybrid_offline` | **Retrieval Backend:** `tfidf_dense_fallback + BM25 + RRF`

## 1. Classification & Latency Comparison

| Metric | SocialShield v1 (ML + 22 Rules) | SocialShield v2 (Agentic RAG) | Delta |
|---|---:|---:|---:|
| **Accuracy** | 96.43% | **100.00%** | +3.57% |
| **Macro F1** | 96.70% | **100.00%** | +3.30% |
| **Scam Recall** | 93.75% | **100.00%** | +6.25% |
| **Scam Precision** | 100.00% | **100.00%** | +0.00% |
| **False Positive Rate** | 0.00% | **0.00%** | +0.00% |
| **Latency p50 / p95 (ms)** | 0.75 / 1.39 | 1.47 / 2.3 | — |

## 2. Hybrid RAG Retrieval & Anti-Hallucination Audit

| Metric | Result |
|---|---:|
| **Hybrid RAG Recall@3** | **85.71%** |
| **Hybrid RAG MRR@3** | **0.8333** |
| **Citation Grounding Pass Rate** | **100.00%** |
