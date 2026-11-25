"""Hybrid RAG Retriever (BM25 + Dense Vector Embeddings + Reciprocal Rank Fusion).

Supports:
- Sparse lexical retrieval via BM25Okapi (dual accented + accent-stripped Vietnamese tokenization)
- Dense vector retrieval via Gemini text-embedding-004 (when GEMINI_API_KEY is set) with
  seamless offline Word+Char TF-IDF L2-normalized vector fallback
- Reciprocal Rank Fusion (RRF, k=60) + optional category boosting for high-precision retrieval
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
import numpy as np
from rank_bm25 import BM25Okapi
from sklearn.feature_extraction.text import TfidfVectorizer

from engine.text_utils import normalize_vi, tokenize_vi_dual


class HybridThreatRetriever:
    """Hybrid BM25 + Dense Vector + RRF retriever over Vietnamese Anti-Scam Knowledge Base."""

    def __init__(self, kb_path: str | Path, use_remote_embeddings: bool = True) -> None:
        self.kb_path = Path(kb_path)
        self.docs: list[dict[str, Any]] = json.loads(self.kb_path.read_text(encoding="utf-8"))
        self.use_remote_embeddings = use_remote_embeddings and bool(os.getenv("GEMINI_API_KEY"))
        self.embedding_backend = "tfidf_dense_fallback"

        self._corpus_texts = [self._doc_to_text(d) for d in self.docs]
        self._bm25_corpus = [tokenize_vi_dual(t) for t in self._corpus_texts]
        self._bm25 = BM25Okapi(self._bm25_corpus)

        # Offline dense vector representation (Word + Char n-gram L2-normalized TF-IDF)
        self._word_vec = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)
        self._char_vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True)
        norm_texts = [normalize_vi(t, expand_abbrev=True) for t in self._corpus_texts]
        w_mat = self._word_vec.fit_transform(norm_texts).toarray()
        c_mat = self._char_vec.fit_transform(norm_texts).toarray()
        self._dense_matrix = self._l2_normalize(np.hstack([w_mat, c_mat * 0.6]))

        # Optionally upgrade dense vectors to Gemini text-embedding-004 if key is available
        if self.use_remote_embeddings:
            remote_vecs = self._embed_texts_gemini(self._corpus_texts)
            if remote_vecs is not None:
                self._dense_matrix = self._l2_normalize(remote_vecs)
                self.embedding_backend = "gemini_text_embedding_004"

    @staticmethod
    def _doc_to_text(doc: dict[str, Any]) -> str:
        tags = " ".join(doc.get("tags", []))
        return f"{doc['title']} {doc['content']} {doc.get('official_channels', '')} {tags}"

    @staticmethod
    def _l2_normalize(mat: np.ndarray) -> np.ndarray:
        norms = np.linalg.norm(mat, axis=1, keepdims=True)
        norms = np.where(norms == 0, 1.0, norms)
        return mat / norms

    def _embed_texts_gemini(self, texts: list[str]) -> np.ndarray | None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return None
        url = f"https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:batchEmbedContents?key={api_key}"
        payload = {
            "requests": [
                {"model": "models/text-embedding-004", "content": {"parts": [{"text": t[:2000]}]}}
                for t in texts
            ]
        }
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                vecs = [item["values"] for item in data["embeddings"]]
                return np.array(vecs, dtype=np.float32)
        except Exception:
            return None

    def _embed_query(self, query: str) -> np.ndarray:
        if self.embedding_backend == "gemini_text_embedding_004":
            remote = self._embed_texts_gemini([query])
            if remote is not None:
                return self._l2_normalize(remote)[0]
        norm_q = normalize_vi(query, expand_abbrev=True)
        wq = self._word_vec.transform([norm_q]).toarray()
        cq = self._char_vec.transform([norm_q]).toarray()
        return self._l2_normalize(np.hstack([wq, cq * 0.6]))[0]

    def retrieve(
        self,
        query: str,
        top_k: int = 3,
        category_hint: str | None = None,
        situation: str | None = None,
        rrf_k: int = 60,
    ) -> list[dict[str, Any]]:
        """Retrieve top_k authoritative threat KB chunks using BM25 + Dense Vector + RRF."""
        # 1. BM25 sparse ranking (keep query clean of UI situation labels)
        q_tokens = tokenize_vi_dual(query)
        bm25_scores = self._bm25.get_scores(q_tokens) if q_tokens else np.zeros(len(self.docs))
        bm25_order = np.argsort(-bm25_scores)
        bm25_ranks = {int(idx): rank + 1 for rank, idx in enumerate(bm25_order)}

        # 2. Dense vector cosine ranking
        q_vec = self._embed_query(query)
        dense_scores = self._dense_matrix @ q_vec
        dense_order = np.argsort(-dense_scores)
        dense_ranks = {int(idx): rank + 1 for rank, idx in enumerate(dense_order)}

        # 3. Reciprocal Rank Fusion + calibrated metadata boosting
        fused: list[tuple[int, float, float, float]] = []
        situation_cat_map = {
            "Chưa bấm link": "response_not_clicked",
            "Đã bấm link": "response_clicked_or_otp",
            "Đã nhập OTP": "response_clicked_or_otp",
            "Đã gửi thông tin": "response_clicked_or_otp",
            "Đã chuyển tiền": "response_transferred_money",
            "Đã cài app lạ": "response_installed_apk",
        }
        sit_cat = situation_cat_map.get(situation or "")

        for idx, doc in enumerate(self.docs):
            rrf = (1.0 / (rrf_k + bm25_ranks[idx])) + (1.0 / (rrf_k + dense_ranks[idx]))
            if category_hint and doc["category"] == category_hint:
                rrf += 0.012
            if sit_cat and doc["category"] == sit_cat and category_hint != "legitimate_reference":
                rrf += 0.003
            fused.append((idx, rrf, float(bm25_scores[idx]), float(dense_scores[idx])))

        fused.sort(key=lambda x: x[1], reverse=True)
        results: list[dict[str, Any]] = []
        for idx, rrf_score, b_score, d_score in fused[:top_k]:
            doc = self.docs[idx]
            results.append({
                "id": doc["id"],
                "category": doc["category"],
                "title": doc["title"],
                "source": doc["source"],
                "content": doc["content"],
                "official_channels": doc.get("official_channels", ""),
                "rrf_score": round(rrf_score, 5),
                "bm25_score": round(b_score, 3),
                "dense_score": round(d_score, 3),
            })
        return results
