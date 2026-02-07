#!/usr/bin/env python3
"""
Confidence Scoring Utility

Computes numeric confidence scores and buckets for findings based on
evidence signals, verification results, and recency.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List


def compute_confidence_score(vuln: Dict[str, Any]) -> Dict[str, Any]:
    evidence = vuln.get("evidence", [])
    verification = vuln.get("verification", {}) or {}
    evidence_verification = vuln.get("evidence_verification", {}) or {}

    signals = 0
    score = 0.0

    # Evidence signals
    evidence_items: List[Any] = evidence if isinstance(evidence, list) else [evidence] if evidence else []
    signals += len(evidence_items)
    score += min(20, 5 * len(evidence_items))

    for item in evidence_items:
        if isinstance(item, dict):
            ev_type = item.get("type", "").lower()
            if ev_type == "exact":
                score += 5
            elif ev_type == "regex":
                score += 3
            elif ev_type == "header":
                score += 2

    # Verification signals
    if verification.get("verified") is True:
        score += 40
    elif verification:
        score += 10

    ev_status = evidence_verification.get("verification_status")
    if ev_status == "verified":
        score += 20
    elif ev_status == "stale":
        score -= 10

    # Recency
    timestamp = vuln.get("timestamp")
    if timestamp:
        try:
            ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            age = datetime.utcnow() - ts.replace(tzinfo=None)
            if age <= timedelta(hours=24):
                score += 10
            elif age <= timedelta(days=7):
                score += 5
        except Exception:
            pass

    score = max(0.0, min(100.0, score))

    if score >= 80:
        bucket = "Certain"
    elif score >= 60:
        bucket = "Firm"
    elif score >= 40:
        bucket = "Tentative"
    else:
        bucket = "Unlikely"

    return {
        "confidence_score": round(score, 2),
        "confidence_bucket": bucket,
        "signal_count": signals,
    }
