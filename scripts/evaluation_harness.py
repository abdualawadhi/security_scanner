#!/usr/bin/env python3
"""
Evaluation harness for benchmark datasets.

Computes precision/recall for scanner output against an expected dataset.
"""

import json
from pathlib import Path
from typing import Dict, List


def _load_json(path: Path) -> Dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _index_expected(target: Dict) -> Dict[str, Dict]:
    expected = {}
    for finding in target.get("expected_findings", []):
        key = f"{finding.get('type')}|{finding.get('owasp')}|{finding.get('severity')}"
        expected[key] = finding
    return expected


def _index_actual(results: Dict) -> Dict[str, Dict]:
    actual = {}
    for vuln in results.get("vulnerabilities", []):
        key = f"{vuln.get('type')}|{vuln.get('owasp')}|{vuln.get('severity')}"
        actual[key] = vuln
    return actual


def evaluate(dataset_path: Path, results_path: Path) -> Dict[str, float]:
    dataset = _load_json(dataset_path)
    results_bundle = _load_json(results_path)

    targets = dataset.get("targets", [])
    if not targets:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}

    total_tp = 0
    total_fp = 0
    total_fn = 0

    results_by_url = {r.get("url"): r for r in results_bundle.get("results", [])}

    for target in targets:
        expected = _index_expected(target)
        actual_results = results_by_url.get(target.get("url"), {})
        actual = _index_actual(actual_results)

        expected_keys = set(expected.keys())
        actual_keys = set(actual.keys())

        tp = len(expected_keys & actual_keys)
        fp = len(actual_keys - expected_keys)
        fn = len(expected_keys - actual_keys)

        total_tp += tp
        total_fp += fp
        total_fn += fn

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0.0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "true_positives": total_tp,
        "false_positives": total_fp,
        "false_negatives": total_fn,
    }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate scanner results against a benchmark dataset.")
    parser.add_argument("--dataset", required=True, help="Path to benchmark dataset JSON")
    parser.add_argument("--results", required=True, help="Path to scanner results bundle JSON")
    args = parser.parse_args()

    metrics = evaluate(Path(args.dataset), Path(args.results))
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
