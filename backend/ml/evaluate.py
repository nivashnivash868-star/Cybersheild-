"""Measures the detectors and prints the numbers reported in docs/detection-evaluation.md.

    python -m ml.evaluate --data <folder from ml.train_url_model> [--benign-files <folder of ordinary files>]

URL numbers use the model trained WITHOUT the held-out domains (model_holdout.json), so they describe unseen data.
"""
import argparse
import json
import math
from pathlib import Path

from app.services.phishing_engine import ALERT_SCORE, SUSPICIOUS_SCORE, PhishingDetector
from app.services.url_features import UrlModel
from ml.datasets import BUCKETS
from ml.message_corpora import BLIND, EVAL


def auc(pos, neg):
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def pct(a, b):
    return f"{100 * a / b:.1f}%" if b else "n/a"


def evaluate_urls(data: Path):
    holdout = json.loads((data / "holdout.json").read_text())
    m = json.loads((data / "model_holdout.json").read_text())
    det = PhishingDetector()
    det.url_model = UrlModel(m["weights"], m["intercept"], {})

    phish = [det.score_url(u)[0] for u in holdout["phishing"]]
    out = {"phishing_held_out": len(phish),
           "recall_alert": pct(sum(s >= ALERT_SCORE for s in phish), len(phish)),
           "recall_suspicious": pct(sum(s >= SUSPICIOUS_SCORE for s in phish), len(phish))}
    benign_scores = [(det.score_url(r["url"])[0], r["bucket"]) for r in holdout["benign"]]
    out["benign_held_out"] = len(benign_scores)
    out["buckets"] = {}
    for b, (lo, hi) in enumerate(BUCKETS):
        s = [x for x, bb in benign_scores if bb == b]
        out["buckets"][f"rank {lo:,}-{hi:,}"] = {
            "n": len(s), "false_alert": pct(sum(x >= ALERT_SCORE for x in s), len(s)),
            "false_suspicious": pct(sum(x >= SUSPICIOUS_SCORE for x in s), len(s))}
    lo_tail = [x for x, bb in benign_scores if bb >= 2]
    out["auc_rules_plus_model"] = round(auc(phish, [x for x, _ in benign_scores]), 4)
    probs_p = [det.url_model.probability(__import__("app.services.url_features", fromlist=["x"]).ParsedUrl(u)) for u in holdout["phishing"]]
    probs_n = [det.url_model.probability(__import__("app.services.url_features", fromlist=["x"]).ParsedUrl(r["url"])) for r in holdout["benign"]]
    out["auc_model_only"] = round(auc(probs_p, probs_n), 4)
    out["false_alert_unpopular_domains"] = pct(sum(x >= ALERT_SCORE for x in lo_tail), len(lo_tail))
    return out


def evaluate_messages():
    det = PhishingDetector()
    rows = [(det.analyze_message(t, "email").risk_score, y, t) for t, y in EVAL]
    out = {"n": len(rows), "phishing": sum(y for _, y, _ in rows)}
    for name, thr in (("alert", ALERT_SCORE), ("suspicious", SUSPICIOUS_SCORE)):
        tp = sum(s >= thr and y for s, y, _ in rows)
        fp = sum(s >= thr and not y for s, y, _ in rows)
        fn = sum(s < thr and y for s, y, _ in rows)
        out[name] = {"recall": pct(tp, tp + fn), "precision": pct(tp, tp + fp), "false_positives": fp, "missed": fn}
    out["missed_texts"] = [t[:90] for s, y, t in rows if y and s < ALERT_SCORE]
    out["false_alert_texts"] = [t[:90] for s, y, t in rows if not y and s >= ALERT_SCORE]
    out["auc"] = round(auc([s for s, y, _ in rows if y], [s for s, y, _ in rows if not y]), 4)
    blind = [(det.analyze_message(t, "email").risk_score, y) for t, y in BLIND]
    out["blind_set"] = {"n": len(blind), "correct_at_suspicious_threshold": sum((s >= SUSPICIOUS_SCORE) == bool(y) for s, y in blind)}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--benign-files")
    args = ap.parse_args()
    report = {"urls": evaluate_urls(Path(args.data)), "messages": evaluate_messages()}
    try:
        from ml.evaluate_files import evaluate_files
        report["files"] = evaluate_files(Path(args.benign_files) if args.benign_files else None)
    except ImportError:
        pass
    try:
        from ml.evaluate_network import evaluate_network
        report["network"] = evaluate_network()
    except ImportError:
        pass
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
