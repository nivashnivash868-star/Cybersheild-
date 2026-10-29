"""Trains the URL model (character n-gram logistic regression) and writes app/detection_data/url_model.json.

    python -m ml.train_url_model --data <folder with openphish.txt and tranco_all.csv>

Two models are fitted: one on a domain-grouped 80% split (used by ml.evaluate to measure unseen data) and the shipped
one on everything. The held-out split is written next to the model so the evaluation is reproducible.
"""
import argparse
import json
import random
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression

from app.services.url_features import ParsedUrl, char_ngrams
from ml.datasets import benign_urls, group_of, load_phishing, load_tranco

APP_DATA = Path(__file__).resolve().parent.parent / "app" / "detection_data"
HOLDOUT_FRACTION = 0.2


def split_by_group(items, key, seed, fraction=HOLDOUT_FRACTION):
    groups = sorted({key(i) for i in items})
    random.Random(seed).shuffle(groups)
    held = set(groups[: int(len(groups) * fraction)])
    return [i for i in items if key(i) not in held], [i for i in items if key(i) in held]


def fit(urls, labels, min_df=3, C=0.5):
    vec = CountVectorizer(analyzer=lambda t: char_ngrams(t), binary=True, min_df=min_df)
    texts = [ParsedUrl(u).model_text() for u in urls]
    X = vec.fit_transform(texts)
    clf = LogisticRegression(C=C, max_iter=2000, class_weight="balanced")
    clf.fit(X, labels)
    weights = {g: round(float(w), 4) for g, w in zip(vec.get_feature_names_out(), clf.coef_[0]) if abs(w) > 0.05}
    return weights, float(clf.intercept_[0])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--per-bucket", type=int, default=1500)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    data = Path(args.data)

    phish = load_phishing(data / "openphish.txt")
    benign = benign_urls(load_tranco(data / "tranco_all.csv"), args.per_bucket, args.seed)
    print(f"phishing URLs: {len(phish)} | benign URLs: {len(benign)}")

    p_train, p_test = split_by_group(phish, group_of, args.seed)
    b_train, b_test = split_by_group(benign, lambda r: r[1], args.seed)
    print(f"train: {len(p_train)} phishing / {len(b_train)} benign | held out: {len(p_test)} / {len(b_test)}")

    holdout = {"phishing": p_test, "benign": [{"url": u, "domain": d, "bucket": b} for u, d, b in b_test]}
    (data / "holdout.json").write_text(json.dumps(holdout))
    w, b = fit(p_train + [r[0] for r in b_train], [1] * len(p_train) + [0] * len(b_train))
    (data / "model_holdout.json").write_text(json.dumps({"weights": w, "intercept": b}))

    w, b = fit(phish + [r[0] for r in benign], [1] * len(phish) + [0] * len(benign))
    meta = {"trained_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "phishing_urls": len(phish),
            "benign_urls": len(benign), "features": len(w), "source_phishing": "OpenPhish community feed snapshot",
            "source_benign": "Tranco top-1M, sampled across four popularity buckets"}
    (APP_DATA / "url_model.json").write_text(json.dumps({"weights": w, "intercept": b, "meta": meta}, separators=(",", ":")))
    print(f"shipped model: {len(w)} features -> app/detection_data/url_model.json")


if __name__ == "__main__":
    main()
