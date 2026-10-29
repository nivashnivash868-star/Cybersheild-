"""Loads the URL training/evaluation data and builds the benign side.

Phishing: an OpenPhish community-feed snapshot (plain text, one URL per line).
Benign:   registrable domains sampled from the Tranco top-1M list across popularity buckets, each turned into a URL
          with and without a path. The paths are ordinary site paths, including login-style ones, because a real
          benign population contains them; a model must not learn "has /login" or "has a path" as "phishing".

Both files are treated as text. Nothing here is fetched or executed.
Usage: place openphish.txt and tranco_all.csv (rank,domain) in a folder and pass it with --data.
"""
import random
from pathlib import Path
from typing import List, Tuple

from app.services.url_features import ParsedUrl

BUCKETS = [(1, 1_000), (1_001, 10_000), (10_001, 100_000), (100_001, 1_000_000)]
BENIGN_PATHS = ["", "", "/", "/login", "/signin", "/account", "/account/security", "/support/contact", "/en/about",
                "/products/item-2231", "/blog/2026/quarterly-update", "/search?q=pricing", "/help/password-reset",
                "/docs/getting-started", "/careers", "/news/article/1048213", "/user/profile/settings", "/cart",
                "/wp-login.php", "/webmail", "/portal", "/verify-email?token=abc123", "/index.html", "/downloads"]
SUBDOMAINS = ["", "", "", "www.", "www.", "accounts.", "login.", "mail.", "secure.", "my.", "app.", "support.", "shop."]


def load_phishing(path: Path) -> List[str]:
    return sorted({l.strip() for l in path.read_text(errors="ignore").splitlines() if l.strip().startswith("http")})


def load_tranco(path: Path) -> List[Tuple[int, str]]:
    rows = []
    for line in path.read_text(errors="ignore").splitlines():
        rank, _, domain = line.partition(",")
        if rank.isdigit() and domain:
            rows.append((int(rank), domain.strip().lower()))
    return rows


def benign_urls(tranco: List[Tuple[int, str]], per_bucket: int, seed: int) -> List[Tuple[str, str, int]]:
    """(url, registrable domain, bucket index) with per_bucket domains drawn from each popularity bucket."""
    rng = random.Random(seed)
    out = []
    for b, (lo, hi) in enumerate(BUCKETS):
        pool = [d for r, d in tranco if lo <= r <= hi]
        for domain in rng.sample(pool, min(per_bucket, len(pool))):
            scheme = "https" if rng.random() < 0.9 else "http"
            out.append((f"{scheme}://{rng.choice(SUBDOMAINS)}{domain}{rng.choice(BENIGN_PATHS)}", domain, b))
    return out


def group_of(url: str) -> str:
    """Phishing URLs from one kit/host share a registrable domain; keep them on one side of a split."""
    return ParsedUrl(url).registrable
