"""URL parsing, domain reputation context and the learned URL model.

Nothing here touches the network: a submitted URL is only ever analysed as text.

The learned part is a logistic regression over character n-grams. It is stored as plain JSON (vocabulary -> weight), so
there is no pickle to load and no dependence on the scikit-learn version that trained it. Training and evaluation live
in backend/ml/ and docs/detection-evaluation.md reports how well it does.
"""
import json
import math
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple
from urllib.parse import urlparse

DATA_DIR = Path(__file__).resolve().parent.parent / "detection_data"
URL_MODEL_PATH = DATA_DIR / "url_model.json"
POPULAR_DOMAINS_PATH = DATA_DIR / "popular_domains.txt"

# Hosts where anybody can publish a page under a subdomain. A popular parent domain says nothing about the page.
USER_CONTENT_SUFFIXES: FrozenSet[str] = frozenset({
    "pages.dev", "workers.dev", "r2.dev", "vercel.app", "netlify.app", "github.io", "gitlab.io", "blogspot.com",
    "herokuapp.com", "web.app", "firebaseapp.com", "azurewebsites.net", "azurestaticapps.net", "weebly.com",
    "wixsite.com", "square.site", "glitch.me", "repl.co", "onrender.com", "myshopify.com", "webflow.io",
    "framer.app", "framer.website", "appspot.com", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "duckdns.org",
    "no-ip.org", "dynu.net", "000webhostapp.com", "wordpress.com", "godaddysites.com", "mystrikingly.com",
    "sites.google.com", "s3.amazonaws.com", "cloudfront.net", "storage.googleapis.com", "web.core.windows.net",
    "typedream.app", "carrd.co", "notion.site", "canva.site", "wixstudio.io", "link.storjshare.io",
})
SECOND_LEVEL_LABELS = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil"}
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "work", "loan", "club", "icu", "cam", "monster", "rest", "fit",
    "click", "link", "support", "zip", "mov", "cyou", "sbs", "cfd", "lol",
}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc"}

# Brand -> registrable domains the brand really uses. A brand name anywhere else in a host is impersonation.
OFFICIAL_DOMAINS: Dict[str, Tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me", "paypal.com.au", "paypal.co.uk"),
    "microsoft": ("microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com", "outlook.com",
                  "sharepoint.com", "azure.com", "msn.com", "bing.com", "skype.com", "onedrive.com", "windows.com",
                  "xbox.com", "azure.net", "windows.net", "microsoft365.com"),
    "office365": ("office365.com", "office.com", "microsoft.com"),
    "outlook": ("outlook.com", "office.com", "microsoft.com", "live.com"),
    "sharepoint": ("sharepoint.com", "microsoft.com"),
    "google": ("google.com", "gmail.com", "googleapis.com", "youtube.com", "gstatic.com", "googleusercontent.com",
               "goo.gl", "withgoogle.com", "google.org", "googlemail.com", "google.co.uk", "google.de", "google.co.in"),
    "apple": ("apple.com", "icloud.com", "me.com"),
    "netflix": ("netflix.com", "nflxext.com", "nflximg.net", "nflxso.net", "nflxvideo.net"),
    "amazon": ("amazon.com", "amazonaws.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazon.fr", "amazon.ca",
               "amazon.co.jp", "amazon.es", "amazon.it", "amazon.com.au", "amazon.jobs", "amazon.dev"),
    "chase": ("chase.com", "jpmorganchase.com", "jpmorgan.com"),
    "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com", "bofa.com"),
    "citibank": ("citibank.com", "citi.com"),
    "dhl": ("dhl.com", "dhl.de", "dhl.co.uk", "dhl.fr", "dhl.nl"),
    "fedex": ("fedex.com",),
    "usps": ("usps.com",),
    "irs": ("irs.gov",),
    "binance": ("binance.com", "binance.us"),
    "coinbase": ("coinbase.com",),
    "metamask": ("metamask.io",),
    "docusign": ("docusign.com", "docusign.net"),
    "dropbox": ("dropbox.com", "dropboxusercontent.com"),
    "linkedin": ("linkedin.com", "licdn.com"),
    "facebook": ("facebook.com", "fb.com", "fbcdn.net", "meta.com"),
    "instagram": ("instagram.com", "cdninstagram.com"),
    "whatsapp": ("whatsapp.com", "whatsapp.net"),
    "adobe": ("adobe.com", "adobe.io", "adobelogin.com"),
    "ups": ("ups.com",),
    "dpd": ("dpd.com", "dpd.co.uk", "dpd.de", "dpd.fr", "dpdgroup.com"),
}
# Brands this short are only matched as a whole word, never as a fragment ("firstbank" is not "irs").
SHORT_BRAND_LIMIT = 5
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
PRIVATE_V4 = re.compile(r"^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.)")
CREDENTIAL_WORDS = ("login", "signin", "sign-in", "verify", "secure", "account", "update", "banking", "authenticate",
                    "password", "credential", "portal", "confirm", "webmail", "unlock", "suspend", "recover")


class ParsedUrl:
    """A URL taken apart for scoring. Never fetched."""

    def __init__(self, raw: str):
        raw = (raw or "").strip()
        cleaned = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else "http://" + raw
        try:
            p = urlparse(cleaned)
            self.hostname = (p.hostname or "").lower().rstrip(".")
        except ValueError:
            p, self.hostname = urlparse("http://invalid"), ""
        self.raw = raw
        self.scheme = (p.scheme or "http").lower()
        self.path = p.path or ""
        self.query = p.query or ""
        self.has_userinfo = "@" in (p.netloc or "")
        self.is_ip = bool(IPV4.match(self.hostname))
        self.is_internal = self.is_ip and bool(PRIVATE_V4.match(self.hostname)) or self._internal_name()
        self.registrable = registrable_domain(self.hostname)
        self.labels = self.hostname.split(".") if self.hostname else []
        self.tld = self.labels[-1] if self.labels else ""

    def _internal_name(self) -> bool:
        h = self.hostname
        return bool(h) and ("." not in h or h.endswith((".local", ".internal", ".lan", ".corp", ".intranet", ".home.arpa"))
                            or h == "localhost")

    @property
    def on_user_content_host(self) -> bool:
        return any(self.hostname == s or self.hostname.endswith("." + s) for s in USER_CONTENT_SUFFIXES)

    def model_text(self) -> str:
        return f"{self.hostname}{self.path}{('?' + self.query) if self.query else ''}"[:300].lower()


def registrable_domain(host: str) -> str:
    """Registered domain without needing the public-suffix list: handles co.uk-style suffixes and free-hosting parents."""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    for n in (3, 2):
        suffix = ".".join(parts[-n:])
        if suffix in USER_CONTENT_SUFFIXES and len(parts) > n:
            return ".".join(parts[-(n + 1):])
    if len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL_LABELS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


@lru_cache(maxsize=1)
def popular_domains() -> Dict[str, int]:
    """Domain -> rank for the 20,000 most visited registrable domains (Tranco list, see docs/detection-evaluation.md)."""
    try:
        return {d: i + 1 for i, d in enumerate(POPULAR_DOMAINS_PATH.read_text().split())}
    except OSError:
        return {}


@lru_cache(maxsize=1)
def _popular_by_label_length() -> Dict[int, List[str]]:
    out: Dict[int, List[str]] = {}
    for d in list(popular_domains())[:5000]:
        sld = d.split(".")[0]
        if len(sld) >= 6:
            out.setdefault(len(sld), []).append(d)
    return out


def _edit_distance_at_most_one(a: str, b: str) -> bool:
    if a == b:
        return False
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1 or any(
            a[i] == b[i + 1] and a[i + 1] == b[i] and a[:i] == b[:i] and a[i + 2:] == b[i + 2:] for i in range(len(a) - 1))
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return any(long_[:i] + long_[i + 1:] == short for i in range(len(long_)))


def lookalike_of(parsed: ParsedUrl) -> Optional[str]:
    """A popular domain this one is one typo or one look-alike character away from (paypa1.com, gooogle.com)."""
    reg = parsed.registrable
    if not reg or reg in popular_domains() or parsed.on_user_content_host:
        return None
    sld = reg.split(".")[0]
    if len(sld) < 6:
        return None
    normal = sld.translate(LEET).replace("rn", "m").replace("vv", "w")
    for length in (len(sld) - 1, len(sld), len(sld) + 1):
        for domain in _popular_by_label_length().get(length, ()):
            target = domain.split(".")[0]
            if normal == target or _edit_distance_at_most_one(sld, target):
                return domain
    return None


def brand_impersonated(parsed: ParsedUrl) -> Optional[str]:
    """A brand named in the host where the registrable domain is not one the brand owns."""
    if not parsed.hostname or parsed.is_ip:
        return None
    host = parsed.hostname.translate(LEET)
    tokens = set(re.split(r"[.\-_]", host))
    for brand, official in OFFICIAL_DOMAINS.items():
        named = brand in tokens if len(brand) <= SHORT_BRAND_LIMIT else any(brand in label for label in host.split("."))
        if not named:
            continue
        if parsed.registrable in official and not parsed.on_user_content_host:
            continue
        if brand == "amazon" and re.match(r"^amazon\.[a-z.]+$", parsed.registrable):
            continue
        return brand
    return None


def credential_words(parsed: ParsedUrl) -> List[str]:
    text = (parsed.hostname + parsed.path + parsed.query).lower()
    return [w for w in CREDENTIAL_WORDS if w in text]


def host_entropy(parsed: ParsedUrl) -> float:
    label = parsed.labels[-3] if len(parsed.labels) >= 3 else (parsed.labels[0] if parsed.labels else "")
    label = parsed.registrable.split(".")[0] if parsed.registrable else label
    if len(label) < 8:
        return 0.0
    counts = {c: label.count(c) for c in set(label)}
    return -sum(n / len(label) * math.log2(n / len(label)) for n in counts.values())


# ---------------------------------------------------------------------------- learned model


def char_ngrams(text: str, low: int = 3, high: int = 5) -> Set[str]:
    padded = f"^{text}$"
    return {padded[i:i + n] for n in range(low, high + 1) for i in range(len(padded) - n + 1)}


class UrlModel:
    """Logistic regression over binary character n-grams, loaded from JSON."""

    def __init__(self, weights: Dict[str, float], intercept: float, meta: Dict):
        self.weights, self.intercept, self.meta = weights, intercept, meta

    def probability(self, parsed: ParsedUrl) -> float:
        z = self.intercept + sum(self.weights.get(g, 0.0) for g in char_ngrams(parsed.model_text()))
        return 1.0 / (1.0 + math.exp(-max(min(z, 30.0), -30.0)))


@lru_cache(maxsize=1)
def load_url_model() -> Optional[UrlModel]:
    try:
        data = json.loads(URL_MODEL_PATH.read_text())
        return UrlModel(data["weights"], float(data["intercept"]), data.get("meta", {}))
    except (OSError, ValueError, KeyError):
        return None
