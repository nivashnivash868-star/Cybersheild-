import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from app.schemas import IndicatorDetail, PhishingAnalysisResponse
from app.services import url_features as uf

MESSAGE_TRAINING_PATH = uf.DATA_DIR / "message_training.json"

# Signal groups for message text: (label, severity, points, patterns). Each group scores once.
PRESSURE = re.compile(r"\b(immediately|urgent(ly)?|asap|right now|act now|final (notice|warning)|action required|"
                      r"within \d+ ?(hours?|hrs|minutes|days)|expires? (today|tonight|in \d+)|(closes?|ends?|due) tonight|"
                      r"(account|access|mailbox) (will be )?(suspended|terminated|closed|deleted|restricted|limited|locked|deactivated)|"
                      r"unauthorized activity|temporary hold|restricted access|can'?t wait|before \d+ ?(pm|am))\b", re.I)
SECRECY = re.compile(r"(keep (this|it) (strictly )?(confidential|between us|private)|do not (discuss|tell|share)|don'?t (discuss|tell)|"
                     r"between us|can'?t (talk|call)|cannot (talk|call)|in a (client )?meeting and)", re.I)
CREDENTIAL = re.compile(r"(verify your (account|identity|password)|confirm your (password|identity|account)|"
                        r"(enter|re-?enter|send|reply with|provide|share) (us |me )?(your )?(current |email |login |account )?"
                        r"(password|credentials|username and password|recovery key|otp|one-?time (code|passcode))|"
                        r"(your |email |corporate |work )password to (view|open|access)|sign[- ]?in (with|using) your|"
                        r"log ?in with your|login here|reset your password at|re-?authenticate|sign in to (restore|keep|view)|"
                        r"security question|(two|multi)-?factor settings|confirm it was you)", re.I)
PAYMENT = re.compile(r"(wire( transfer)?|gift ?cards?|(new|updated|changed) (bank|banking) (account|details)|banking details|"
                     r"bank details|routing number|direct deposit|bank account (and|number)|card number|iban|bitcoin|crypto(currency)?|"
                     r"redelivery fee|customs fee|remit(tance)? payment|(send|route|process|pay) (the |all |this )?(transfer|payment|invoice|funds)|"
                     r"w-?2|tax refund|you are owed a refund)", re.I)
EXECUTABLE = re.compile(r"(run the attached|open the attached (file|installer)|attached installer|download the attached|enable (macros|content)|"
                        r"run (it|the (file|installer|update))|install (the )?(attached|update from))", re.I)
LURE = re.compile(r"(voicemail|qr code|scan (this|the) code|undelivered package|package (could not|cannot) be delivered|"
                  r"(won|selected for|claim your) (a |an |your )?(prize|reward|voucher|\$)|congratulations|document has been shared|"
                  r"shared (with you|document)|needs your (microsoft|google|office|account)|mailbox (is )?(almost )?full|"
                  r"exceeded its (limit|quota)|storage quota|unusual sign-?in|suspicious login|compromised|"
                  r"are you (available|at your desk)|favou?r that|need (you )?to (buy|purchase))", re.I)
NEGATION = re.compile(r"(will never ask|never ask for|do not (share|give) your password|if (this )?was (not )?you|no action (is )?needed|"
                      r"if you did not request)", re.I)

# Score bands shared by the URL and message paths.
ALERT_SCORE = 60      # High and above: raise it
SUSPICIOUS_SCORE = 35


class PhishingDetector:
    def __init__(self):
        self._initialize_message_model()
        self.url_model = uf.load_url_model()

    def _initialize_message_model(self):
        """Text classifier for message bodies. Trained on a small labelled corpus (see docs/detection-evaluation.md)."""
        corpus = json.loads(MESSAGE_TRAINING_PATH.read_text())
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1, lowercase=True, sublinear_tf=True)
        X = self.vectorizer.fit_transform([t for t, _ in corpus])
        self.classifier = LogisticRegression(C=3.0, max_iter=500, class_weight="balanced")
        self.classifier.fit(X, [y for _, y in corpus])

    # ------------------------------------------------------------------ URLs

    def score_url(self, raw_url: str) -> Tuple[int, List[IndicatorDetail], dict]:
        """Score one URL as text. The URL is never fetched and no DNS lookup is made."""
        u = uf.ParsedUrl(raw_url)
        indicators: List[IndicatorDetail] = []
        features = {"hostname": u.hostname, "registrable_domain": u.registrable, "path_length": len(u.path),
                    "has_query_params": bool(u.query), "scheme": u.scheme}
        score = 5

        def add(points, category, signal, severity, description):
            nonlocal score
            score += points
            indicators.append(IndicatorDetail(category=category, signal=signal, weight=points, severity=severity, description=description))

        if not u.hostname:
            return 5, [IndicatorDetail(category="Heuristic Evaluation", signal="No host found", weight=0, severity="Low",
                                       description="The text does not contain a recognisable web address.")], features

        rank = uf.popular_domains().get(u.registrable)
        trusted = rank is not None and not u.on_user_content_host
        features.update({"popularity_rank": rank, "on_user_content_host": u.on_user_content_host, "internal_host": bool(u.is_internal)})

        if u.is_internal:
            indicators.append(IndicatorDetail(
                category="Network / Addressing", signal="Internal address", weight=0, severity="Low",
                description="A private, loopback or single-label host. External reputation does not apply; it is only suspicious if it appears where an external address is expected."))
            if u.has_userinfo:
                add(35, "URI Deception", "Embedded '@' Authority Deception", "High", "Text before '@' is read as a username, hiding the real destination host.")
            return min(score, 40), indicators, features

        if u.is_ip:
            add(35, "Network / Addressing", "Raw IP Hostname", "High", "Business portals use registered domain names; a bare IP address is typical of phishing kits.")
        if u.tld in uf.SUSPICIOUS_TLDS:
            add(15, "Domain Architecture", f"Higher-risk TLD (.{u.tld})", "Medium", "This TLD is cheap and heavily used for disposable infrastructure. Many legitimate sites use it too, so it only adds weight.")
        brand = uf.brand_impersonated(u)
        if brand:
            add(45, "Impersonation", f"Brand Squatting ({brand})", "Critical", f"The host names '{brand}' but its registered domain ({u.registrable}) is not one that {brand} uses.")
        else:
            look = uf.lookalike_of(u)
            if look:
                add(35, "Impersonation", f"Look-alike of {look}", "High", f"{u.registrable} is one character or look-alike away from the popular domain {look}.")
        words = uf.credential_words(u)
        if words and not trusted:
            added = min(len(words) * 10, 20)
            add(added, "Intent Pattern", f"Authentication wording in URL ({', '.join(words[:3])})", "Medium", "The address asks for sign-in, verification or account recovery on a site we have no reason to trust.")
        if u.on_user_content_host:
            add(10, "Hosting", "Free page-hosting service", "Low", f"{u.registrable} lets anyone publish a page; most phishing kits use such services, and so do many legitimate projects.")
        if len(u.labels) - len(u.registrable.split(".")) >= 3:
            add(15, "DNS Structure", f"Deeply nested subdomains ({len(u.labels)} labels)", "Medium", "Long subdomain chains push the real domain out of view on mobile address bars.")
        if u.has_userinfo:
            add(35, "URI Deception", "Embedded '@' Authority Deception", "High", "Text before '@' is read as a username, hiding the real destination host.")
        if u.hostname in uf.URL_SHORTENERS:
            add(20, "Redirection", f"Shortened link ({u.hostname})", "Medium", "Shorteners hide the destination.")
        if u.hostname.startswith("xn--") or ".xn--" in u.hostname:
            add(20, "Domain Architecture", "Punycode (internationalised) host", "Medium", "Can render as a look-alike of a familiar name.")
        if u.scheme == "http" and words and not trusted:
            add(15, "Transport Security", "Credential wording over plain HTTP", "Medium", "A sign-in page without HTTPS.")
        if not trusted and uf.host_entropy(u) > 3.4:
            add(10, "Domain Architecture", "Random-looking domain name", "Low", "The registered name looks machine-generated.")

        if self.url_model and not trusted:
            prob = self.url_model.probability(u)
            features["url_model_probability"] = round(prob, 3)
            if prob >= 0.5:
                points = 25 if prob < 0.7 else 40 if prob < 0.9 else 55
                add(points, "Machine Learning Classifier", f"URL model: {int(prob * 100)}% similar to known phishing URLs",
                    "High" if prob >= 0.9 else "Medium",
                    "Character-pattern model trained on a phishing-feed snapshot against popular legitimate sites.")
        if trusted and not u.has_userinfo:
            score = min(score, 25)
            features["capped_as_popular_domain"] = True
        return score, indicators, features

    def analyze_url(self, raw_url: str) -> PhishingAnalysisResponse:
        score, indicators, features = self.score_url(raw_url)
        final_score = min(max(score, 2), 99)
        risk_category = self._score_to_category(final_score)
        return PhishingAnalysisResponse(
            analysis_id=f"TA-URL-{uuid.uuid4().hex[:12].upper()}",
            timestamp=datetime.now(timezone.utc),
            submission_type="url",
            target=raw_url,
            risk_score=final_score,
            risk_category=risk_category,
            detection_engine="URL rules + character n-gram model" if self.url_model else "URL rules (model file missing)",
            indicators=indicators or [IndicatorDetail(
                category="Heuristic Evaluation", signal="Ordinary web address", weight=0, severity="Low",
                description="No deceptive structure, brand misuse or risky pattern found in the address itself.")],
            explanation=self._build_explanation("URL", risk_category, final_score, indicators),
            recommended_precautions=self._build_precautions(risk_category, "url"),
            features_extracted=features,
            reputation_status="Local analysis only: the address is not fetched and no reputation service was asked",
        )

    # --------------------------------------------------------------- messages

    def analyze_message(self, content: str, submission_type: str, email_subject: str = None, sender_info: str = None) -> PhishingAnalysisResponse:
        indicators: List[IndicatorDetail] = []
        combined_text = f"{email_subject or ''} {content}".strip()
        lower_text = combined_text.lower()
        score = 8
        features = {"char_count": len(combined_text), "word_count": len(combined_text.split()), "submission_type": submission_type,
                    "has_subject": bool(email_subject), "has_sender": bool(sender_info)}

        def add(points, category, signal, severity, description):
            nonlocal score
            score += points
            indicators.append(IndicatorDetail(category=category, signal=signal, weight=points, severity=severity, description=description))

        reassured = bool(NEGATION.search(combined_text))
        groups = [
            ("Social Engineering", "Pressure", PRESSURE, 12, "High", "Artificial deadlines or consequences meant to rush the reader."),
            ("Social Engineering", "Secrecy or unavailability", SECRECY, 12, "High", "Asks the reader to keep quiet or not to verify by another channel."),
            ("Credential Harvesting", "Credential request", CREDENTIAL, 0 if reassured else 28, "High", "Directs the reader to hand over or enter authentication details."),
            ("Fraud Pattern (BEC)", "Payment or banking-detail request", PAYMENT, 28, "Critical", "Asks for money, gift cards or a change of payment details."),
            ("Malware Delivery", "Asks the reader to run a file", EXECUTABLE, 40, "Critical", "Asks the reader to open or run an attachment or installer."),
            ("Lure", "Common phishing lure", LURE, 14, "Medium", "Voicemail, QR code, shared-document, prize or account-problem pretext."),
        ]
        hit_groups = 0
        for category, label, pattern, points, severity, description in groups:
            found = sorted({m.group(0).lower() for m in pattern.finditer(combined_text)})
            if found and points:
                hit_groups += 1
                add(points, category, f"{label} ({', '.join(found[:3])})", severity, description)
        if hit_groups >= 3:
            add(10, "Social Engineering", "Several phishing traits together", "High", "Pressure, a request and a pretext in one message is far more typical of fraud than any one alone.")
        features["signal_groups_hit"] = hit_groups

        urls = re.findall(r"(?:https?://|www\.)[^\s<>\"')]+", combined_text)[:10]
        features["embedded_urls_count"] = len(urls)
        if urls:
            results = [self.score_url(u) for u in urls]
            worst_score, worst_ind, _ = max(results, key=lambda r: r[0])
            worst = urls[results.index(max(results, key=lambda r: r[0]))]
            features["worst_embedded_url"] = worst
            features["worst_embedded_url_score"] = worst_score
            if worst_score >= ALERT_SCORE:
                add(55, "Embedded Links", f"Link scored {worst_score}/100 ({worst_ind[0].signal})" if worst_ind else "High-risk link", "Critical",
                    f"The message links to {worst}, which looks like a phishing address.")
            elif worst_score >= SUSPICIOUS_SCORE:
                add(15, "Embedded Links", f"Link scored {worst_score}/100", "Medium", f"The message links to {worst}, which has suspicious traits.")
            else:
                add(3, "Embedded Links", f"{len(urls)} link(s), none suspicious", "Low", "Links were checked as text; none looks deceptive.")

        prob = float(self.classifier.predict_proba(self.vectorizer.transform([combined_text]))[0][1])
        features["ml_phishing_probability"] = round(prob, 3)
        if prob > 0.6:
            add(int(prob * 30), "Machine Learning Classifier", f"Text model: {int(prob * 100)}% similar to known phishing wording",
                "High" if prob > 0.8 else "Medium", "Word-pattern model trained on a small labelled message set; treat as a supporting signal.")

        final_score = min(max(score, 3), 99)
        risk_category = self._score_to_category(final_score)
        return PhishingAnalysisResponse(
            analysis_id=f"TA-MSG-{uuid.uuid4().hex[:12].upper()}",
            timestamp=datetime.now(timezone.utc),
            submission_type=submission_type,
            target=(email_subject or content[:60] + "..."),
            risk_score=final_score,
            risk_category=risk_category,
            detection_engine="Message rules + link analysis + word-pattern model",
            indicators=indicators or [IndicatorDetail(
                category="Heuristic Evaluation", signal="Ordinary message", weight=0, severity="Low",
                description="No pressure, payment request, credential request or suspicious link found.")],
            explanation=self._build_explanation("Message", risk_category, final_score, indicators),
            recommended_precautions=self._build_precautions(risk_category, submission_type),
            features_extracted=features,
            reputation_status="Local analysis only: no reputation service was asked",
        )

    def _score_to_category(self, score: int) -> str:
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 35:
            return "Medium"
        return "Low"

    def _build_explanation(self, target_type: str, category: str, score: int, indicators: List[IndicatorDetail]) -> str:
        if category in ("Critical", "High"):
            reasons = "; ".join([ind.signal for ind in indicators[:3]])
            return (
                f"{target_type} evaluated as {category} Risk (Score: {score}/100). "
                f"Primary detection triggers include: {reasons}. "
                "Significant risk of credential theft, session interception, or financial fraud."
            )
        elif category == "Medium":
            return (
                f"{target_type} scored as Medium Risk (Score: {score}/100). "
                "Contains suspicious traits or keywords that warrant caution, but lacks conclusive indicators of malicious intent."
            )
        else:
            return (
                f"{target_type} evaluated as Low Risk (Score: {score}/100). "
                "No overt malicious indicators or deceptive structures found. "
                "Note: Static inspection cannot guarantee 100% absence of novel zero-day threats."
            )

    def _build_precautions(self, category: str, sub_type: str) -> List[str]:
        if category in ("Critical", "High"):
            return [
                "DO NOT click hyperlinks, open attachments, or input passwords on the linked portal.",
                "Block the sender IP and domain at the mail exchange / web proxy boundary.",
                "Purge matching messages from all corporate user inboxes via SOC response workflow.",
                "If credentials were submitted by a user, immediately invalidate active sessions and initiate password rotation.",
                "Report target infrastructure to registrar abuse desks and upstream threat intelligence feeds."
            ]
        elif category == "Medium":
            return [
                "Verify the sender identity through a secondary, trusted out-of-band communication channel (e.g., phone call).",
                "Inspect full email headers for SPF, DKIM, and DMARC alignment failures.",
                "Open links only inside an isolated browser sandbox environment if business verification is mandatory."
            ]
        else:
            return [
                "Standard operational caution: Continue monitoring for anomalous recipient behavior.",
                "Always verify URL destinations before supplying organizational credentials."
            ]

phishing_detector = PhishingDetector()
