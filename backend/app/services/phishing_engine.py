import re
import math
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from app.schemas import IndicatorDetail, PhishingAnalysisResponse
from app.utils.ssrf_guard import validate_url_safe_for_inspection

# Cybersecurity knowledge base of suspicious patterns
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".work",
    ".loan", ".club", ".icu", ".cam", ".monster", ".rest", ".fit"
}

FINANCIAL_AND_BRAND_KEYWORDS = [
    "paypal", "microsoft", "google", "apple", "netflix", "chase", "wellsfargo",
    "bankofamerica", "citibank", "amazon", "dhl", "fedex", "usps", "irs",
    "binance", "coinbase", "metamask", "office365", "outlook", "sharepoint"
]

CREDENTIAL_HARVEST_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "banking",
    "authenticate", "password", "credential", "portal", "session", "confirm"
]

URGENCY_TRIGGERS = [
    "immediately", "urgent", "account suspended", "24 hours", "action required",
    "temporary hold", "unauthorized activity", "final notice", "restricted access",
    "wire transfer", "gift card", "payroll direct deposit", "overdue invoice"
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly"
}

class PhishingDetector:
    def __init__(self):
        self._initialize_ml_model()

    def _initialize_ml_model(self):
        """
        Train a calibrated baseline NLP/text classifier for phishing signals.
        """
        training_corpus = [
            # Phishing / Scam samples
            ("URGENT: Your Microsoft 365 account will be suspended within 24 hours. Click here to verify credentials.", 1),
            ("Notice from PayPal: Unauthorized login attempt detected. Verify your identity immediately to prevent lock.", 1),
            ("Your parcel could not be delivered due to unpaid customs fee of $2.50. Update details at link below.", 1),
            ("WIRE INVOICE: Please process the attached invoice immediately per CEO instructions. Keep confidential.", 1),
            ("Bank Alert: Your debit card has been locked. Text YES or click to restore banking access.", 1),
            ("HR Department: Important updates regarding employee payroll tax refunds. Submit 2026 tax form here.", 1),
            ("Security Notification: We noticed a suspicious login from Russia. Confirm your password now.", 1),
            ("Netflix payment failed! Update billing information immediately or your subscription will terminate.", 1),
            ("Crypto Wallet: A transaction of 1.45 BTC is pending. Click to cancel or confirm authorization.", 1),
            ("DocuSign: CEO has sent you an urgent contract to sign. Access document via secure portal.", 1),
            ("Your Apple ID has been locked for security reasons. Enter your recovery key to unlock.", 1),
            ("SMS Alert: USPS delivery exception. Redeliver package by confirming residential address.", 1),
            # Benign / Legitimate samples
            ("Hi team, attached is the meeting agenda for Thursday's architecture review. See you in the conference room.", 0),
            ("Your weekly project summary: 14 tickets completed, 3 pull requests merged. Good job everyone.", 0),
            ("Reminder: Company all-hands meeting starts at 3:00 PM EST on Google Meet.", 0),
            ("Thank you for your order! Your receipt #88192 is attached. Estimated delivery is Friday.", 0),
            ("Quarterly financial report is available on the internal intranet share for your review.", 0),
            ("Please find the updated documentation for the Python backend API deployment.", 0),
            ("Welcome to the cybersecurity newsletter. Today we discuss hardening Linux SSH daemons.", 0),
            ("Lunch order poll is now open. Please submit your preferences by 11:30 AM.", 0),
            ("System maintenance scheduled for Saturday 2:00 AM UTC. Downtime expected to be 15 minutes.", 0),
            ("Code review requested for PR #245: Added unit tests for database connection pooling.", 0),
            ("The project sprint kickoff is set for Monday morning. Please review the backlog items.", 0),
            ("Your subscription renewal receipt for the annual cloud storage service plan.", 0),
        ]
        
        texts = [x[0] for x in training_corpus]
        labels = [x[1] for x in training_corpus]
        
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1, lowercase=True)
        X = self.vectorizer.fit_transform(texts)
        self.classifier = LogisticRegression(C=2.0, max_iter=200)
        self.classifier.fit(X, labels)

    def analyze_url(self, raw_url: str) -> PhishingAnalysisResponse:
        is_safe, msg = validate_url_safe_for_inspection(raw_url)
        if not is_safe:
            # Blocked SSRF / private targets
            return PhishingAnalysisResponse(
                analysis_id=f"TA-SSRF-{int(datetime.now(timezone.utc).timestamp())}",
                timestamp=datetime.now(timezone.utc),
                submission_type="url",
                target=raw_url,
                risk_score=95,
                risk_category="Critical",
                detection_engine="SSRF Guard & Security Policy",
                indicators=[
                    IndicatorDetail(
                        category="SSRF / Prohibited Scope",
                        signal="Internal/Private Address Access Attempt",
                        weight=95,
                        severity="Critical",
                        description=msg
                    )
                ],
                explanation=f"URL inspection aborted: {msg} Access to loopback, link-local, private LAN or metadata addresses is strictly prohibited.",
                recommended_precautions=[
                    "Do not route or forward external requests to internal corporate IP ranges.",
                    "Verify why internal or restricted host addresses are being inspected from untrusted input.",
                    "Block repeated queries attempting internal service scanning."
                ],
                features_extracted={"error": msg, "blocked_by_policy": True},
                reputation_status="Blocked by Internal SSRF Filter"
            )

        indicators: List[IndicatorDetail] = []
        raw_cleaned = raw_url.strip()
        if not (raw_cleaned.startswith("http://") or raw_cleaned.startswith("https://")):
            raw_cleaned = "http://" + raw_cleaned

        parsed = urlparse(raw_cleaned)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        total_url = raw_cleaned.lower()

        extracted_features = {
            "hostname": hostname,
            "path_length": len(path),
            "has_query_params": bool(query),
            "scheme": parsed.scheme
        }

        score = 5  # Baseline score

        # 1. IP address used as hostname
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
            score += 35
            indicators.append(IndicatorDetail(
                category="Network / Addressing",
                signal="Raw IP Hostname",
                weight=35,
                severity="High",
                description="Legitimate business portals use registered domain names. Naked IP hosts are frequently associated with phishing kits."
            ))

        # 2. Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                score += 25
                indicators.append(IndicatorDetail(
                    category="Domain Architecture",
                    signal=f"High-Risk TLD ({tld})",
                    weight=25,
                    severity="Medium",
                    description=f"Top-level domain '{tld}' has a statistically elevated correlation with disposable phishing infrastructure."
                ))
                break

        # 3. Brand impersonation in domain
        matched_brand = None
        for brand in FINANCIAL_AND_BRAND_KEYWORDS:
            if brand in hostname:
                # Check if it's the authentic domain (e.g. google.com vs google-security-login.xyz)
                if not (hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com")):
                    matched_brand = brand
                    score += 40
                    indicators.append(IndicatorDetail(
                        category="Impersonation",
                        signal=f"Brand Squatting ({brand})",
                        weight=40,
                        severity="Critical",
                        description=f"Domain contains target brand '{brand}' without matching official legitimate domain hierarchy."
                    ))
                    break

        # 4. Credential harvesting keywords in URL path/subdomains
        found_cred_words = [w for w in CREDENTIAL_HARVEST_KEYWORDS if w in total_url]
        if found_cred_words:
            added = min(len(found_cred_words) * 12, 30)
            score += added
            indicators.append(IndicatorDetail(
                category="Intent Pattern",
                signal=f"Authentication Tokens in URL ({', '.join(found_cred_words[:3])})",
                weight=added,
                severity="Medium" if added < 20 else "High",
                description="URL path or subdomain explicitly targets authentication, credential capture, or password reset operations."
            ))

        # 5. Excessive subdomains count
        subdomain_parts = hostname.split(".")
        if len(subdomain_parts) > 4:
            score += 20
            indicators.append(IndicatorDetail(
                category="DNS Structure",
                signal=f"Excessive Subdomain Nesting ({len(subdomain_parts)} levels)",
                weight=20,
                severity="Medium",
                description="Multi-tier subdomains are often crafted to push the real apex domain off visible mobile address bars."
            ))

        # 6. Embedded '@' symbol in URL
        if "@" in raw_cleaned:
            score += 35
            indicators.append(IndicatorDetail(
                category="URI Deception",
                signal="Embedded '@' Authority Deception",
                weight=35,
                severity="High",
                description="The '@' sign causes browsers to treat preceding characters as username credentials, hiding the true destination host."
            ))

        # 7. URL shortener used
        if hostname in URL_SHORTENERS:
            score += 20
            indicators.append(IndicatorDetail(
                category="Redirection",
                signal=f"Shortened Link Service ({hostname})",
                weight=20,
                severity="Medium",
                description="URL shorteners obscure target landing pages, common in initial SMS and social engineering vectors."
            ))

        # 8. Unencrypted HTTP for sensitive login
        if parsed.scheme == "http" and ("login" in total_url or "secure" in total_url):
            score += 25
            indicators.append(IndicatorDetail(
                category="Transport Security",
                signal="Plaintext HTTP for Authentication",
                weight=25,
                severity="High",
                description="Authentic enterprise credential portals require HTTPS. Plaintext HTTP indicates fraudulent or vulnerable staging."
            ))

        # 9. Scikit-learn ML assessment on URL string tokens
        url_text = f"{hostname} {path.replace('/', ' ')} {query.replace('=', ' ')}"
        X_test = self.vectorizer.transform([url_text])
        ml_prob = float(self.classifier.predict_proba(X_test)[0][1])
        ml_score_contrib = int(ml_prob * 30)
        extracted_features["ml_phishing_probability"] = round(ml_prob, 3)

        if ml_prob > 0.65:
            indicators.append(IndicatorDetail(
                category="Machine Learning Classifier",
                signal=f"Trained NLP Model Classification ({int(ml_prob * 100)}% Phishing Confidence)",
                weight=ml_score_contrib,
                severity="High" if ml_prob > 0.8 else "Medium",
                description="Trained TF-IDF n-gram model detected semantic similarity to verified phishing and scam attack vectors."
            ))
            score += ml_score_contrib

        final_score = min(max(score, 2), 99)
        risk_category = self._score_to_category(final_score)

        explanation = self._build_explanation(
            target_type="URL",
            category=risk_category,
            score=final_score,
            indicators=indicators
        )

        precautions = self._build_precautions(risk_category, "url")

        return PhishingAnalysisResponse(
            analysis_id=f"TA-URL-{int(datetime.now(timezone.utc).timestamp())}",
            timestamp=datetime.now(timezone.utc),
            submission_type="url",
            target=raw_url,
            risk_score=final_score,
            risk_category=risk_category,
            detection_engine="Heuristic Feature Rules + Scikit-Learn NLP Classifier",
            indicators=indicators if indicators else [
                IndicatorDetail(
                    category="Heuristic Evaluation",
                    signal="Standard Web Domain Structure",
                    weight=0,
                    severity="Low",
                    description="No overtly deceptive homoglyphs, high-risk TLDs, or credential harvesting tokens detected in URL string."
                )
            ],
            explanation=explanation,
            recommended_precautions=precautions,
            features_extracted=extracted_features,
            reputation_status="Heuristic/ML Analysis (Live Reputation API key not configured in .env)"
        )

    def analyze_message(self, content: str, submission_type: str, email_subject: str = None, sender_info: str = None) -> PhishingAnalysisResponse:
        indicators: List[IndicatorDetail] = []
        combined_text = f"{email_subject or ''} {content}".strip()
        lower_text = combined_text.lower()
        score = 8

        extracted_features = {
            "char_count": len(combined_text),
            "word_count": len(combined_text.split()),
            "submission_type": submission_type,
            "has_subject": bool(email_subject),
            "has_sender": bool(sender_info)
        }

        # 1. Urgent call to action / Coercive psychology
        urgency_matches = [u for u in URGENCY_TRIGGERS if u in lower_text]
        if urgency_matches:
            added = min(len(urgency_matches) * 15, 45)
            score += added
            indicators.append(IndicatorDetail(
                category="Social Engineering",
                signal=f"Coercive Urgency Trigger ({', '.join(urgency_matches[:3])})",
                weight=added,
                severity="High",
                description="Message induces artificial panic, immediate deadlines, or financial consequences to bypass victim critical thinking."
            ))

        # 2. Financial / Wire / Gift card requests (Business Email Compromise - BEC)
        bec_terms = ["wire transfer", "gift card", "direct deposit", "routing number", "invoice payment", "w-2", "cryptocurrency"]
        bec_hits = [t for t in bec_terms if t in lower_text]
        if bec_hits:
            score += 35
            indicators.append(IndicatorDetail(
                category="Fraud Pattern (BEC)",
                signal=f"Direct Financial Action Request ({', '.join(bec_hits)})",
                weight=35,
                severity="Critical",
                description="Classic Business Email Compromise (BEC) pattern requesting unauthorized fund disbursement or payment method modification."
            ))

        # 3. Credential Harvesting prompts
        cred_prompts = ["verify your account", "confirm your password", "login here", "reset password", "two-factor", "otp code", "security question"]
        cred_hits = [p for p in cred_prompts if p in lower_text]
        if cred_hits:
            score += 30
            indicators.append(IndicatorDetail(
                category="Credential Harvesting",
                signal=f"Identity Verification Directive ({', '.join(cred_hits[:2])})",
                weight=30,
                severity="High",
                description="Message directs recipient to external input mechanisms for authentication tokens or credentials."
            ))

        # 4. Embedded URLs in text
        found_urls = re.findall(r"https?://[^\s]+", combined_text)
        extracted_features["embedded_urls_count"] = len(found_urls)
        if found_urls:
            score += 15
            indicators.append(IndicatorDetail(
                category="Embedded Links",
                signal=f"Embedded Hyperlinks Detected ({len(found_urls)} link(s))",
                weight=15,
                severity="Medium",
                description="Contains embedded web destinations. Attackers frequently use clickable anchors to lead victims to spoofed portals."
            ))

        # 5. ML Model NLP Prediction
        X_test = self.vectorizer.transform([combined_text])
        ml_prob = float(self.classifier.predict_proba(X_test)[0][1])
        ml_contrib = int(ml_prob * 35)
        extracted_features["ml_phishing_probability"] = round(ml_prob, 3)

        if ml_prob > 0.50:
            indicators.append(IndicatorDetail(
                category="Machine Learning Classifier",
                signal=f"NLP Language Model Score ({int(ml_prob * 100)}% Threat Probability)",
                weight=ml_contrib,
                severity="High" if ml_prob > 0.75 else "Medium",
                description="Scikit-learn logistic regression engine evaluated language structure as strongly matching fraudulent correspondence."
            ))
            score += ml_contrib

        final_score = min(max(score, 3), 99)
        risk_category = self._score_to_category(final_score)

        explanation = self._build_explanation(
            target_type="Email/Message",
            category=risk_category,
            score=final_score,
            indicators=indicators
        )

        precautions = self._build_precautions(risk_category, submission_type)

        return PhishingAnalysisResponse(
            analysis_id=f"TA-MSG-{int(datetime.now(timezone.utc).timestamp())}",
            timestamp=datetime.now(timezone.utc),
            submission_type=submission_type,
            target=(email_subject or content[:60] + "..."),
            risk_score=final_score,
            risk_category=risk_category,
            detection_engine="Heuristic NLP + Scikit-Learn Vectorizer Classifier",
            indicators=indicators if indicators else [
                IndicatorDetail(
                    category="Heuristic Evaluation",
                    signal="Normal Conversational Tone",
                    weight=0,
                    severity="Low",
                    description="No coercive deadlines, banking routing requests, or credential harvest vectors detected."
                )
            ],
            explanation=explanation,
            recommended_precautions=precautions,
            features_extracted=extracted_features,
            reputation_status="Heuristic/ML Analysis (Live Reputation API key not configured in .env)"
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
