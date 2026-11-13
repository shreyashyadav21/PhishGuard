from dataclasses import dataclass
from typing import Optional

@dataclass
class IndicatorResult:
    name: str
    severity: str  # "low", "medium", "high", "critical"
    points: int
    description: str
    category: str  # "protocol", "domain", "url_structure", "content", "social_engineering", etc.
    evidence: Optional[str] = None

# Known popular brands and their legitimate official domains
KNOWN_BRANDS = {
    "paypal": {
        "name": "PayPal",
        "official_domains": ["paypal.com", "paypal-community.com"],
        "keywords": ["paypal", "paypa1", "pay-pal", "paypal-security", "paypal-service"]
    },
    "google": {
        "name": "Google",
        "official_domains": ["google.com", "accounts.google.com", "gmail.com", "google.co.in", "google.co.uk"],
        "keywords": ["google", "goog1e", "g00gle", "gmail", "googledrive"]
    },
    "microsoft": {
        "name": "Microsoft",
        "official_domains": ["microsoft.com", "live.com", "office.com", "outlook.com", "azure.com"],
        "keywords": ["microsoft", "micros0ft", "m1crosoft", "outlook", "office365", "onedrive"]
    },
    "apple": {
        "name": "Apple",
        "official_domains": ["apple.com", "icloud.com"],
        "keywords": ["apple", "app1e", "icloud", "appleid", "app-store"]
    },
    "amazon": {
        "name": "Amazon",
        "official_domains": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "aws.amazon.com"],
        "keywords": ["amazon", "amaz0n", "amzn", "prime-video", "aws-security"]
    },
    "netflix": {
        "name": "Netflix",
        "official_domains": ["netflix.com"],
        "keywords": ["netflix", "netfl1x", "net-flix", "netflix-verify"]
    },
    "facebook": {
        "name": "Facebook",
        "official_domains": ["facebook.com", "meta.com", "fb.com"],
        "keywords": ["facebook", "faceb00k", "face-book", "meta-verify"]
    },
    "instagram": {
        "name": "Instagram",
        "official_domains": ["instagram.com"],
        "keywords": ["instagram", "instagrarn", "insta-login"]
    },
    "sbi": {
        "name": "State Bank of India (SBI)",
        "official_domains": ["onlinesbi.sbi", "sbi.co.in", "statebankofindia.com"],
        "keywords": ["onlinesbi", "sbicard", "sbi-banking", "sbi-kyc", "yono"]
    },
    "hdfc": {
        "name": "HDFC Bank",
        "official_domains": ["hdfcbank.com", "netbanking.hdfcbank.com"],
        "keywords": ["hdfc", "hdfcbank", "hdfc-netbanking", "hdfc-kyc"]
    },
    "icici": {
        "name": "ICICI Bank",
        "official_domains": ["icicibank.com"],
        "keywords": ["icici", "icicibank", "icici-netbanking", "icici-login"]
    },
    "chase": {
        "name": "Chase Bank",
        "official_domains": ["chase.com"],
        "keywords": ["chase", "chaseonline", "chase-security"]
    },
    "dropbox": {
        "name": "Dropbox",
        "official_domains": ["dropbox.com"],
        "keywords": ["dropbox", "drop-box"]
    }
}

# Suspicious / high-risk TLDs often abused in automated phishing campaigns
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".buzz", ".fit", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".work", ".click", ".loan", ".surf", ".monster", ".icu", ".cam",
    ".rest", ".bar", ".cfd", ".sbs", ".quest"
}

# Suspicious keywords commonly seen in phishing lures
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "account", "password", "secure",
    "update", "banking", "wallet", "payment", "authenticate", "authentication",
    "recovery", "recover", "urgent", "suspended", "confirm", "confirmation",
    "validation", "security", "resolve", "reactivate", "unlock", "alert",
    "billing", "invoice", "auth", "signin", "sign-in", "webscr", "cmd=_login"
]

# Sensitive credential harvesting requests in emails
CREDENTIAL_REQUEST_TERMS = [
    "password", "passcode", "secret code", "one-time password", "otp",
    "pin code", "atm pin", "cvv", "credit card number", "card details",
    "bank account number", "routing number", "ssn", "social security",
    "private key", "seed phrase", "recovery phrase", "credentials"
]

# Urgency / fear triggers in emails
URGENCY_TERMS = [
    "immediate action required", "immediately", "account will be suspended",
    "account suspended", "account terminated", "within 24 hours",
    "within 12 hours", "within 2 hours", "last warning", "final notice",
    "unauthorized login attempt", "security alert", "suspicious activity detected",
    "access restricted", "action needed", "critical update", "failure to respond"
]

# Social engineering triggers
SOCIAL_ENGINEERING_TERMS = [
    "lottery winner", "you have won", "selected for prize", "inheritance",
    "wire transfer", "unclaimed funds", "claim your prize", "free gift card",
    "refund processing", "tax refund", "cryptocurrency payout", "urgent request"
]

