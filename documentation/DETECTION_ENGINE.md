# PhishGuard Threat Detection Engine Reference

## 1. Engine Heuristics & Weighted Scoring

PhishGuard employs a multi-tiered, rule-based heuristic detection engine located in `backend/app/detection/`.

```
Raw Input Target
      |
      +---> RFC 3986 Normalization & Protocol Inspection
      |
      +---> Domain Partitions (ccTLD, SLD, Subdomains)
      |
      +---> Homoglyph Normalization & Levenshtein Distance
      |
      +---> Abused TLD & Keyword Pattern Matching
      |
      +---> Category Caps & Correlated Signal Saturation
      |
      v
Final Risk Score (0-100) & Severity Classification
```

### 1.1 URL Scoring Matrix

| Indicator ID | Rule Name | Base Points | Severity | Category Cap | Description |
|---|---|---|---|---|---|
| `IND_HTTP_SCHEME` | Insecure HTTP Connection | 5 | Low | 10 | Unencrypted HTTP communication |
| `IND_RAW_IP` | Raw IP Hostname | 20 | High | 25 | Hostname is an IPv4 or IPv6 address |
| `IND_AT_SYMBOL` | Deceptive '@' Character | 25 | Critical | 20 | RFC 3986 userinfo trick to mask true host |
| `IND_URL_LENGTH` | Excessively Long URL (>120) | 12 | Medium | 25 | Obfuscation via excessive path length |
| `IND_BRAND_HOMOGLYPH` | Brand Impersonation (Homoglyph) | 30 | Critical | 35 | Leetspeak/character substitution (e.g. `paypa1`) |
| `IND_BRAND_TYPO` | Brand Typosquatting (Levenshtein) | 25 | High | 35 | Distance = 1 from registered trademark |
| `IND_BRAND_SUBDOMAIN`| Deceptive Brand Subdomain | 30 | Critical | 35 | Brand injected into subdomain of unrelated root |
| `IND_EXCESS_SUBDOM` | Excessive Subdomain Depth (>=3) | 10 | Medium | 25 | Complex nesting hiding primary registrar |
| `IND_MULTIPLE_HYPHENS`| Multiple Hyphens in Host (>=3) | 10 | Medium | 25 | Keyword concatenation in domain |
| `IND_ABUSED_TLD` | Suspicious / Abused TLD | 8 | Low | 15 | Statistically elevated phishing TLD (.xyz, .top, .buzz) |
| `IND_KEYWORD_COMBO` | Security Keyword Combinations | 15 | High | 20 | Lures (login, verify, banking, wallet) |
| `IND_PERCENT_ENCODING`| Excessive Percent Encoding (>=4) | 10 | Medium | 15 | Payloads obfuscated with %xx encoding |
| `IND_OPEN_REDIRECT` | Open Redirection Parameter | 12 | Medium | 25 | URL parameter contains forwarded link |

---

## 2. Risk Classification Thresholds

The aggregated risk score is mapped to standard SOC severity bands:

- **0 – 19**: **Low Risk (Safe)** — Clean domain structure, recognized legitimate infrastructure, or standard internet host with zero malicious markers.
- **20 – 39**: **Suspicious** — Minor structural anomalies, unfamiliar TLD, or plain HTTP without brand impersonation.
- **40 – 69**: **High Risk** — Multiple correlated indicators, raw IP hosts, or brand keywords concatenated in unregistered domains.
- **70 – 100**: **Critical Risk** — Severe homoglyph impersonations, credential harvesting traps, or deceptive '@' character redirection tricks.
- **Unknown / Insufficient Evidence**: Assigned when input is syntactically invalid or blank.

---

## 3. Email Phishing & Social Engineering Heuristics

The email analyzer (`email_analyzer.py`) processes:

1. **Display Name Spoofing**: Checks whether the friendly display name references a protected brand while the actual sending domain is hosted on third-party infrastructure.
2. **Reply-To Divergence**: Flags when the `Reply-To` domain diverges from the `From` envelope sender.
3. **High-Pressure Urgency**: Detects psychological coercion patterns (e.g. `account suspended within 24 hours`, `last warning`).
4. **Credential Solicitation**: Flags unsolicited requests for passwords, OTPs, PINs, or card CVVs.
5. **Embedded Link Crawling**: Recursively analyzes all extracted hyperlinks through the URL detection engine.

