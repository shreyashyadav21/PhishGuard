import re
from typing import Optional, Tuple, List
from .indicators import KNOWN_BRANDS, SUSPICIOUS_TLDS, IndicatorResult

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def normalize_homoglyphs(text: str) -> str:
    """Normalize common leetspeak / homoglyph characters."""
    substitutions = {
        '0': 'o',
        '1': 'l',
        '3': 'e',
        '4': 'a',
        '@': 'a',
        '5': 's',
        '$': 's',
        '7': 't',
        '8': 'b',
        'vv': 'w',
        'rn': 'm',
    }
    result = text.lower()
    for char, replacement in substitutions.items():
        result = result.replace(char, replacement)
    return result

def extract_domain_parts(hostname: str) -> Tuple[str, str, List[str]]:
    """
    Given a hostname, returns:
    (full_domain, registered_domain, subdomains_list)
    Handles common ccTLDs like .co.uk, .co.in, .com.br, etc.
    """
    clean_host = hostname.lower().strip()
    if ':' in clean_host:
        clean_host = clean_host.split(':')[0]

    parts = clean_host.split('.')
    if len(parts) <= 1:
        return clean_host, clean_host, []

    double_tlds = {"co.uk", "co.in", "com.au", "co.nz", "com.br", "org.uk", "gov.in", "edu.in"}
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in double_tlds:
        reg_domain = f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
        subdomains = parts[:-3]
    elif len(parts) >= 2:
        reg_domain = f"{parts[-2]}.{parts[-1]}"
        subdomains = parts[:-2]
    else:
        reg_domain = clean_host
        subdomains = []

    return clean_host, reg_domain, subdomains

def check_domain_reputation(hostname: str) -> Tuple[List[IndicatorResult], List[str]]:
    """
    Analyzes hostname for brand impersonation, typosquatting,
    suspicious TLDs, and structural anomalies.
    Returns: (indicators, positive_observations)
    """
    indicators: List[IndicatorResult] = []
    positive_observations: List[str] = []

    if not hostname:
        return indicators, positive_observations

    full_domain, reg_domain, subdomains = extract_domain_parts(hostname)

    # Check if domain matches any known official brand domains
    matched_official = None
    for brand_key, brand_info in KNOWN_BRANDS.items():
        for off_dom in brand_info["official_domains"]:
            if full_domain == off_dom or full_domain.endswith("." + off_dom):
                matched_official = brand_info["name"]
                break
        if matched_official:
            break

    if matched_official:
        positive_observations.append(
            f"Domain matches recognized legitimate infrastructure for {matched_official}."
        )
        return indicators, positive_observations

    # Impersonation checks against known brands
    reg_sld = reg_domain.split('.')[0] if '.' in reg_domain else reg_domain
    normalized_reg_sld = normalize_homoglyphs(reg_sld)

    impersonation_detected = False

    for brand_key, brand_info in KNOWN_BRANDS.items():
        brand_name = brand_info["name"]
        keywords = brand_info["keywords"]

        # 1. Homoglyph / Typosquatting in SLD
        # Example: 'paypa1' normalized is 'paypal', but original sld is not 'paypal'
        if normalized_reg_sld == brand_key and reg_sld != brand_key:
            indicators.append(IndicatorResult(
                name="Brand Impersonation (Homoglyph / Typosquatting)",
                severity="critical",
                points=30,
                description=f"Domain '{reg_domain}' uses homoglyph character substitutions to mimic '{brand_name}'.",
                category="domain_impersonation",
                evidence=f"Target: {brand_name}, Found: {reg_sld} -> Normalized: {normalized_reg_sld}"
            ))
            impersonation_detected = True
            break

        # 2. Levenshtein edit distance check (1 or 2 edits away on names with length >= 4)
        if len(brand_key) >= 4:
            dist = levenshtein_distance(reg_sld, brand_key)
            if dist == 1 and reg_sld != brand_key:
                indicators.append(IndicatorResult(
                    name="Brand Impersonation (Typosquatting)",
                    severity="high",
                    points=25,
                    description=f"Domain '{reg_domain}' is 1 character different from official brand '{brand_name}'.",
                    category="domain_impersonation",
                    evidence=f"Domain SLD '{reg_sld}' vs Brand '{brand_key}' (Distance: {dist})"
                ))
                impersonation_detected = True
                break

        # 3. Brand name embedded in registered domain with hyphens or prefixes
        # e.g., 'paypal-security.com', 'paypa1-verify-account.com', 'login-apple-update.com'
        pattern = rf"(^|[-_]){re.escape(brand_key)}([-_]|$)"
        if (re.search(pattern, reg_sld) or re.search(pattern, normalized_reg_sld)) and not impersonation_detected:
            indicators.append(IndicatorResult(
                name="Brand Keyword in Domain Name",
                severity="high",
                points=25,
                description=f"Domain '{reg_domain}' includes '{brand_name}' keyword (or homoglyph) in an unauthorized domain.",
                category="domain_impersonation",
                evidence=f"Matched brand keyword '{brand_key}' in domain '{reg_domain}'"
            ))
            impersonation_detected = True
            break

        # 4. Brand name placed in subdomain of unrelated domain
        # e.g., 'paypal.login-verify.com', 'accounts.google.com.attacker.org', 'paypa1-security.example.com'
        for sub in subdomains:
            norm_sub = normalize_homoglyphs(sub)
            if brand_key in sub or brand_key in norm_sub:
                indicators.append(IndicatorResult(
                    name="Brand Impersonation in Subdomain",
                    severity="critical",
                    points=30,
                    description=f"Brand name '{brand_name}' appears in subdomain '{sub}', tricking users into assuming ownership while root domain is '{reg_domain}'.",
                    category="domain_impersonation",
                    evidence=f"Subdomain: {sub}, Root Domain: {reg_domain}"
                ))
                impersonation_detected = True
                break
        if impersonation_detected:
            break

    # Subdomain depth analysis
    if len(subdomains) >= 3:
        indicators.append(IndicatorResult(
            name="Excessive Subdomains",
            severity="medium",
            points=10,
            description=f"Domain has an unusually deep hierarchy ({len(subdomains)} subdomains: {'.'.join(subdomains)}), commonly used to hide the true root domain.",
            category="url_structure",
            evidence=f"Subdomains: {subdomains}"
        ))

    # Multiple hyphens in domain name
    hyphen_count = full_domain.count('-')
    if hyphen_count >= 3:
        indicators.append(IndicatorResult(
            name="Multiple Hyphens in Hostname",
            severity="medium",
            points=10,
            description=f"Hostname contains {hyphen_count} hyphens, a frequent tactic to combine multiple legitimate-sounding terms into a deceptive domain.",
            category="url_structure",
            evidence=f"Hyphen count: {hyphen_count}"
        ))

    # Suspicious / abused TLD check
    matched_tld = None
    for tld in SUSPICIOUS_TLDS:
        if full_domain.endswith(tld):
            matched_tld = tld
            break

    if matched_tld:
        indicators.append(IndicatorResult(
            name=f"High-Risk / Frequently Abused TLD ({matched_tld})",
            severity="low",
            points=8,
            description=f"The top-level domain '{matched_tld}' has a statistically higher incidence of phishing campaigns due to low registration costs. Considered a contributing indicator.",
            category="domain",
            evidence=f"TLD: {matched_tld}"
        ))

    if not indicators:
        positive_observations.append("Domain name structure appears standard with no detected typosquatting or excessive nesting.")

    return indicators, positive_observations
