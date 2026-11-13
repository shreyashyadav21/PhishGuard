import pytest
from app.detection.url_analyzer import analyze_url

def test_normal_https_website():
    res = analyze_url("https://www.google.com")
    assert res["analysis_status"] == "completed"
    assert res["risk_score"] < 20
    assert res["classification"] == "safe"
    assert any("https" in obs.lower() for obs in res["positive_observations"])

def test_insecure_http_website():
    res = analyze_url("http://example.com")
    assert res["analysis_status"] == "completed"
    assert any("http" in ind["name"].lower() for ind in res["indicators"])

def test_raw_ip_address_url():
    res = analyze_url("http://192.168.1.1/admin/login")
    assert res["risk_score"] >= 20
    assert any("raw ip" in ind["name"].lower() for ind in res["indicators"])

def test_very_long_url():
    long_url = "https://example.com/" + "a" * 150
    res = analyze_url(long_url)
    assert any("long url" in ind["name"].lower() for ind in res["indicators"])

def test_url_with_at_symbol():
    res = analyze_url("http://google.com@evil-attacker.com/login")
    assert res["risk_score"] >= 30
    assert any("@" in ind["name"] for ind in res["indicators"])

def test_suspicious_brand_impersonation():
    res = analyze_url("http://paypa1-security-verification.example.com/verify")
    assert res["risk_score"] >= 50
    assert any("impersonation" in ind["name"].lower() for ind in res["indicators"])

def test_excessive_subdomains():
    res = analyze_url("https://a.b.c.d.example.com/index")
    assert any("subdomain" in ind["name"].lower() for ind in res["indicators"])

def test_encoded_characters_url():
    res = analyze_url("http://example.com/%20%2f%2e%25%20%20%20test")
    assert any("percent" in ind["name"].lower() for ind in res["indicators"])

def test_empty_url():
    res = analyze_url("")
    assert res["analysis_status"] == "insufficient_evidence"
    assert res["classification"] == "unknown"

def test_malformed_url():
    res = analyze_url("   ")
    assert res["classification"] == "unknown"

