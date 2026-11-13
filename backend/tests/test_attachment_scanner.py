import pytest
from app.detection.attachment_scanner import analyze_attachment

def test_safe_pdf_attachment():
    res = analyze_attachment(
        filename="invoice_receipt.pdf",
        content_bytes=b"%PDF-1.4\n%test content for pdf",
        file_size=1024,
        declared_mime="application/pdf"
    )
    assert not res["is_dangerous"]
    assert res["threat_score"] == 0
    assert res["safe_to_open"] is True

def test_double_extension_executable():
    res = analyze_attachment(
        filename="bonus_payout.pdf.exe",
        content_bytes=b"MZ\x90\x00\x03\x00\x00\x00",
        file_size=2048
    )
    assert res["is_dangerous"] is True
    assert res["threat_score"] >= 70
    assert res["severity"] == "Critical"
    assert any("double extension" in r.lower() for r in res["threat_reasons"])

def test_macro_enabled_office_doc():
    res = analyze_attachment(
        filename="financial_summary.docm",
        file_size=50000
    )
    assert res["is_dangerous"] is True
    assert res["threat_score"] >= 25
    assert any("macro-enabled" in r.lower() for r in res["threat_reasons"])

def test_file_format_spoofing():
    # Named as a photo (.jpg) but starts with MZ Windows executable signature
    res = analyze_attachment(
        filename="vacation_photo.jpg",
        content_bytes=b"MZ\x90\x00binary_executable_code_here"
    )
    assert res["is_dangerous"] is True
    assert any("mz" in r.lower() for r in res["threat_reasons"])

