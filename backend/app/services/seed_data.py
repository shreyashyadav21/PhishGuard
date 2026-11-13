import json
import datetime
from sqlalchemy.orm import Session
from ..models import (
    Scan,
    Indicator,
    Recommendation,
    Setting,
    ThreatIndicator,
    QuizAttempt,
    SecurityEvent,
    Attachment,
    ConnectedAccount
)
from ..detection.url_analyzer import analyze_url
from ..detection.email_analyzer import analyze_email
from ..detection.attachment_scanner import analyze_attachment

def seed_database_if_empty(db: Session):
    """
    Seeds initial realistic demonstration threat intelligence, historical scans,
    and system settings if the database is newly initialized.
    """
    # Check if settings already exist
    existing_settings = db.query(Setting).first()
    if not existing_settings:
        default_settings = [
            ("theme", "dark"),
            ("engine_version", "3.1.0-SOC"),
            ("store_email_body", "false"),
            ("notification_sound", "true"),
            ("alert_threshold", "40"),
            ("auto_export_pdf", "false"),
            ("telemetry_sharing", "false"),
        ]
        for k, v in default_settings:
            db.add(Setting(setting_key=k, setting_value=v))
        db.commit()

    # Check if threat indicators already exist
    existing_threats = db.query(ThreatIndicator).first()
    if not existing_threats:
        demo_threats = [
            ThreatIndicator(
                indicator_value="paypa1-security-verification.com",
                category="Domain Impersonation",
                severity="Critical",
                detection_reason="Homoglyph substitution 'paypa1' mimicking PayPal with banking keywords.",
                first_observed=datetime.datetime.utcnow() - datetime.timedelta(days=12),
                scan_count=42,
                is_simulated=True,
                recommended_action="Block hostname across firewall and secure web gateway (SWG)."
            ),
            ThreatIndicator(
                indicator_value="185.220.101.5",
                category="Malicious URL Structure",
                severity="High",
                detection_reason="Direct IPv4 address hosting an unencrypted credential submission portal.",
                first_observed=datetime.datetime.utcnow() - datetime.timedelta(days=18),
                scan_count=19,
                is_simulated=True,
                recommended_action="Blacklist IP at border edge routers and flag all inbound connections."
            ),
            ThreatIndicator(
                indicator_value="security-alert@micros0ft-support.xyz",
                category="Credential Theft",
                severity="Critical",
                detection_reason="Display name spoofing and homoglyph 'micros0ft' on abused .xyz TLD.",
                first_observed=datetime.datetime.utcnow() - datetime.timedelta(days=7),
                scan_count=35,
                is_simulated=True,
                recommended_action="Add sender address and domain regex to mail transfer agent (MTA) reject list."
            ),
            ThreatIndicator(
                indicator_value="amaz0n-prime-renewal.top",
                category="Social Engineering",
                severity="High",
                detection_reason="Abused .top TLD paired with simulated Amazon subscription cancellation lure.",
                first_observed=datetime.datetime.utcnow() - datetime.timedelta(days=4),
                scan_count=27,
                is_simulated=True,
                recommended_action="Add domain to DNS sinkhole and reset credentials for affected users."
            ),
            ThreatIndicator(
                indicator_value="login.netflix.account-billing-update.buzz",
                category="Suspicious Redirection",
                severity="Critical",
                detection_reason="Excessive 4-level subdomain nesting with brand name prefixed to hide true .buzz registrar.",
                first_observed=datetime.datetime.utcnow() - datetime.timedelta(days=2),
                scan_count=14,
                is_simulated=True,
                recommended_action="Quarantine all emails referencing this host; purge web cache."
            ),
            ThreatIndicator(
                indicator_value="sbi-kyc-update-portal.org",
                category="Domain Impersonation",
                severity="High",
                detection_reason="Brand keyword 'sbi' combined with 'kyc' targeting retail banking customers.",
                first_observed=datetime.datetime.utcnow() - datetime.timedelta(days=9),
                scan_count=21,
                is_simulated=True,
                recommended_action="Alert fraud division; submit takedown notice to registrar."
            ),
        ]
        db.add_all(demo_threats)
        db.commit()

    # Check if historical scans already exist
    existing_scans = db.query(Scan).count()
    if existing_scans == 0:
        seed_samples = [
            ("url", "http://paypa1-login-security.com/verify", 14),
            ("url", "https://google.com/search?q=cybersecurity", 13),
            ("email", "Immediate Action: Your Microsoft Account is Suspended!", 11),
            ("url", "http://192.168.1.100/admin/auth/login", 10),
            ("url", "https://accounts.google.com/signin/v2/identifier", 8),
            ("email", "You Won $1,500,000 in International Lottery! Claim Now", 7),
            ("url", "http://amaz0n-security-update.xyz/login?session=confirm", 5),
            ("url", "https://github.com/trending", 4),
            ("email", "HR Notification: Updated Employee Benefits Document Attached", 3),
            ("url", "http://netflix.account-billing-update.buzz/renew", 2),
            ("url", "https://www.apple.com/iphone/", 1),
            ("email", "Urgent: Complete your SBI KYC within 24 hours to avoid suspension", 0),
        ]

        for scan_type, sample_input, days_ago in seed_samples:
            created_dt = datetime.datetime.utcnow() - datetime.timedelta(days=days_ago, hours=3)
            if scan_type == "url":
                analysis = analyze_url(sample_input)
                scan_obj = Scan(
                    scan_type="url",
                    submitted_item=sample_input,
                    risk_score=analysis["risk_score"],
                    classification=analysis["classification"],
                    created_at=created_dt,
                    analysis_json=json.dumps(analysis)
                )
                db.add(scan_obj)
                db.flush()

                for ind in analysis.get("indicators", []):
                    db.add(Indicator(
                        scan_id=scan_obj.id,
                        indicator_name=ind.get("name", ""),
                        severity=ind.get("severity", "medium"),
                        risk_points=ind.get("points", 0),
                        description=ind.get("description", "")
                    ))
                for rec in analysis.get("recommendations", []):
                    db.add(Recommendation(
                        scan_id=scan_obj.id,
                        recommendation_text=rec
                    ))
            else:
                email_payload = {
                    "sender": "Security Alert <alert@bank-verify.xyz>",
                    "subject": sample_input,
                    "body": f"Dear user,\n{sample_input}\nPlease verify your credentials immediately at http://paypa1-verify.top or your account will be locked.",
                    "reply_to": "attacker@darkmail.xyz"
                }
                analysis = analyze_email(email_payload)
                scan_obj = Scan(
                    scan_type="email",
                    submitted_item=sample_input,
                    risk_score=analysis["risk_score"],
                    classification=analysis["classification"],
                    created_at=created_dt,
                    analysis_json=json.dumps(analysis)
                )
                db.add(scan_obj)
                db.flush()

                for ind in analysis.get("indicators", []):
                    db.add(Indicator(
                        scan_id=scan_obj.id,
                        indicator_name=ind.get("name", ""),
                        severity=ind.get("severity", "medium"),
                        risk_points=ind.get("points", 0),
                        description=ind.get("description", "")
                    ))
                for rec in analysis.get("recommendations", []):
                    db.add(Recommendation(
                        scan_id=scan_obj.id,
                        recommendation_text=rec
                    ))

        # Add initial sample quiz attempt
        db.add(QuizAttempt(
            total_questions=10,
            correct_answers=8,
            score=80,
            created_at=datetime.datetime.utcnow() - datetime.timedelta(days=1)
        ))

    # Seed sample timeline events if empty
    existing_events = db.query(SecurityEvent).first()
    if not existing_events:
        demo_events = [
            SecurityEvent(
                event_type="threat_identified",
                title="Critical Impersonation Attack Flagged",
                description="Identified homoglyph phishing domain paypa1-login-security.com attempting credential harvesting.",
                severity="critical",
                target_item="http://paypa1-login-security.com/verify",
                created_at=datetime.datetime.utcnow() - datetime.timedelta(hours=2)
            ),
            SecurityEvent(
                event_type="quarantine",
                title="Suspicious Invoice Quarantined",
                description="User confirmed quarantine for message containing macro-enabled document 'remittance_dec.docm'.",
                severity="high",
                target_item="Message ID: msg_8829104",
                created_at=datetime.datetime.utcnow() - datetime.timedelta(hours=5)
            ),
            SecurityEvent(
                event_type="email_detected",
                title="Banking Verification Lure Scanned",
                description="Automated scan of incoming message claiming SBI KYC suspension with urgency cues.",
                severity="high",
                target_item="Urgent: Complete your SBI KYC within 24 hours",
                created_at=datetime.datetime.utcnow() - datetime.timedelta(days=1)
            ),
            SecurityEvent(
                event_type="trash",
                title="Lottery Scam Moved to Trash",
                description="User reviewed and confirmed Move-to-Trash for $1.5M international lottery claim lure.",
                severity="medium",
                target_item="You Won $1,500,000 in International Lottery!",
                created_at=datetime.datetime.utcnow() - datetime.timedelta(days=2)
            ),
            SecurityEvent(
                event_type="keep",
                title="Legitimate Security Alert Preserved",
                description="User confirmed Keep action for authentic Google sign-in security confirmation notice.",
                severity="info",
                target_item="Security alert for your linked Google Account",
                created_at=datetime.datetime.utcnow() - datetime.timedelta(days=3)
            )
        ]
        db.add_all(demo_events)

    # Seed sample attachment records if empty
    existing_att = db.query(Attachment).first()
    if not existing_att:
        first_scan = db.query(Scan).first()
        if first_scan:
            demo_att = [
                Attachment(
                    scan_id=first_scan.id,
                    filename="Statement_Dec2026.pdf.exe",
                    file_size=348160,
                    mime_type="application/x-dosexec",
                    sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    is_dangerous=True,
                    threat_score=75,
                    threat_reasons=json.dumps([
                        "Double extension deception detected ('Statement_Dec2026.pdf.exe'). Attacker disguised executable '.exe' as 'pdf'.",
                        "High-risk extension '.exe': Windows Executable Binary."
                    ])
                ),
                Attachment(
                    scan_id=first_scan.id,
                    filename="purchase_order_macro.docm",
                    file_size=118272,
                    mime_type="application/vnd.ms-word.document.macroEnabled.12",
                    sha256_hash="f441712a89c9c8e8d89e5a4843b10287a9354e6ffec2b64a38cb627ff76efee4",
                    is_dangerous=True,
                    threat_score=50,
                    threat_reasons=json.dumps([
                        "High-risk extension '.docm': Macro-Enabled Microsoft Word Document."
                    ])
                ),
                Attachment(
                    scan_id=first_scan.id,
                    filename="Quarterly_Report_Benign.pdf",
                    file_size=524288,
                    mime_type="application/pdf",
                    sha256_hash="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    is_dangerous=False,
                    threat_score=0,
                    threat_reasons=json.dumps([])
                )
            ]
            db.add_all(demo_att)

        db.commit()

