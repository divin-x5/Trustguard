from fastapi.testclient import TestClient

from engine import analyze_url, analyze_message, build_report
from main import app

client = TestClient(app)


def test_phishing_url_high_risk():
    report = build_report(analyze_url("https://sbi-secure-login.xyz/verify-account"))
    assert report["risk"]["level"] == "HIGH"
    ids = {s["id"] for s in report["signals"]}
    assert "brand_mismatch" in ids
    assert "suspicious_tld" in ids
    assert "Don't" in " ".join(report["recommended_actions"]) or "Do not" in " ".join(report["recommended_actions"])


def test_legitimate_url_safe():
    report = build_report(analyze_url("https://www.wikipedia.org/wiki/Phishing"))
    assert report["risk"]["score"] < 40


def test_scam_message_high_risk():
    msg = "URGENT! Your bank account will be blocked today. Verify immediately: http://sbi-login.xyz/otp"
    report = build_report(analyze_message(msg))
    assert report["risk"]["score"] >= 70
    ids = {s["id"] for s in report["signals"]}
    assert "urgency" in ids
    assert "threat" in ids
    assert "contains_link" in ids


def test_normal_message_safe():
    report = build_report(analyze_message("Hey, are we still meeting for lunch tomorrow?"))
    assert report["risk"]["level"] == "SAFE"


def test_api_endpoint_url():
    r = client.post("/analyze", json={"text": "https://hdfcbank-secure.top/login"})
    assert r.status_code == 200
    body = r.json()
    assert body["input_type"] == "url"
    assert body["risk"]["level"] in ("HIGH", "MEDIUM")


def test_api_endpoint_message():
    r = client.post("/analyze", json={"text": "Congratulations! You won a lottery. Share your OTP to claim."})
    assert r.status_code == 200
    body = r.json()
    assert body["input_type"] == "message"
    assert body["risk"]["level"] in ("HIGH", "MEDIUM")


def test_message_with_link_is_message_not_url():
    r = client.post("/analyze", json={"text": "URGENT! Your bank account will be blocked today. Share your OTP at http://sbi-login.xyz"})
    assert r.status_code == 200
    body = r.json()
    assert body["input_type"] == "message"
    assert body["risk"]["level"] in ("HIGH", "MEDIUM")


def test_bare_domain_is_url():
    r = client.post("/analyze", json={"text": "sbi-secure-login.xyz"})
    assert r.json()["input_type"] == "url"


# --- Adversarial hardening tests ---

def test_empty_input_rejected():
    r = client.post("/analyze", json={"text": ""})
    assert r.status_code == 422


def test_whitespace_only_rejected():
    r = client.post("/analyze", json={"text": "   \n\t "})
    assert r.status_code == 422


def test_emoji_only_rejected():
    r = client.post("/analyze", json={"text": "🎉🎊🎉"})
    assert r.status_code == 422


def test_oversized_input_rejected():
    r = client.post("/analyze", json={"text": "a" * 20000})
    assert r.status_code == 422


def test_url_userinfo_trick_flagged():
    report = build_report(analyze_url("http://sbi.co.in@evil-secure.xyz/login"))
    ids = {s["id"] for s in report["signals"]}
    assert "url_userinfo" in ids


def test_shortener_flagged():
    report = build_report(analyze_url("https://bit.ly/3xY2zQ"))
    ids = {s["id"] for s in report["signals"]}
    assert "url_shortener" in ids


def test_homoglyph_host_flagged():
    report = build_report(analyze_url("https://аpple.com/verify"))
    ids = {s["id"] for s in report["signals"]}
    assert "mixed_script_host" in ids


def test_leetspeak_keyword_detected():
    report = build_report(analyze_url("https://secure-verify.xyz/l0g1n?v3r1fy=1"))
    ids = {s["id"] for s in report["signals"]}
    assert "credential_keywords" in ids


def test_official_bank_domain_not_flagged_for_keywords():
    report = build_report(analyze_url("https://www.hdfcbank.com/personal/bank-accounts"))
    ids = {s["id"] for s in report["signals"]}
    assert "credential_keywords" not in ids


def test_benign_fine_not_flagged_as_threat():
    report = build_report(analyze_message("The fine for the event is Rs 200, pay at the office today"))
    ids = {s["id"] for s in report["signals"]}
    assert "threat" not in ids
    assert report["risk"]["level"] in ("SAFE", "LOW")


def test_embedded_url_scored_in_message():
    msg = "Dear customer, your KYC has expired. Update at https://paytm-kyc-update.blogspot.com/2026/10/kyc.html"
    report = build_report(analyze_message(msg))
    ids = {s["id"] for s in report["signals"]}
    assert "url:brand_mismatch" in ids
    assert report["risk"]["level"] == "HIGH"


def test_hinglish_scam_detected():
    msg = "Turant OTP saajha karein warna aapka account band ho jayega"
    report = build_report(analyze_message(msg))
    assert report["risk"]["score"] >= 40


def test_devanagari_scam_detected():
    msg = "आपका खाता आज बंद हो जाएगा। तुरंत OTP साझा करें"
    report = build_report(analyze_message(msg))
    assert report["risk"]["score"] >= 40


def test_localhost_handled_gracefully():
    report = build_report(analyze_url("http://localhost:8000/admin"))
    ids = {s["id"] for s in report["signals"]}
    assert "private_host" in ids
    assert "invalid_url" not in ids


def test_long_input_accepted_but_capped():
    r = client.post("/analyze", json={"text": "https://sbi-secure-login.xyz/verify-account" + "x" * 9000})
    assert r.status_code == 200


def test_leet_brand_bypass_detected():
    report = build_report(analyze_url("https://app1e-id.xyz/signin"))
    ids = {s["id"] for s in report["signals"]}
    assert "brand_mismatch" in ids


def test_percent_encoded_keyword_detected():
    report = build_report(analyze_url("https://evil-secure.xyz/%6C%6Fgin"))
    ids = {s["id"] for s in report["signals"]}
    assert "credential_keywords" in ids


def test_report_structure():
    r = client.post("/analyze", json={"text": "https://sbi-secure.xyz/login"})
    body = r.json()
    for key in ("risk", "summary", "signals", "recommended_actions"):
        assert key in body
