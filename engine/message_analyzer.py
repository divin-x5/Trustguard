"""Message analyzer: detects social-engineering patterns in text.

Embedded URLs found in the message are additionally run through the URL
analyzer so the link — often the real payload — is scored, not just the prose.
"""
import re

from .regexes import URL_RE
from .url_analyzer import analyze_url

# Word-boundary keyword lists (substring matching caused false positives
# like "fine, thanks" -> threat, or "wonderful" -> reward).
URGENCY = ["urgent", "immediately", "right now", "asap", "act now", "last chance",
           "final warning", "within 24", "turant", "jaldi", "foran", "तुरंत", "जल्दी"]
THREATS = ["blocked", "suspend", "suspended", "suspension", "deactivate", "deactivated",
           "close your account", "legal action", "arrest", "penalty", "expired",
           "band ho jayega", "block ho jayega", "बंद हो जाएगा"]
CREDENTIAL_REQUESTS = ["otp", "password", "pin", "cvv", "card number", "account number",
                       "verify your", "confirm your", "enter your", "share your",
                       "saajha karein", "shared karein", "साझा करें"]
REWARDS = ["winner", "won", "lottery", "prize", "cashback", "gift", "free",
           "congratulations", "lucky draw", "refund", "jeeta", "inam"]
AUTHORITY_CLAIMS = ["bank", "income tax", "police", "cbi", "customs", "support team",
                    "customer care", "official", "government", "sarkari"]


def _hits(text: str, words: list[str]) -> list[str]:
    return [w for w in words if re.search(r"\b" + re.escape(w) + r"\b", text)]


def _clean_url(u: str) -> str:
    return u.rstrip(".,;:!?)('\"")


def analyze_message(text: str) -> dict:
    signals = []
    t = " ".join((text or "").lower().split())  # collapse whitespace/zero-width tricks

    def add(sid, desc, score):
        signals.append({"id": sid, "description": desc, "base_score": score})

    if _hits(t, URGENCY):
        add("urgency", "Message pressures the reader to act immediately (urgency manipulation)", 20)
    if _hits(t, THREATS):
        add("threat", "Message uses threats of account suspension or legal consequences", 25)
    if _hits(t, CREDENTIAL_REQUESTS):
        add("credential_request", "Message asks for sensitive credentials such as OTP, password, or card details", 35)
    if _hits(t, REWARDS):
        add("too_good_to_be_true", "Message promises rewards, prizes, or unexpected money", 20)
    if _hits(t, AUTHORITY_CLAIMS):
        add("authority_claim", "Message impersonates a bank, government body, or official support", 20)

    urls = [_clean_url(u) for u in URL_RE.findall(text or "")][:3]
    embedded_signals = []
    for u in urls:
        url_analysis = analyze_url(u)
        for s in url_analysis["signals"]:
            embedded_signals.append({
                "id": f"url:{s['id']}",
                "description": f"Embedded link {u[:60]}: {s['description']}",
                "base_score": s["base_score"],
            })
    if urls:
        add("contains_link", f"Message contains {len(urls)} link(s): {urls[0][:60]}", 15)
    signals.extend(embedded_signals)

    if re.search(r"\b\d{4}\b", t) and _hits(t, CREDENTIAL_REQUESTS):
        add("otp_pattern", "Message appears to reference 4-digit codes alongside credential requests", 15)

    if text and (sum(c.isupper() for c in text) / max(len(text), 1)) > 0.5 and len(text) > 20:
        add("shouting", "Excessive capitalization, a common scam pressure tactic", 5)

    return {"type": "message", "input": text, "signals": signals}
