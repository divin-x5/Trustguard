"""URL analyzer: extracts heuristic signals from a URL."""
from urllib.parse import urlparse, unquote
import re

SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "click", "info", "link"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
              "shorturl.at", "tiny.cc", "rebrand.ly"}
PRIVATE_HOSTS = {".localhost", ".local", ".test", ".internal", ".home.arpa"}
BRANDS = {
    "sbi": "sbi.co.in", "hdfcbank": "hdfcbank.com", "icicibank": "icicibank.com",
    "axisbank": "axisbank.com", "paytm": "paytm.com", "phonepe": "phonepe.com",
    "google": "google.com", "amazon": "amazon.com", "paypal": "paypal.com",
    "apple": "apple.com", "microsoft": "microsoft.com", "netflix": "netflix.com",
}
CREDENTIAL_KEYWORDS = ["login", "signin", "verify", "secure", "account", "update",
                       "password", "otp", "confirm", "banking", "wallet", "refund"]
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})
# Digits commonly substituted for letters in lookalike brand domains
_DIGIT_FOR_LETTER = {"a": "4", "b": "8", "e": "3", "g": "9", "i": "1",
                     "l": "1", "o": "0", "s": "5", "t": "7", "z": "2"}


def _brand_pattern(brand: str) -> re.Pattern:
    """Regex matching a brand name including digit-substituted letters (app1e, goog1e)."""
    parts = []
    for ch in brand:
        parts.append(f"[{ch}{_DIGIT_FOR_LETTER[ch]}]" if ch in _DIGIT_FOR_LETTER else re.escape(ch))
    return re.compile("".join(parts))


def analyze_url(url: str) -> dict:
    signals = []
    url = (url or "").strip()
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "") + "?" + (parsed.query or "")
    # De-obfuscated view for keyword scanning: percent-decode then un-leet
    path_scan = unquote(path.lower()).replace("%20", "").translate(_LEET)
    host_scan = host.translate(_LEET)

    def add(sid, desc, score):
        signals.append((sid, desc, score))

    if not host or ("." not in host and host != "localhost"):
        add("invalid_url", "URL could not be parsed into a valid host", 40)

    # Private/internal hostnames — heuristics may not apply
    is_private = host == "localhost" or any(host.endswith(s) for s in PRIVATE_HOSTS)
    if is_private:
        add("private_host", "Private/internal hostname — analysis may not apply to external users", 10)

    # IP-literal host
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        add("ip_host", "Host is a raw IP address instead of a domain name", 35)

    # user:pass@host trick — the visible part is not the real host
    if "@" in (parsed.netloc or ""):
        add("url_userinfo",
            "URL embeds credentials/reader-target before '@' — the real destination is hidden after it",
            30)

    # Homoglyph / mixed-script host (e.g. Cyrillic 'а' in 'apple')
    if any(ord(ch) > 127 for ch in host):
        add("mixed_script_host",
            "Host contains non-ASCII characters — classic lookalike/homoglyph attack",
            30)
    if "xn--" in host:
        add("punycode", "Punycode-encoded domain can disguise lookalike characters", 30)

    # URL shortener — destination is obscured
    if any(host == s or host.endswith("." + s) for s in SHORTENERS):
        add("url_shortener", "Link uses a URL shortener that hides the real destination", 25)

    # Brand impersonation: brand in host but not on the official domain.
    # _brand_pattern also matches digit-substituted brands (app1e, goog1e).
    matched_brand = matched_official = None
    for brand, official in BRANDS.items():
        if _brand_pattern(brand).search(host):
            matched_brand, matched_official = brand, official
            break
    on_official_domain = (matched_official is not None
                          and (host == matched_official or host.endswith("." + matched_official)))
    if matched_brand and not on_official_domain:
        add("brand_mismatch",
            f"Domain claims to relate to '{matched_brand}' but does not use the official domain '{matched_official}'",
            40)

    # Suspicious TLD
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        add("suspicious_tld", f"'.{tld}' is commonly abused in phishing campaigns", 20)

    # Credential-bait keywords (skipped on official brand domains)
    if not on_official_domain:
        hits = [k for k in CREDENTIAL_KEYWORDS if k in path_scan or k in host_scan]
        if hits:
            add("credential_keywords",
                f"URL contains credential-bait keywords: {', '.join(hits[:4])}", 15)

    # Excessive subdomains / hyphens
    if host.count(".") >= 4:
        add("deep_subdomains", "Unusually deep subdomain chain", 10)
    if host.count("-") >= 3:
        add("hyphenated_host", "Host contains many hyphens (common in lookalike domains)", 10)

    # Non-standard port
    if parsed.port and parsed.port not in (80, 443):
        add("odd_port", f"Non-standard port {parsed.port}", 10)

    # Very long URL
    if len(url) > 100:
        add("long_url", "Unusually long URL, often used to hide the real destination", 10)

    return {"type": "url", "input": url, "host": host, "signals": [
        {"id": sid, "description": desc, "base_score": score} for sid, desc, score in signals
    ]}
