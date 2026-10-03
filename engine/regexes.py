"""Shared regexes — single source of truth for URL extraction/classification."""
import re

# Matches scheme'd URLs, www.-prefixed URLs, and bare domains with common TLDs.
URL_RE = re.compile(
    r"(https?://\S+|www\.\S+|\b[\w-]+\.(?:com|net|org|xyz|top|in|co|link|info)\b\S*)",
    re.I,
)
