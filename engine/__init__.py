"""TrustGuard detection engine package.

Layers:
- analyzers: URL and message analysis producing structured signals
- scoring: deterministic risk scoring from signals
- report: unified JSON risk report builder
"""
from .url_analyzer import analyze_url
from .message_analyzer import analyze_message
from .scoring import compute_risk
from .report import build_report

__all__ = ["analyze_url", "analyze_message", "compute_risk", "build_report"]
