"""Unified risk report builder: Risk -> Reason -> Evidence -> Recommendation."""
from .scoring import compute_risk

ACTION_HIGH = [
    "🚫 Do not click links or open attachments",
    "❌ Do not enter credentials or share OTPs",
    "✅ Verify independently via the official website or app",
]
ACTION_MED = [
    "⚠️ Proceed with caution; double-check the sender and domain",
    "✅ Prefer typing the official URL manually instead of clicking",
]
ACTION_LOW = [
    "🟢 No strong scam indicators found, but stay alert",
]
ACTION_SAFE = [
    "🟢 No risk indicators detected in this input",
]


def build_report(analysis: dict) -> dict:
    risk = compute_risk(analysis["signals"])
    level = risk["level"]
    actions = {"HIGH": ACTION_HIGH, "MEDIUM": ACTION_MED,
               "LOW": ACTION_LOW, "SAFE": ACTION_SAFE}[level]
    return {
        "input_type": analysis["type"],
        "input": analysis["input"],
        "risk": risk,
        "summary": (
            f"{risk['emoji']} {level} RISK — {risk['score']}/100. "
            f"{len(analysis['signals'])} signal(s) detected."
            if analysis["signals"]
            else f"{risk['emoji']} SAFE — no risk indicators detected."
        ),
        "signals": analysis["signals"],
        "recommended_actions": actions,
        "disclaimer": "Heuristic analysis only. Always verify independently before acting.",
    }
