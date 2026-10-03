"""Deterministic risk scoring from analyzer signals."""


def compute_risk(signals: list[dict]) -> dict:
    total = sum(s.get("base_score", 0) for s in signals)
    score = min(100, total)
    if score >= 70:
        level = "HIGH"
        emoji = "🔴"
    elif score >= 40:
        level = "MEDIUM"
        emoji = "🟠"
    elif score > 0:
        level = "LOW"
        emoji = "🟡"
    else:
        level = "SAFE"
        emoji = "🟢"
    return {"score": score, "level": level, "emoji": emoji}
