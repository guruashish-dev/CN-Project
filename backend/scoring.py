from collections import Counter


SEVERITY_SCORE = {
    "Low": 2,
    "Medium": 5,
    "High": 8,
    "Critical": 10,
}


def calculate_risk_score(findings):
    if not findings:
        return {"score": 0, "label": "Informational", "distribution": {}}
    vals = [SEVERITY_SCORE.get(f.get("severity", "Low"), 1) for f in findings]
    score = min(100, int(sum(vals) / (len(vals) * 10) * 100))
    label = "Low"
    if score >= 75:
        label = "Critical"
    elif score >= 55:
        label = "High"
    elif score >= 30:
        label = "Medium"
    dist = dict(Counter(f.get("severity", "Low") for f in findings))
    return {"score": score, "label": label, "distribution": dist}
