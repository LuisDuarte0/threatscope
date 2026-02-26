from config import (
    SEVERITY_CRITICAL, SEVERITY_HIGH,
    SEVERITY_MEDIUM, SEVERITY_LOW,
    WEIGHT_OTX, WEIGHT_ABUSEIPDB, WEIGHT_VT
)


def calculate_severity(score: float) -> str:
    if score >= SEVERITY_CRITICAL:
        return "Critical"
    elif score >= SEVERITY_HIGH:
        return "High"
    elif score >= SEVERITY_MEDIUM:
        return "Medium"
    return "Low"


def composite_score(otx_score: float = None,
                    abuse_score: float = None,
                    vt_score: float = None) -> float:
    """
    Weighted composite score across the three sources.
    Only averages available scores — skips None values and
    redistributes weights proportionally.
    """
    components = []
    weights    = []

    if otx_score is not None:
        components.append(otx_score)
        weights.append(WEIGHT_OTX)
    if abuse_score is not None:
        components.append(abuse_score)
        weights.append(WEIGHT_ABUSEIPDB)
    if vt_score is not None:
        components.append(vt_score)
        weights.append(WEIGHT_VT)

    if not components:
        return 0.0

    total_weight = sum(weights)
    score = sum(c * w for c, w in zip(components, weights)) / total_weight
    return round(min(score, 100.0), 2)


def confidence_label(score: float) -> str:
    if score >= 80:
        return "High Confidence"
    elif score >= 50:
        return "Medium Confidence"
    return "Low Confidence"


def severity_color(severity: str) -> str:
    colors = {
        "Critical": "#FF4B4B",
        "High":     "#FF8C00",
        "Medium":   "#FFD700",
        "Low":      "#00CC88",
    }
    return colors.get(severity, "#AAAAAA")
