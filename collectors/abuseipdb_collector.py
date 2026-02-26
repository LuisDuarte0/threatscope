import requests
from config import ABUSEIPDB_API_KEY, ABUSEIPDB_BASE_URL, ABUSEIPDB_LIMIT, CONFIDENCE_DAYS
from processors.scorer import calculate_severity


def collect_abuseipdb() -> list[dict]:
    if not ABUSEIPDB_API_KEY:
        raise ValueError("ABUSEIPDB_API_KEY not set in .env")

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    params = {
        "confidenceMinimum": 50,
        "limit": ABUSEIPDB_LIMIT,
    }

    try:
        response = requests.get(
            f"{ABUSEIPDB_BASE_URL}/blacklist",
            headers=headers,
            params=params,
            timeout=15
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        raise ConnectionError(f"AbuseIPDB API error: {e}")

    iocs = []
    for entry in data.get("data", []):
        ip          = entry.get("ipAddress", "")
        confidence  = entry.get("abuseConfidenceScore", 0)
        country     = entry.get("countryCode", None)
        last_seen   = entry.get("lastReportedAt", None)
        isp         = entry.get("isp", "")
        usage_type  = entry.get("usageType", "")

        if not ip:
            continue

        score    = float(confidence)
        severity = calculate_severity(score)

        iocs.append({
            "value":       ip,
            "ioc_type":    "IPv4",
            "source":      "AbuseIPDB",
            "severity":    severity,
            "score":       score,
            "confidence":  confidence,
            "country":     country,
            "tags":        usage_type,
            "description": f"ISP: {isp} | Usage: {usage_type}",
            "first_seen":  None,
            "last_seen":   last_seen,
            "raw_data":    str(entry),
        })

    return iocs


def enrich_ip(ip: str) -> dict:
    """Enrich a single IP against AbuseIPDB."""
    if not ABUSEIPDB_API_KEY:
        raise ValueError("ABUSEIPDB_API_KEY not set in .env")

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    params = {
        "ipAddress":    ip,
        "maxAgeInDays": CONFIDENCE_DAYS,
        "verbose":      True,
    }

    try:
        response = requests.get(
            f"{ABUSEIPDB_BASE_URL}/check",
            headers=headers,
            params=params,
            timeout=15
        )
        response.raise_for_status()
        return response.json().get("data", {})
    except requests.RequestException as e:
        return {"error": str(e)}
