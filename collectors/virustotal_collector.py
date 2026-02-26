import requests
from config import VT_API_KEY, VT_BASE_URL
from processors.scorer import calculate_severity


def enrich_ioc(value: str, ioc_type: str) -> dict:
    """Enrich a single IoC against VirusTotal."""
    if not VT_API_KEY:
        raise ValueError("VT_API_KEY not set in .env")

    headers = {"x-apikey": VT_API_KEY}
    endpoint = _get_endpoint(value, ioc_type)

    if not endpoint:
        return {"error": f"Unsupported IoC type for VT: {ioc_type}"}

    try:
        response = requests.get(
            f"{VT_BASE_URL}/{endpoint}",
            headers=headers,
            timeout=15
        )
        if response.status_code == 404:
            return {"error": "Not found in VirusTotal"}
        response.raise_for_status()
        data = response.json().get("data", {})
        return _parse_vt_response(data, ioc_type)
    except requests.RequestException as e:
        return {"error": str(e)}


def _get_endpoint(value: str, ioc_type: str) -> str:
    if ioc_type == "IPv4":
        return f"ip_addresses/{value}"
    elif ioc_type in ("domain", "hostname"):
        return f"domains/{value}"
    elif ioc_type == "URL":
        import base64
        url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
        return f"urls/{url_id}"
    elif ioc_type in ("FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"):
        return f"files/{value}"
    return ""


def _parse_vt_response(data: dict, ioc_type: str) -> dict:
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    total       = sum(stats.values()) if stats else 1

    vt_score = round(((malicious + suspicious) / max(total, 1)) * 100, 2)
    severity = calculate_severity(vt_score)

    return {
        "vt_score":         vt_score,
        "severity":         severity,
        "malicious_votes":  malicious,
        "suspicious_votes": suspicious,
        "total_engines":    total,
        "reputation":       attrs.get("reputation", None),
        "tags":             ", ".join(attrs.get("tags", [])),
        "country":          attrs.get("country", None),
        "last_analysis":    attrs.get("last_analysis_date", None),
        "names":            ", ".join(attrs.get("names", [])[:5]),
    }
