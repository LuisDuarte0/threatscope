import requests
from datetime import datetime
from config import OTX_API_KEY, OTX_BASE_URL, OTX_PULSE_LIMIT
from processors.scorer import calculate_severity


def collect_otx() -> list[dict]:
    if not OTX_API_KEY:
        raise ValueError("OTX_API_KEY not set in .env")

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    iocs = []

    # Fetch subscribed pulses
    url = f"{OTX_BASE_URL}/pulses/subscribed"
    params = {"limit": OTX_PULSE_LIMIT, "modified_since": "2024-01-01"}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        raise ConnectionError(f"OTX API error: {e}")

    for pulse in data.get("results", []):
        pulse_name = pulse.get("name", "")
        pulse_tags = ", ".join(pulse.get("tags", []))
        pulse_desc = pulse.get("description", "")

        for indicator in pulse.get("indicators", []):
            ioc_value = indicator.get("indicator", "")
            ioc_type  = _map_otx_type(indicator.get("type", ""))
            if not ioc_value or not ioc_type:
                continue

            score    = _score_otx_indicator(pulse, indicator)
            severity = calculate_severity(score)

            iocs.append({
                "value":       ioc_value,
                "ioc_type":    ioc_type,
                "source":      "OTX",
                "severity":    severity,
                "score":       score,
                "confidence":  None,
                "country":     indicator.get("country", None),
                "tags":        pulse_tags,
                "description": f"{pulse_name} — {pulse_desc}"[:300],
                "first_seen":  indicator.get("created", None),
                "last_seen":   indicator.get("expiration", None),
                "raw_data":    str(indicator),
            })

    return iocs


def _map_otx_type(otx_type: str) -> str:
    mapping = {
        "IPv4":         "IPv4",
        "IPv6":         "IPv6",
        "domain":       "domain",
        "hostname":     "hostname",
        "URL":          "URL",
        "FileHash-MD5": "FileHash-MD5",
        "FileHash-SHA1":"FileHash-SHA1",
        "FileHash-SHA256": "FileHash-SHA256",
    }
    return mapping.get(otx_type, "")


def _score_otx_indicator(pulse: dict, indicator: dict) -> float:
    score = 50.0  # baseline

    # Boost for adversary attribution
    if pulse.get("adversary"):
        score += 15

    # Boost for targeted countries
    targeted = pulse.get("targeted_countries", [])
    if targeted:
        score += min(len(targeted) * 2, 10)

    # Boost for malware families
    malware = pulse.get("malware_families", [])
    if malware:
        score += min(len(malware) * 3, 15)

    # Boost for attack IDs (MITRE ATT&CK)
    attack_ids = pulse.get("attack_ids", [])
    if attack_ids:
        score += min(len(attack_ids) * 2, 10)

    return min(score, 100.0)
