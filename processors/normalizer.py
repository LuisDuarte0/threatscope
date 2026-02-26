import re
import pandas as pd


def normalize_ioc_list(iocs: list[dict]) -> list[dict]:
    """Clean and normalize a list of raw IoC dicts before DB insertion."""
    normalized = []
    for ioc in iocs:
        value = _clean_value(ioc.get("value", ""))
        if not value:
            continue
        ioc["value"]       = value
        ioc["ioc_type"]    = ioc.get("ioc_type", "unknown").strip()
        ioc["source"]      = ioc.get("source", "unknown").strip()
        ioc["description"] = _truncate(ioc.get("description", ""), 400)
        ioc["tags"]        = _truncate(ioc.get("tags", ""), 200)
        normalized.append(ioc)
    return normalized


def _clean_value(value: str) -> str:
    if not value:
        return ""
    value = value.strip()
    # Defang common patterns: hxxp → http, [.] → .
    value = re.sub(r"hxxp", "http", value, flags=re.IGNORECASE)
    value = re.sub(r"\[\.\]", ".", value)
    value = re.sub(r"\[at\]", "@", value, flags=re.IGNORECASE)
    return value


def _truncate(text: str, max_len: int) -> str:
    if not text:
        return ""
    return text[:max_len]


def dataframe_to_display(df: pd.DataFrame) -> pd.DataFrame:
    """Prepare a DataFrame for Streamlit display — rename and select columns."""
    if df.empty:
        return df

    display_cols = {
        "value":        "IoC Value",
        "ioc_type":     "Type",
        "source":       "Source",
        "severity":     "Severity",
        "score":        "Score",
        "country":      "Country",
        "tags":         "Tags",
        "description":  "Description",
        "collected_at": "Collected At",
    }

    available = [c for c in display_cols if c in df.columns]
    df = df[available].rename(columns=display_cols)

    if "Score" in df.columns:
        df["Score"] = df["Score"].round(1).map("{:.1f}".format)
    if "Collected At" in df.columns:
        df["Collected At"] = pd.to_datetime(
            df["Collected At"], errors="coerce"
        ).dt.strftime("%Y-%m-%d %H:%M")

    return df
