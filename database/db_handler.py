import sqlite3
import pandas as pd
from datetime import datetime
from config import DB_PATH


def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            value           TEXT NOT NULL,
            ioc_type        TEXT NOT NULL,
            source          TEXT NOT NULL,
            severity        TEXT NOT NULL,
            score           REAL NOT NULL,
            confidence      REAL,
            country         TEXT,
            tags            TEXT,
            description     TEXT,
            first_seen      TEXT,
            last_seen       TEXT,
            collected_at    TEXT NOT NULL,
            raw_data        TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS collection_runs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source          TEXT NOT NULL,
            status          TEXT NOT NULL,
            iocs_collected  INTEGER DEFAULT 0,
            error_message   TEXT,
            started_at      TEXT NOT NULL,
            finished_at     TEXT
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_value     ON iocs(value);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type      ON iocs(ioc_type);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_severity  ON iocs(severity);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_collected ON iocs(collected_at);")

    conn.commit()
    conn.close()


def insert_iocs(ioc_list: list[dict]) -> int:
    if not ioc_list:
        return 0
    conn = get_connection()
    cursor = conn.cursor()
    inserted = 0
    for ioc in ioc_list:
        cursor.execute("""
            INSERT INTO iocs
                (value, ioc_type, source, severity, score, confidence,
                 country, tags, description, first_seen, last_seen,
                 collected_at, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ioc.get("value"),
            ioc.get("ioc_type"),
            ioc.get("source"),
            ioc.get("severity"),
            ioc.get("score", 0.0),
            ioc.get("confidence"),
            ioc.get("country"),
            ioc.get("tags"),
            ioc.get("description"),
            ioc.get("first_seen"),
            ioc.get("last_seen"),
            datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            ioc.get("raw_data"),
        ))
        inserted += 1
    conn.commit()
    conn.close()
    return inserted


def fetch_iocs(
    ioc_type: str = None,
    source: str = None,
    severity: str = None,
    date_from: str = None,
    date_to: str = None,
    limit: int = 500,
) -> pd.DataFrame:
    conn = get_connection()
    query = "SELECT * FROM iocs WHERE 1=1"
    params = []

    if ioc_type and ioc_type != "All":
        query += " AND ioc_type = ?"
        params.append(ioc_type)
    if source and source != "All":
        query += " AND source = ?"
        params.append(source)
    if severity and severity != "All":
        query += " AND severity = ?"
        params.append(severity)
    if date_from:
        query += " AND DATE(collected_at) >= ?"
        params.append(str(date_from)[:10])
    if date_to:
        query += " AND DATE(collected_at) <= ?"
        params.append(str(date_to)[:10])

    query += " ORDER BY collected_at DESC LIMIT ?"
    params.append(limit)

    df = pd.read_sql_query(query, conn, params=params)
    conn.close()
    return df


def fetch_ioc_by_value(value: str) -> pd.DataFrame:
    conn = get_connection()
    df = pd.read_sql_query(
        "SELECT * FROM iocs WHERE value = ? ORDER BY collected_at DESC",
        conn, params=[value]
    )
    conn.close()
    return df


def fetch_stats() -> dict:
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM iocs")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM iocs WHERE severity = 'Critical'")
    critical = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM iocs WHERE severity = 'High'")
    high = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM iocs WHERE severity = 'Medium'")
    medium = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM iocs WHERE severity = 'Low'")
    low = cursor.fetchone()[0]

    cursor.execute(
        "SELECT source, COUNT(*) as cnt FROM iocs GROUP BY source"
    )
    by_source = {row["source"]: row["cnt"] for row in cursor.fetchall()}

    cursor.execute(
        "SELECT ioc_type, COUNT(*) as cnt FROM iocs GROUP BY ioc_type"
    )
    by_type = {row["ioc_type"]: row["cnt"] for row in cursor.fetchall()}

    conn.close()
    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "by_source": by_source,
        "by_type": by_type,
    }


def log_collection_run(source: str, status: str,
                       iocs_collected: int = 0,
                       error_message: str = None,
                       started_at: str = None,
                       finished_at: str = None):
    conn = get_connection()
    conn.execute("""
        INSERT INTO collection_runs
            (source, status, iocs_collected, error_message, started_at, finished_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (source, status, iocs_collected, error_message,
          started_at or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
          finished_at or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()