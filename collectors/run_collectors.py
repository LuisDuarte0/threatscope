from datetime import datetime
from database.db_handler import insert_iocs, log_collection_run, init_db
from collectors.otx_collector import collect_otx
from collectors.abuseipdb_collector import collect_abuseipdb
from processors.normalizer import normalize_ioc_list


def run_all():
    init_db()
    print(f"[{datetime.utcnow().isoformat()}] Starting collection run...")

    sources = [
        ("OTX",       collect_otx),
        ("AbuseIPDB", collect_abuseipdb),
    ]

    for source_name, collector_fn in sources:
        started = datetime.utcnow().isoformat()
        try:
            print(f"  → Collecting from {source_name}...")
            raw_iocs   = collector_fn()
            clean_iocs = normalize_ioc_list(raw_iocs)
            count      = insert_iocs(clean_iocs)
            print(f"  ✓ {source_name}: {count} IoCs inserted")
            log_collection_run(
                source=source_name,
                status="success",
                iocs_collected=count,
                started_at=started,
                finished_at=datetime.utcnow().isoformat()
            )
        except Exception as e:
            print(f"  ✗ {source_name} failed: {e}")
            log_collection_run(
                source=source_name,
                status="error",
                error_message=str(e),
                started_at=started,
                finished_at=datetime.utcnow().isoformat()
            )

    print(f"[{datetime.utcnow().isoformat()}] Collection run complete.\n")


if __name__ == "__main__":
    run_all()
