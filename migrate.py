import sqlite3

conn = sqlite3.connect('threatscope.db')

result = conn.execute("""
    UPDATE iocs
    SET collected_at = SUBSTR(collected_at, 1, 19)
    WHERE collected_at LIKE '%T%'
""")

conn.commit()

remaining = conn.execute(
    "SELECT COUNT(*) FROM iocs WHERE collected_at LIKE '%T%'"
).fetchone()[0]

print(f"Migration complete. Remaining old-format records: {remaining}")
conn.close()
