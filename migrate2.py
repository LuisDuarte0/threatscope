import sqlite3

conn = sqlite3.connect('threatscope.db')

# Ver exemplos do formato atual
samples = conn.execute(
    "SELECT collected_at FROM iocs WHERE collected_at LIKE '%T%' LIMIT 5"
).fetchall()

print("Exemplos de registros restantes:")
for s in samples:
    print(" ", s[0])

# Corrigir substituindo o T por espaço e cortando microsegundos
conn.execute("""
    UPDATE iocs
    SET collected_at = REPLACE(SUBSTR(collected_at, 1, 19), 'T', ' ')
    WHERE collected_at LIKE '%T%'
""")

conn.commit()

remaining = conn.execute(
    "SELECT COUNT(*) FROM iocs WHERE collected_at LIKE '%T%'"
).fetchone()[0]

print(f"Migration complete. Remaining old-format records: {remaining}")
conn.close()
