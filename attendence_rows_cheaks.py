import sqlite3
conn = sqlite3.connect("rru.db")

cursor = conn.execute("PRAGMA table_info(attendance)")
for row in cursor.fetchall():
    print(row)
conn.close()
