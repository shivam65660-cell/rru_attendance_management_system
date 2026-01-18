import sqlite3

conn = sqlite3.connect("rru.db")
cur = conn.cursor()

cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
print("Tables:", cur.fetchall())

cur.execute("PRAGMA table_info(students);")
columns = [col[1] for col in cur.fetchall()]

# optional: show schema for students
cur.execute("SELECT sql FROM sqlite_master WHERE name='students';")
print("students schema:\n", cur.fetchone()[0])

cur.execute("PRAGMA table_info(attendance);")
for col in cur.fetchall():
    print(col)
cur.execute("PRAGMA table_info(attendance);")
for col in cur.fetchall():
    print(col)
cur.execute("SELECT * FROM admins")
rows = cur.fetchall()
conn.close()

for row in rows:
    print(row)
