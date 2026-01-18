import sqlite3

conn = sqlite3.connect("rru.db")
cur = conn.cursor()

# Staff table create
cur.execute("""
CREATE TABLE IF NOT EXISTS staff (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    school_id INTEGER NOT NULL,
    FOREIGN KEY (school_id) REFERENCES schools(id)
)
""")

conn.commit()
conn.close()
print(" staff table created successfully.")
