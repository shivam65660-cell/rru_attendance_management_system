import sqlite3

conn = sqlite3.connect("rru.db")
cur = conn.cursor()

cur.execute("""
DELETE FROM subjects
WHERE id NOT IN (
    SELECT MIN(id)
    FROM subjects
    GROUP BY subject_name
);
""")

conn.commit()
conn.close()

print("Duplicate subjects removed successfully.")
