import sqlite3

conn = sqlite3.connect("rru.db")
cur = conn.cursor()

queries = [
    "ALTER TABLE students ADD COLUMN otp_hash TEXT",
    "ALTER TABLE students ADD COLUMN otp_expiry DATETIME",
    "ALTER TABLE teachers ADD COLUMN otp_hash TEXT",
    "ALTER TABLE teachers ADD COLUMN otp_expiry DATETIME",
    "ALTER TABLE admins ADD COLUMN otp_hash TEXT",
    "ALTER TABLE admins ADD COLUMN otp_expiry DATETIME"
]

for q in queries:
    try:
        cur.execute(q)
    except Exception as e:
        print(f"Skipping: {q} -> {e}")

conn.commit()
conn.close()
print("OTP columns added!")
