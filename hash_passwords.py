import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = "rru.db"

def hash_passwords():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # --- Update Teachers Passwords ---
    cur.execute("SELECT id, password FROM teachers")
    teachers = cur.fetchall()
    for tid, pwd in teachers:
        # अगर पहले से hashed नहीं है तभी hash करो
        if not pwd.startswith("pbkdf2:sha256"):
            hashed = generate_password_hash(pwd)
            cur.execute("UPDATE teachers SET password=? WHERE id=?", (hashed, tid))

    # --- Update Students Passwords ---
    cur.execute("SELECT id, password FROM students")
    students = cur.fetchall()
    for sid, pwd in students:
        if not pwd.startswith("pbkdf2:sha256"):
            hashed = generate_password_hash(pwd)
            cur.execute("UPDATE students SET password=? WHERE id=?", (hashed, sid))

    conn.commit()
    conn.close()
    print("✅ All plain passwords converted to hashed successfully!")

if __name__ == "__main__":
    hash_passwords()
