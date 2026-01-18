# seed_admin.py
import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("rru.db")
cur = conn.cursor()

username = "shivam"
password = generate_password_hash("shivam123")

cur.execute("INSERT OR IGNORE INTO admins (username, password) VALUES (?, ?)", (username, password))
conn.commit()
conn.close()

print("Default admin created (username=shivam, password=shivam123)")
