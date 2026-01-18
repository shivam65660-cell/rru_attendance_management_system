import sqlite3

DATABASE_FILE = 'rru.db' # Replace with your actual database file name

def drop_subjects_table():
    conn = None
    try:
        conn = sqlite3.connect("rru.db")
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS subjects")
        conn.commit()
        print("Table 'subjects' dropped successfully.")
    except sqlite3.Error as e:
        print(f"Error dropping table: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    drop_subjects_table()