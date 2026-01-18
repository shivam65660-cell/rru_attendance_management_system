import sqlite3, shutil, os

DB = "rru.db"

# backup
if not os.path.exists(DB + ".bak"):
    shutil.copy(DB, DB + ".bak")
    print("Backup created:", DB + ".bak")
else:
    print("Backup already exists:", DB + ".bak")

conn = sqlite3.connect(DB)
cur = conn.cursor()

# Ensure teacher_courses exists with full schema (create if missing)
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='teacher_courses'")
if not cur.fetchone():
    print("teacher_courses table not found -> creating full table.")
    cur.execute("""
    CREATE TABLE teacher_courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        teacher_id INTEGER NOT NULL,
        school_id INTEGER,
        course_id INTEGER,
        subject_id INTEGER,
        semester INTEGER DEFAULT 1,
        FOREIGN KEY(teacher_id) REFERENCES teachers(id),
        FOREIGN KEY(school_id) REFERENCES schools(id),
        FOREIGN KEY(course_id) REFERENCES courses(id),
        FOREIGN KEY(subject_id) REFERENCES subjects(id),
        UNIQUE(teacher_id, school_id, course_id, subject_id, semester)
    );
    """)
    conn.commit()
else:
    # Add missing columns if needed
    cols = [r[1] for r in cur.execute("PRAGMA table_info(teacher_courses)").fetchall()]
    if "school_id" not in cols:
        cur.execute("ALTER TABLE teacher_courses ADD COLUMN school_id INTEGER;")
        print("Added column: teacher_courses.school_id")
    if "course_id" not in cols:
        cur.execute("ALTER TABLE teacher_courses ADD COLUMN course_id INTEGER;")
        print("Added column: teacher_courses.course_id")
    if "subject_id" not in cols:
        cur.execute("ALTER TABLE teacher_courses ADD COLUMN subject_id INTEGER;")
        print("Added column: teacher_courses.subject_id")
    if "semester" not in cols:
        cur.execute("ALTER TABLE teacher_courses ADD COLUMN semester INTEGER DEFAULT 1;")
        print("Added column: teacher_courses.semester")
    conn.commit()

print("Migration done.")
conn.close()
