import sqlite3
import os
import shutil
import sys
sys.stdout.reconfigure(encoding='utf-8')

DB = "rru.db"

# 1) Backup
if not os.path.exists(DB + ".bak"):
    shutil.copy(DB, DB + ".bak")
    print("Backup created:", DB + ".bak")
else:
    print("Backup already exists:", DB + ".bak")

conn = sqlite3.connect(DB)
cur = conn.cursor()  

# Disable foreign keys for migration
cur.execute("PRAGMA foreign_keys = OFF;")
# 1a) Create schools table if not exists
# 2) Create courses table (with school_id if not exists)
cur.execute("""
CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_name TEXT NOT NULL UNIQUE,
    school_id INTEGER,
    FOREIGN KEY(school_id) REFERENCES schools(id)
);
""")
print("Ensured table: courses")

# 2a) Add missing school_id column (for older DBs)
cols = [r[1] for r in cur.execute("PRAGMA table_info(courses)").fetchall()]
if "school_id" not in cols:
    cur.execute("ALTER TABLE courses ADD COLUMN school_id INTEGER;")
    print("Added column: courses.school_id")
else:
    print("Column courses.school_id exists")

# 3) Add semester and course_id columns to students if missing
cols = [r[1] for r in cur.execute("PRAGMA table_info(students)").fetchall()]
if "semester" not in cols:
    cur.execute("ALTER TABLE students ADD COLUMN semester INTEGER DEFAULT 1;")
    print("Added column: students.semester")
else:
    print("Column students.semester exists")

if "course_id" not in cols:
    cur.execute("ALTER TABLE students ADD COLUMN course_id INTEGER;")
    print("Added column: students.course_id")
else:
    print("Column students.course_id exists")

conn.commit()

# 10) Add school_id to students if missing
cols = [r[1] for r in cur.execute("PRAGMA table_info(students)").fetchall()]
if "school_id" not in cols:
    cur.execute("ALTER TABLE students ADD COLUMN school_id INTEGER;")
    print("Added column: students.school_id")
else:
    print("Column students.school_id exists")
    conn.commit()


# 4) Migrate existing course names into courses table
cur.execute("SELECT DISTINCT course FROM students WHERE course IS NOT NULL AND TRIM(course) != '';")
rows = cur.fetchall()
for (c,) in rows:
    name = c.strip()
    if name:
        cur.execute("INSERT OR IGNORE INTO courses (course_name) VALUES (?)", (name,))
conn.commit()
print("Migrated distinct course names into courses table")

# Build mapping: course_name -> id
cur.execute("SELECT id, course_name FROM courses")
map_rows = cur.fetchall()
course_map = {name: cid for (cid, name) in map_rows}

# 5) Update students.course_id based on students.course (text)
cur.execute("SELECT id, course FROM students")
for sid, course_text in cur.fetchall():
    if course_text and course_text.strip() != "":
        cname = course_text.strip()
        cid = course_map.get(cname)
        if cid:
            cur.execute("UPDATE students SET course_id=? WHERE id=?", (cid, sid))
conn.commit()
print("Updated students.course_id from students.course")

# 6) Create upgraded attendance table (with remark, course_id, semester)
cur.execute("""
CREATE TABLE IF NOT EXISTS attendance_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    semester INTEGER NOT NULL,
    date TEXT NOT NULL,
    status TEXT NOT NULL,
    remark TEXT,
    marked_by INTEGER,
    FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,
    FOREIGN KEY(course_id) REFERENCES courses(id),
    FOREIGN KEY(marked_by) REFERENCES teachers(id),
    UNIQUE(student_id, course_id, date)
);
""")
conn.commit()
print("Created upgraded table: attendance_new (with remark)")

# 6b) Create subjects table if not exists
cur.execute("""
CREATE TABLE IF NOT EXISTS subjects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_name TEXT NOT NULL,
    course_id INTEGER NOT NULL,
    semester INTEGER NOT NULL,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
    UNIQUE (subject_name, course_id, semester)
);
""")
print("Ensured table: subjects")

# 6c) Create teacher_subjects table if not exists
cur.execute("""
CREATE TABLE IF NOT EXISTS teacher_subjects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    teacher_id INTEGER,
    subject_id INTEGER,
    UNIQUE(teacher_id, subject_id),
    FOREIGN KEY (teacher_id) REFERENCES teachers(id),
    FOREIGN KEY (subject_id) REFERENCES subjects(id)
);
""")
print("Ensured table: teacher_subjects")

# 7) Migrate old attendance data
cur.execute("SELECT id, student_id, date, status FROM attendance")
old_rows = cur.fetchall()
count = 0
for aid, sid, date_str, status in old_rows:
    cur.execute("SELECT course_id, semester FROM students WHERE id=?", (sid,))
    r = cur.fetchone()
    if r:
        course_id = r[0] if r[0] is not None else 0
        semester = r[1] if r[1] is not None else 1
    else:
        course_id = 0
        semester = 1
    try:
        cur.execute("""
            INSERT OR IGNORE INTO attendance_new
            (student_id, course_id, semester, date, status, remark, marked_by)
            VALUES (?, ?, ?, ?, ?, NULL, NULL)
        """, (sid, course_id, semester, date_str, status))
        count += 1
    except Exception as e:
        print("Skipped id", aid, "Error:", e)
conn.commit()
print(f"Migrated {count} attendance rows")


# 12) Create teacher_courses linking table (school_id, course_id, subject_id, semester)
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='teacher_courses'")
if not cur.fetchone():
    cur.execute("""
    CREATE TABLE teacher_courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        teacher_id INTEGER NOT NULL,
        school_id INTEGER NOT NULL,
        course_id INTEGER NOT NULL,
        subject_id INTEGER NOT NULL,
        semester INTEGER NOT NULL,
        FOREIGN KEY (teacher_id) REFERENCES teachers(id),
        FOREIGN KEY (school_id) REFERENCES schools(id),
        FOREIGN KEY (course_id) REFERENCES courses(id),
        FOREIGN KEY (subject_id) REFERENCES subjects(id)
    )
    """)
    print("Created new table: teacher_courses (linking table)")
else:
    print("teacher_courses already exists, skipping")

# 9) Add school_id to teachers table if missing
cols = [r[1] for r in cur.execute("PRAGMA table_info(teachers)").fetchall()]
if "school_id" not in cols:
    cur.execute("ALTER TABLE teachers ADD COLUMN school_id INTEGER;")
    print("Added column: teachers.school_id")
else:
    print("Column teachers.school_id exists")

# 13) Create notifications table if not exists
cur.execute("""
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    teacher_id INTEGER NOT NULL,
    school_id INTEGER,
    course_id INTEGER,
    semester INTEGER,
    subject_id INTEGER,
    student_id INTEGER,  -- NULL => broadcast to matching students
    title TEXT NOT NULL,
    message TEXT,
    file_path TEXT,
    file_name TEXT,
    mime_type TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    is_active INTEGER DEFAULT 1,
    FOREIGN KEY (teacher_id) REFERENCES teachers(id),
    FOREIGN KEY (school_id) REFERENCES schools(id),
    FOREIGN KEY (course_id) REFERENCES courses(id),
    FOREIGN KEY (subject_id) REFERENCES subjects(id),
    FOREIGN KEY (student_id) REFERENCES students(id)
);
""")

# Indexes for performance
cur.execute("CREATE INDEX IF NOT EXISTS idx_notifications_teacher ON notifications (teacher_id);")
cur.execute("CREATE INDEX IF NOT EXISTS idx_notifications_student ON notifications (student_id);")
cur.execute("CREATE INDEX IF NOT EXISTS idx_notifications_course_sem ON notifications (course_id, semester);")

print("Ensured table: notifications (teacher -> student messages/attachments)")

# 11) Update students.school_id based on their course_id
cur.execute("SELECT id, course_id FROM students WHERE course_id IS NOT NULL")
rows = cur.fetchall()
for sid, cid in rows:
    cur.execute("SELECT school_id FROM courses WHERE id=?", (cid,))
    r = cur.fetchone()
    if r and r[0]:
        cur.execute("UPDATE students SET school_id=? WHERE id=?", (r[0], sid))
conn.commit()
print("Updated students.school_id from courses table")

# 8) Rename tables
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='attendance_old'")
if not cur.fetchone():
    cur.execute("ALTER TABLE attendance RENAME TO attendance_old;")
    cur.execute("ALTER TABLE attendance_new RENAME TO attendance;")
    conn.commit()
    print("Renamed tables: attendance -> attendance_old, attendance_new -> attendance")
else:
    print("attendance_old already exists, skipping rename")

# Re-enable foreign keys
cur.execute("PRAGMA foreign_keys = ON;")
conn.commit()
conn.close()
print("Migration complete. Backup at:", DB + ".bak")