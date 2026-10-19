PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS schools(id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
 w_test INT NOT NULL DEFAULT 20, w_mid INT NOT NULL DEFAULT 30, w_final INT NOT NULL DEFAULT 50, CHECK(w_test+w_mid+w_final=100));
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN('office','school_admin','teacher')), school_id INT REFERENCES schools(id),
 must_change INT NOT NULL DEFAULT 1, fails INT NOT NULL DEFAULT 0, locked_until INT NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, csrf TEXT NOT NULL, expires INT NOT NULL);
CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY, sid TEXT UNIQUE NOT NULL, school_id INT NOT NULL REFERENCES schools(id),
 name TEXT NOT NULL, birth_date TEXT NOT NULL, grade INT NOT NULL CHECK(grade BETWEEN 9 AND 12), section TEXT NOT NULL, year INT NOT NULL);
CREATE TABLE IF NOT EXISTS subjects(id INTEGER PRIMARY KEY, school_id INT NOT NULL REFERENCES schools(id), name TEXT NOT NULL, UNIQUE(school_id,name));
CREATE TABLE IF NOT EXISTS assignments(teacher_id INT REFERENCES users(id), subject_id INT REFERENCES subjects(id), grade INT, section TEXT,
 PRIMARY KEY(teacher_id,subject_id,grade,section));
CREATE TABLE IF NOT EXISTS marks(student_id INT REFERENCES students(id), subject_id INT REFERENCES subjects(id),
 semester INT CHECK(semester IN(1,2)), test REAL CHECK(test>=0), mid REAL CHECK(mid>=0), final REAL CHECK(final>=0),
 submitted INT NOT NULL DEFAULT 0, PRIMARY KEY(student_id,subject_id,semester));
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts INT, user_id INT, action TEXT);
