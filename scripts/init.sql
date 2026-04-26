-- Zero-Trust Ecosystem Database Schema
-- PostgreSQL 16

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Professors ────────────────────────────────────────────────────────────────
CREATE TABLE professors (
  id           VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
  name         VARCHAR(120) NOT NULL,
  email        VARCHAR(120) UNIQUE NOT NULL,
  department   VARCHAR(80),
  title        VARCHAR(80),
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ── Students ──────────────────────────────────────────────────────────────────
CREATE TABLE students (
  id            VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
  name          VARCHAR(120) NOT NULL,
  email         VARCHAR(120) UNIQUE NOT NULL,
  department    VARCHAR(80),
  enrolled_year INTEGER,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ── Courses ───────────────────────────────────────────────────────────────────
CREATE TABLE courses (
  id            VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
  name          VARCHAR(160) NOT NULL,
  description   TEXT,
  credits       INTEGER DEFAULT 3,
  department    VARCHAR(80),
  professor_id  VARCHAR(36) REFERENCES professors(id),
  room          VARCHAR(40),
  schedule_time VARCHAR(60),
  is_public     BOOLEAN DEFAULT true,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ── Enrollments ───────────────────────────────────────────────────────────────
CREATE TABLE enrollments (
  id          VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
  student_id  VARCHAR(36) REFERENCES students(id),
  course_id   VARCHAR(36) REFERENCES courses(id),
  enrolled_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(student_id, course_id)
);

-- ── Grades ────────────────────────────────────────────────────────────────────
CREATE TABLE grades (
  id           VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
  student_id   VARCHAR(36) REFERENCES students(id),
  course_id    VARCHAR(36) REFERENCES courses(id),
  grade        VARCHAR(4),
  semester     VARCHAR(20),
  submitted_by VARCHAR(36),
  submitted_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(student_id, course_id, semester)
);

-- ── Events ────────────────────────────────────────────────────────────────────
CREATE TABLE events (
  id          VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
  title       VARCHAR(160) NOT NULL,
  description TEXT,
  event_date  TIMESTAMPTZ,
  location    VARCHAR(120),
  organizer   VARCHAR(120),
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── Announcements ─────────────────────────────────────────────────────────────
CREATE TABLE announcements (
  id           VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
  title        VARCHAR(200) NOT NULL,
  body         TEXT,
  category     VARCHAR(60),
  is_public    BOOLEAN DEFAULT true,
  published_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── Seed data ─────────────────────────────────────────────────────────────────
INSERT INTO professors (id, name, email, department, title) VALUES
  ('u-002', 'Dr. Sarah Chen',    'professor@uni.edu', 'Computer Science', 'Associate Professor'),
  ('p-003', 'Dr. James Okoye',   'j.okoye@uni.edu',  'Mathematics',      'Professor'),
  ('p-004', 'Dr. Aisha Patel',   'a.patel@uni.edu',  'Physics',          'Assistant Professor');

INSERT INTO students (id, name, email, department, enrolled_year) VALUES
  ('u-001', 'Alex Rivera',   'student@uni.edu', 'Computer Science', 2022),
  ('s-002', 'Maya Johnson',  'm.johnson@uni.edu','Mathematics',      2023),
  ('s-003', 'Liam Park',     'l.park@uni.edu',  'Physics',          2021);

INSERT INTO courses (id, name, description, credits, department, professor_id, room, schedule_time) VALUES
  ('c-001', 'CS301: Algorithms',        'Advanced algorithm design',    3, 'Computer Science', 'u-002', 'B-201', 'Mon/Wed 10:00'),
  ('c-002', 'CS450: Security Systems',  'Zero-trust & secure systems',  3, 'Computer Science', 'u-002', 'A-105', 'Tue/Thu 14:00'),
  ('c-003', 'MATH201: Linear Algebra',  'Vectors, matrices, transforms',3, 'Mathematics',      'p-003', 'C-301', 'Mon/Wed 09:00'),
  ('c-004', 'PHYS301: Quantum Mech.',   'Introduction to QM',           4, 'Physics',          'p-004', 'D-401', 'Tue/Thu 11:00');

INSERT INTO enrollments (student_id, course_id) VALUES
  ('u-001', 'c-001'), ('u-001', 'c-002'),
  ('s-002', 'c-003'), ('s-003', 'c-004');

INSERT INTO grades (student_id, course_id, grade, semester, submitted_by) VALUES
  ('u-001', 'c-001', 'A-', 'Fall 2024',   'u-002'),
  ('u-001', 'c-002', 'B+', 'Fall 2024',   'u-002'),
  ('s-002', 'c-003', 'A',  'Fall 2024',   'p-003'),
  ('s-003', 'c-004', 'B',  'Fall 2024',   'p-004');

INSERT INTO events (title, description, event_date, location, organizer) VALUES
  ('Open House 2025',          'Annual university open day',       NOW() + INTERVAL '30 days',  'Main Auditorium', 'Admissions'),
  ('CS Hackathon',             '24-hour coding challenge',         NOW() + INTERVAL '14 days',  'Engineering Hall','CS Society'),
  ('Research Symposium',       'Graduate research presentations',  NOW() + INTERVAL '60 days',  'Conference Center','Research Office');

INSERT INTO announcements (title, body, category) VALUES
  ('Spring Enrollment Open',   'Enrollment for Spring 2025 is now open until January 15.',     'Academic'),
  ('Campus Network Upgrade',   'Scheduled maintenance on Jan 5 from 02:00-06:00 UTC.',         'IT'),
  ('Zero-Trust Policy Update', 'New authentication policies take effect February 1, 2025.',    'Security');

-- Indexes
CREATE INDEX idx_grades_student    ON grades(student_id);
CREATE INDEX idx_grades_course     ON grades(course_id);
CREATE INDEX idx_enrollments_student ON enrollments(student_id);
CREATE INDEX idx_courses_professor ON courses(professor_id);
CREATE INDEX idx_courses_dept      ON courses(department);
