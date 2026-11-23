require("dotenv").config();
const express = require("express");
const path = require("path");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { body, param, validationResult } = require("express-validator");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const db = require("./src/db");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "development-only-change-this-secret";

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, limit: 50 }));

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ message: "Please check the submitted information.", errors: errors.array() });
  next();
}
function signToken(user) {
  return jwt.sign({ id: user.id, name: user.name, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || "2h" });
}
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ message: "Please sign in to continue." });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ message: "Your session has expired. Please sign in again." }); }
}
function allow(...roles) {
  return (req, res, next) => roles.includes(req.user.role) ? next() : res.status(403).json({ message: "You do not have permission to perform this action." });
}
function attendancePercent(present, total) {
  return total === 0 ? 0 : Math.round((present / total) * 100);
}
function riskFor(percent) {
  if (percent < 65) return "Critical";
  if (percent < 75) return "At Risk";
  return "Safe";
}
function getStudents() {
  return db.prepare("SELECT * FROM students ORDER BY name").all().map(s => ({
    ...s, percentage: attendancePercent(s.present, s.total), risk: riskFor(attendancePercent(s.present, s.total))
  }));
}

app.post("/api/auth/login", [
  body("email").isEmail().normalizeEmail(),
  body("password").isString().isLength({ min: 6, max: 100 })
], validate, (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(req.body.email);
  if (!user || !bcrypt.compareSync(req.body.password, user.password_hash)) return res.status(401).json({ message: "Invalid email or password." });
  const { password_hash, ...safeUser } = user;
  res.json({ token: signToken(user), user: safeUser });
});

app.get("/api/auth/me", auth, (req, res) => {
  const user = db.prepare("SELECT id, name, email, role FROM users WHERE id = ?").get(req.user.id);
  if (!user) return res.status(404).json({ message: "Account not found." });
  res.json({ user });
});

app.get("/api/dashboard", auth, (req, res) => {
  let students = getStudents();
  if (req.user.role === "student") students = students.filter(s => s.email === req.user.email);
  const totalStudents = students.length;
  const avg = totalStudents ? Math.round(students.reduce((a, s) => a + s.percentage, 0) / totalStudents) : 0;
  const safe = students.filter(s => s.percentage >= 75).length;
  const atRisk = students.filter(s => s.percentage >= 65 && s.percentage < 75).length;
  const critical = students.filter(s => s.percentage < 65).length;
  const subjects = db.prepare("SELECT subject, SUM(present) present, SUM(total) total FROM subject_attendance GROUP BY subject ORDER BY subject").all()
    .map(s => ({ ...s, percentage: attendancePercent(s.present, s.total) }));
  const recent = db.prepare(`SELECT a.id, s.name student, a.subject, a.status, a.date
    FROM attendance a JOIN students s ON s.id=a.student_id ORDER BY a.date DESC, a.id DESC LIMIT 6`).all();
  res.json({ stats: { totalStudents, average: avg, safe, atRisk, critical }, subjects, recent });
});

app.get("/api/students", auth, (req, res) => {
  let students = getStudents();
  if (req.user.role === "student") students = students.filter(s => s.email === req.user.email);
  res.json({ students });
});

app.post("/api/attendance", auth, allow("mentor", "admin"), [
  body("studentId").isInt({ min: 1 }),
  body("subject").trim().isLength({ min: 2, max: 60 }),
  body("status").isIn(["Present", "Absent"]),
  body("date").isISO8601()
], validate, (req, res) => {
  const student = db.prepare("SELECT id FROM students WHERE id = ?").get(Number(req.body.studentId));
  if (!student) return res.status(404).json({ message: "Student not found." });
  const tx = db.transaction(() => {
    db.prepare("INSERT INTO attendance (student_id, subject, status, date) VALUES (?, ?, ?, ?)")
      .run(Number(req.body.studentId), req.body.subject, req.body.status, req.body.date);
    const row = db.prepare("SELECT present, total FROM subject_attendance WHERE student_id=? AND subject=?").get(Number(req.body.studentId), req.body.subject);
    if (row) db.prepare("UPDATE subject_attendance SET present=?, total=? WHERE student_id=? AND subject=?")
      .run(row.present + (req.body.status === "Present" ? 1 : 0), row.total + 1, Number(req.body.studentId), req.body.subject);
    else db.prepare("INSERT INTO subject_attendance (student_id, subject, present, total) VALUES (?, ?, ?, 1)")
      .run(Number(req.body.studentId), req.body.subject, req.body.status === "Present" ? 1 : 0);
    const overall = db.prepare("SELECT present, total FROM students WHERE id=?").get(Number(req.body.studentId));
    db.prepare("UPDATE students SET present=?, total=? WHERE id=?")
      .run(overall.present + (req.body.status === "Present" ? 1 : 0), overall.total + 1, Number(req.body.studentId));
  });
  tx();
  res.status(201).json({ message: "Attendance saved successfully." });
});

app.get("/api/analytics", auth, allow("mentor", "admin"), (req, res) => {
  const departments = db.prepare(`SELECT department, COUNT(*) students, SUM(present) present, SUM(total) total
    FROM students GROUP BY department ORDER BY department`).all().map(d => ({ ...d, percentage: attendancePercent(d.present, d.total) }));
  const subjects = db.prepare(`SELECT subject, SUM(present) present, SUM(total) total FROM subject_attendance
    GROUP BY subject ORDER BY subject`).all().map(s => ({ ...s, percentage: attendancePercent(s.present, s.total) }));
  res.json({ departments, subjects });
});

app.get("/api/interventions", auth, allow("mentor", "admin"), (req, res) => {
  res.json({ interventions: db.prepare(`SELECT i.*, s.name student FROM interventions i JOIN students s ON s.id=i.student_id ORDER BY i.created_at DESC`).all() });
});
app.post("/api/interventions", auth, allow("mentor", "admin"), [
  body("studentId").isInt({ min: 1 }),
  body("note").trim().isLength({ min: 5, max: 500 })
], validate, (req, res) => {
  const student = db.prepare("SELECT id FROM students WHERE id=?").get(Number(req.body.studentId));
  if (!student) return res.status(404).json({ message: "Student not found." });
  db.prepare("INSERT INTO interventions (student_id, mentor_id, note) VALUES (?, ?, ?)")
    .run(Number(req.body.studentId), req.user.id, req.body.note.trim());
  res.status(201).json({ message: "Mentor intervention recorded." });
});

app.get("/api/health", (req, res) => res.json({ status: "ok", database: "connected" }));
app.use("/api", (req, res) => res.status(404).json({ message: "API endpoint not found." }));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

if (require.main === module) app.listen(PORT, () => console.log(`AttendAlert running at http://localhost:${PORT}`));
module.exports = { app, attendancePercent, riskFor };
