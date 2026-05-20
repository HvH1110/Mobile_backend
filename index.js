require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());

const SECRET_KEY = process.env.JWT_SECRET; 
if (!SECRET_KEY) {
  console.error("FATAL ERROR: JWT_SECRET is not defined!");
  process.exit(1); 
}

// Connect to Cloud SQL using the Public IP and Password
const pool = new Pool({
  user: 'postgres',
  password: process.env.DB_PASSWORD,
  database: 'postgres',
  host: process.env.DB_HOST,
  port: 5432,
  ssl: { rejectUnauthorized: false } // Required for connecting to cloud databases locally
});

// ==========================================
// AUTHENTICATION ROUTES
// ==========================================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    await pool.query(
      'INSERT INTO users (email, password, role) VALUES ($1, $2, $3)',
      [email, hashedPassword, role]
    );
    res.status(201).json({ message: "User registered successfully!" });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    if (err.code === '23505') return res.status(400).json({ error: "Email already exists" });
    res.status(500).json({ error: "Database error" });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: "User not found" });

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '24h' });
    res.json({ message: "Login successful", token: token, role: user.role });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// ==========================================
// MIDDLEWARE (Privileges)
// ==========================================
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; 
  if (!token) return res.status(403).json({ error: "No token provided." });

  jwt.verify(token, SECRET_KEY, (err, decodedUser) => {
    if (err) return res.status(403).json({ error: "Invalid token." });
    req.user = decodedUser; 
    next(); 
  });
};

const verifyTeacher = (req, res, next) => {
  if (req.user.role !== 'teacher') {
    return res.status(403).json({ error: "Access denied. Teachers only." });
  }
  next();
};

// ==========================================
// ASSIGNMENT ROUTES
// ==========================================
app.post('/api/assignments', verifyToken, verifyTeacher, async (req, res) => {
  try {
    const { title, description, dueDate } = req.body;
    await pool.query(
      'INSERT INTO assignments (teacher_id, title, description, due_date) VALUES ($1, $2, $3, $4)',
      [req.user.id, title, description, dueDate]
    );
    res.status(201).json({ message: "Assignment created successfully!" });
  } catch (err) {
    console.error("ASSIGNMENT ERROR:", err);
    res.status(500).json({ error: "Failed to create assignment" });
  }
});

app.get('/api/assignments', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM assignments ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch assignments" });
  }
});

// ==========================================
// DROP TEST DATA ROUTES
// ==========================================
app.post('/api/submissions', verifyToken, async (req, res) => {
  try {
    const { testNum, time, speed, velocity, acc } = req.body;
    await pool.query(
      'INSERT INTO submissions (user_id, test_num, time_seconds, speed, velocity, peak_acc) VALUES ($1, $2, $3, $4, $5, $6)',
      [req.user.id, testNum, time, speed, velocity, acc]
    );
    res.status(201).json({ message: "Data securely saved to database!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to save data" });
  }
});

const port = process.env.PORT || 8080; 
app.listen(port, () => console.log(`Backend Server running LOCALLY on port ${port} connected to Cloud Database!`));