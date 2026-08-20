const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

app.get('/', (req, res) => {
  res.send('Hostel API is running for free!');
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '1d' });
    res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/students/:id/timeline', authenticate, async (req, res) => {
  const studentId = req.params.id;
  try {
    const profile = await db.query('SELECT * FROM students WHERE id = $1', [studentId]);
    const allocations = await db.query(
      'SELECT sa.*, b.bed_number, r.room_number FROM student_allocations sa JOIN beds b ON sa.bed_id = b.id JOIN rooms r ON b.room_id = r.id WHERE sa.student_id = $1', 
      [studentId]
    );
    const outings = await db.query('SELECT * FROM outing_records WHERE student_id = $1 ORDER BY out_time DESC', [studentId]);

    res.json({
      profile: profile.rows[0] || null,
      room_history: allocations.rows,
      outings: outings.rows
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
