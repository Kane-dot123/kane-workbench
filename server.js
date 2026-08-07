const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3456;
const JWT_SECRET = process.env.JWT_SECRET || 'kane-workbench-prod-secret-key-2024';
const DATABASE_URL = process.env.DATABASE_URL;

// ── Database ───────────────────────────────────────────────────────
let pool = null;
let dbReady = false;

if (DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false },
  });

  // Initialize database tables
  (async function initDB() {
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
          username TEXT PRIMARY KEY,
          password_hash TEXT NOT NULL,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );
      `);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS userdata (
          username TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
          data JSONB DEFAULT '{}'::jsonb,
          updated_at TIMESTAMPTZ DEFAULT NOW()
        );
      `);
      dbReady = true;
      console.log('PostgreSQL database tables initialized.');
    } catch (err) {
      console.error('Failed to initialize database:', err.message);
    }
  })();
} else {
  console.warn('WARNING: DATABASE_URL not set - API endpoints will return 503.');
}

// DB helper middleware
function requireDB(req, res, next) {
  if (!dbReady || !pool) {
    return res.status(503).json({ error: 'Database not available' });
  }
  next();
}

// ── Middleware ──────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// CORS for development
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ── Auth middleware ─────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── Routes ─────────────────────────────────────────────────────────

// Health check
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected' });
  } catch (e) {
    res.status(500).json({ status: 'error', db: 'disconnected' });
  }
});

// Register
app.post('/api/register', requireDB, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  if (username.length < 2) {
    return res.status(400).json({ error: 'Username must be at least 2 characters' });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: 'Password must be at least 4 characters' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2)',
      [username, hash]
    );
    // Create empty userdata row
    await pool.query(
      'INSERT INTO userdata (username, data) VALUES ($1, $2)',
      [username, JSON.stringify({})]
    );

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '90d' });
    res.json({ token, username });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({ error: 'Username already exists' });
    }
    console.error('Register error:', e);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/login', requireDB, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const result = await pool.query(
      'SELECT password_hash FROM users WHERE username = $1',
      [username]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const valid = await bcrypt.compare(password, result.rows[0].password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '90d' });
    res.json({ token, username });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Logout (stateless JWT - just acknowledge)
app.post('/api/logout', authMiddleware, (req, res) => {
  res.json({ ok: true });
});

// Check session
app.get('/api/session', authMiddleware, (req, res) => {
  res.json({ username: req.user.username });
});

// Get user data
app.get('/api/data', authMiddleware, requireDB, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT data FROM userdata WHERE username = $1',
      [req.user.username]
    );
    if (result.rows.length === 0) {
      return res.json(null);
    }
    res.json(result.rows[0].data);
  } catch (e) {
    console.error('Get data error:', e);
    res.status(500).json({ error: 'Failed to read data' });
  }
});

// Save user data
app.post('/api/data', authMiddleware, requireDB, async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO userdata (username, data, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (username)
       DO UPDATE SET data = $2, updated_at = NOW()`,
      [req.user.username, JSON.stringify(req.body)]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('Save data error:', e);
    res.status(500).json({ error: 'Failed to save data' });
  }
});

// Change password
app.post('/api/change-password', authMiddleware, requireDB, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: 'Both old and new password required' });
  }
  if (newPassword.length < 4) {
    return res.status(400).json({ error: 'New password must be at least 4 characters' });
  }

  try {
    const result = await pool.query(
      'SELECT password_hash FROM users WHERE username = $1',
      [req.user.username]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const valid = await bcrypt.compare(oldPassword, result.rows[0].password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    await pool.query(
      'UPDATE users SET password_hash = $1 WHERE username = $2',
      [newHash, req.user.username]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error('Change password error:', e);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// SPA fallback - serve index.html for all non-API routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ───────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Kane Workbench server running on port ${PORT}`);
  console.log(`Database: ${DATABASE_URL ? 'PostgreSQL (Neon)' : 'NOT CONFIGURED'}`);
});
