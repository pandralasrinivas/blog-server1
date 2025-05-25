const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const admin = require('firebase-admin');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');



const app = express();
const port = process.env.PORT || 5000;

const db = new sqlite3.Database('./blogs1.db');

// Create tables if they don't exist
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      fullname TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      image_url TEXT
    )
  `);
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// Authentication middleware
async function authenticate(req, res, next) {
  const token =
    req.headers.authorization?.split(' ')[1] ||
    req.cookies?.token;

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  // Check for your own token (database login)
  if (token === 'fake-jwt-token') {
    return next();
  }

  // Otherwise, try to verify as Firebase ID token (Google login)
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded;
    return next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

// API Routes
app.get('/posts', (req, res) => {
  db.all('SELECT * FROM posts', [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ posts: rows });
  });
});

app.get('/posts/:id', (req, res) => {
  const { id } = req.params;
  db.get('SELECT * FROM posts WHERE id = ?', [id], (err, row) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    if (!row) {
      res.status(404).json({ error: 'Post not found' });
      return;
    }
    res.json({ post: row });
  });
});

app.post('/posts', authenticate, (req, res) => {
  const { email, title, content, image_url } = req.body;
  if (!title || !content) {
    res.status(400).json({ error: 'Title and content are required' });
    return;
  }

  const query = 'INSERT INTO posts (email, title, content, image_url) VALUES (?, ?, ?, ?)';
  db.run(query, [email, title, content, image_url], function (err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.status(201).json({ id: this.lastID });
  });
});

app.put('/posts/:id', authenticate, (req, res) => {
  const { id } = req.params;
  const { title, content, image_url } = req.body;

  if (!title || !content) {
    res.status(400).json({ error: 'Title and content are required' });
    return;
  }

  const query = 'UPDATE posts SET title = ?, content = ?, image_url = ? WHERE id = ?';
  db.run(query, [title, content, image_url, id], function (err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    if (this.changes === 0) {
      res.status(404).json({ error: 'Post not found' });
      return;
    }
    res.json({ message: 'Post updated' });
  });
});

app.delete('/posts/:id', authenticate, (req, res) => {
  const { id } = req.params;
  // Get email from authenticated user (Firebase or your own logic)
  const email = req.user?.email || req.body?.email || req.query?.email;

  if (!email) {
    return res.status(400).json({ error: 'Email not found in authentication' });
  }

  // Only delete if the post belongs to the authenticated user
  const query = 'DELETE FROM posts WHERE id = ? AND email = ?';
  db.run(query, [id, email], function (err) {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    if (this.changes === 0) {
      res.status(404).json({ error: 'Post not found or not authorized' });
      return;
    }
    res.json({ message: 'Post deleted' });
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  const query = 'SELECT * FROM users WHERE username = ?';
  db.get(query, [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' });
    }
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    // Compare hashed password
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    // For demo: return a fake token. In production, use JWT.
    res.json({ token: 'fake-jwt-token', username: user.username });
  });
});

app.post('/register', async (req, res) => {
  const { fullname, username, email, password } = req.body;
  if (!fullname || !username || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (username, password, email, fullname) VALUES (?, ?, ?, ?)';
    db.run(query, [username, hashedPassword, email, fullname], function (err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(409).json({ message: 'Username already exists' });
        }
        return res.status(500).json({ message: 'Database error' });
      }
      res.status(201).json({ message: 'User registered successfully', id: this.lastID });
    });
  } catch (err) {
    res.status(500).json({ message: 'Error hashing password' });
  }
});

app.get('/my-posts', authenticate, (req, res) => {
  // For database login, you may need to get email from the request body or token
  // For Firebase login, email is in req.user.email
  let email = req.user?.email || req.body?.email || req.query?.email;

  // If using your own token, you may want to store email in the token/session
  if (!email) {
    return res.status(400).json({ error: 'Email not found in authentication' });
  }

  db.all('SELECT * FROM posts WHERE email = ?', [email], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ posts: rows });
  });
});

app.get('/profile', authenticate, (req, res) => {
  // For Firebase login, email is in req.user.email
  const email = req.user?.email || req.body?.email || req.query?.email;

  if (!email) {
    return res.status(400).json({ error: 'Email not found in authentication' });
  }

  db.get('SELECT id, fullname, username, email FROM users WHERE email = ?', [email], (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ profile: user });
  });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
