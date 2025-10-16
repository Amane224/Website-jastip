const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');  // Gunakan pg untuk PostgreSQL
const multer = require('multer');
const path = require('path');
const app = express();
const port = process.env.PORT || 3000;  // Vercel akan set port

// Database setup (PostgreSQL via Vercel)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,  // Ambil dari environment Vercel
  ssl: { rejectUnauthorized: false }  // Untuk Vercel Postgres
});

// Create tables if not exist and pre-create admin account
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user'
  );
  CREATE TABLE IF NOT EXISTS posts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    photo_url TEXT,
    keterangan TEXT,
    minus TEXT,
    log TEXT,
    spesifikasi_akun TEXT,
    harga REAL,
    nomor_owner TEXT,
    status TEXT DEFAULT 'unsold'
  );
`, (err) => {
  if (err) console.error('Error creating tables:', err);
});

// Pre-create admin account if not exists
const checkAndCreateAdmin = async () => {
  const res = await pool.query('SELECT * FROM users WHERE username = $1', ['Kaoru']);
  if (res.rows.length === 0) {
    const hashedPassword = await bcrypt.hash('admin1234', 10);
    await pool.query('INSERT INTO users (username, password, role) VALUES ($1, $2, $3)', ['Kaoru', hashedPassword, 'admin']);
    console.log('Admin account created!');
  } else {
    console.log('Admin account already exists.');
  }
};
checkAndCreateAdmin().catch(err => console.error(err));

// Session setup
app.use(session({
  secret: process.env.SESSION_SECRET || 'default-secret',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.set('view engine', 'ejs');

// Passport configuration
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const res = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
      if (res.rows.length > 0) {
        const user = res.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect password.' });
        }
      } else {
        return done(null, false, { message: 'Incorrect username.' });
      }
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const res = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    done(null, res.rows[0]);
  } catch (err) {
    done(err);
  }
});

// Multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// Routes
app.get('/', (req, res) => {
  res.render('home', { user: req.user });
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login'
}));

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password, role) VALUES ($1, $2, $3)', [username, hashedPassword, role || 'user']);
    res.redirect('/login');
  } catch (err) {
    res.send('Error registering user');
  }
});

app.get('/admin', (req, res) => {
  if (req.user && req.user.role === 'admin') {
    pool.query('SELECT * FROM users', (err, results) => {
      if (err) {
        res.send('Error fetching users');
      } else {
        res.render('admin', { users: results.rows });
      }
    });
  } else {
    res.redirect('/login');
  }
});

app.post('/admin/make-premium', async (req, res) => {
  if (req.user && req.user.role === 'admin') {
    const { userId } = req.body;
    try {
      await pool.query('UPDATE users SET role = $1 WHERE id = $2', ['premium', userId]);
      res.redirect('/admin');
    } catch (err) {
      res.send('Error updating user');
    }
  } else {
    res.redirect('/login');
  }
});

app.get('/upload', (req, res) => {
  if (req.user && req.user.role === 'premium') {
    res.render('upload');
  } else {
    res.redirect('/');
  }
});

app.post('/upload', upload.single('photo'), async (req, res) => {
  if (req.user && req.user.role === 'premium') {
    const { keterangan, minus, log, spesifikasi_akun, harga, nomor_owner } = req.body;
    const photo_url = '/uploads/' + req.file.filename;
    try {
      await pool.query('INSERT INTO posts (user_id, photo_url, keterangan, minus, log, spesifikasi_akun, harga, nomor_owner) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)', [req.user.id, photo_url, keterangan, minus, log, spesifikasi_akun, parseFloat(harga), nomor_owner]);
      res.redirect('/');
    } catch (err) {
      res.send('Error uploading post');
    }
  } else {
    res.redirect('/');
  }
});

app.get('/posts', (req, res) => {
  pool.query('SELECT * FROM posts', (err, results) => {
    if (err) {
      res.send('Error fetching posts');
    } else {
      res.render('posts', { posts: results.rows, user: req.user });
    }
  });
});

app.post('/update-status', async (req, res) => {
  if (req.user && req.user.role === 'premium') {
    const { postId, status } = req.body;
    try {
      await pool.query('UPDATE posts SET status = $1 WHERE id = $2 AND user_id = $3', [status, postId, req.user.id]);
      res.redirect('/posts');
    } catch (err) {
      res.send('Error updating status');
    }
  } else {
    res.redirect('/');
  }
});

app.get('/leaderboard', (req, res) => {
  pool.query(`
    SELECT u.username, COUNT(p.id) as soldCount, SUM(p.harga) as totalHarga
    FROM users u
    LEFT JOIN posts p ON u.id = p.user_id AND p.status = 'sold'
    WHERE u.role = 'premium'
    GROUP BY u.id
    ORDER BY (COUNT(p.id) * 10 + COALESCE(SUM(p.harga), 0)) DESC
  `, (err, results) => {
    if (err) {
      res.send('Error fetching leaderboard');
    } else {
      res.render('leaderboard', { leaders: results.rows });
    }
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});