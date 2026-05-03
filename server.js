// ============================================================
// server.js — Entry point for SecureShare backend
// Initialises Express, MongoDB, middleware, and routes
// ============================================================

require('dotenv').config();

const express    = require('express');
const mongoose   = require('mongoose');
const helmet     = require('helmet');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');
const path       = require('path');

const fileRoutes = require('./routes/fileRoutes');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Security Middleware ──────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc:  ["'self'"],
        scriptSrc:   ["'self'", "'unsafe-inline'"],
        styleSrc:    ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc:     ["'self'", 'https://fonts.gstatic.com'],
        imgSrc:      ["'self'", 'data:'],
        connectSrc:  ["'self'"],
        upgradeInsecureRequests: null,
      },
    },
  })
);

// ── CORS ─────────────────────────────────────────────────────
app.use(
  cors({
    origin: process.env.NODE_ENV === 'production' ? false : '*',
    methods: ['GET', 'POST'],
  })
);

// ── Rate Limiting ─────────────────────────────────────────────
// Limit each IP to 30 requests per 10 minutes (upload/download)
const apiLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down and try again later.' },
});
app.use('/api', apiLimiter);

// ── Body Parser ───────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ── Static Files ──────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ── API Routes ────────────────────────────────────────────────
app.use('/api', fileRoutes);

// ── Serve HTML pages ──────────────────────────────────────────
app.get('/',         (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/receive',  (_req, res) => res.sendFile(path.join(__dirname, 'public', 'receive.html')));
app.get('/about',    (_req, res) => res.sendFile(path.join(__dirname, 'public', 'about.html')));

// ── 404 Fallback ─────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', 'error.html'));
});

// ── Global Error Handler ─────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error('[ERROR]', err.message);
  res.status(err.status || 500).json({ error: err.message || 'Internal server error.' });
});

// ── MongoDB Connection ────────────────────────────────────────
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    const os = require('os');
    const nets = os.networkInterfaces();
    let networkIp = '';
    for (const name of Object.keys(nets)) {
      for (const net of nets[name]) {
        if (net.family === 'IPv4' && !net.internal && net.address.startsWith('10.')) {
           networkIp = net.address;
        } else if (net.family === 'IPv4' && !net.internal && !networkIp) {
           networkIp = net.address;
        }
      }
    }
    app.listen(PORT, () => {
      console.log('✅  MongoDB connected');
      console.log(`🚀  SecureShare running on:`);
      console.log(`    - Local:   http://localhost:${PORT}`);
      if (networkIp) {
        console.log(`    - Network: http://${networkIp}:${PORT}`);
      }
    });
  })
  .catch((err) => {
    console.error('❌  MongoDB connection failed:', err.message);
    process.exit(1);
  });
