// ============================================================
// routes/fileRoutes.js — API route definitions (multer v2 async)
// ============================================================

const express    = require('express');
const multer     = require('multer');
const {
  uploadFile,
  decryptFile,
  getFileInfo,
} = require('../controllers/fileController');

const router = express.Router();

// ── Multer v2: memory storage, 50 MB limit ───────────────────
const storage = multer.memoryStorage();
const upload  = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
});

// Blocked executable extensions
const BLOCKED_EXT = new Set(['.exe','.bat','.cmd','.sh','.ps1','.msi','.com','.scr','.vbs']);

// ── Wrapper: multer v2 single() is async ─────────────────────
function multerSingle(fieldName) {
  return (req, res, next) => {
    upload.single(fieldName)(req, res, (err) => {
      if (err) {
        if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
          return res.status(413).json({ error: 'File too large. Maximum size is 50 MB.' });
        }
        return res.status(400).json({ error: err.message || 'File upload error.' });
      }

      // Extension filter after multer accepted the file
      if (req.file) {
        const ext = '.' + req.file.originalname.split('.').pop().toLowerCase();
        if (BLOCKED_EXT.has(ext)) {
          return res.status(400).json({ error: 'Executable file types are not allowed.' });
        }
      }
      next();
    });
  };
}

// ── Routes ────────────────────────────────────────────────────

// POST /api/upload  — upload + encrypt a file
router.post('/upload', multerSingle('file'), uploadFile);

// POST /api/decrypt — provide keys, receive decrypted file
router.post('/decrypt', decryptFile);

// GET  /api/file/:id — fetch file metadata (for UI preview)
router.get('/file/:id', getFileInfo);

module.exports = router;
