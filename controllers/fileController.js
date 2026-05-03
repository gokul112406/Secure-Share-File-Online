// ============================================================
// controllers/fileController.js
// Core business logic: encrypt on upload, decrypt on download
// ============================================================

const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const File = require('../models/File');

// ── Constants ─────────────────────────────────────────────────
const ALGORITHM    = 'aes-256-gcm';
const KEY_BYTES    = 32;   // 256 bits
const IV_BYTES     = 12;   // 96 bits — GCM standard
const TAG_LENGTH   = 16;   // 128-bit auth tag
const MAX_MB       = 50;   // file-size cap in MB
const MAX_BYTES    = MAX_MB * 1024 * 1024;

// ── Allowed expiry options (minutes) ─────────────────────────
const EXPIRY_OPTIONS = {
  '1h':  60,
  '6h':  360,
  '12h': 720,
  '24h': 1440,
  '72h': 4320,
};

// ────────────────────────────────────────────────────────────
// HELPER: encrypt a Buffer with AES-256-GCM
//
// Returns:
//   { encryptedData, iv, authTag } — all hex-encoded strings
//
// The caller MUST store the `privateKey` themselves (shown once,
// never saved by server). Without it, decryption is impossible.
// ────────────────────────────────────────────────────────────
function encryptBuffer(buffer, privateKeyHex) {
  // Derive a 32-byte key from the provided hex private key
  const key = Buffer.from(privateKeyHex, 'hex');
  const iv  = crypto.randomBytes(IV_BYTES);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: TAG_LENGTH,
  });

  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag   = cipher.getAuthTag();

  return {
    encryptedData: encrypted.toString('hex'),
    iv:            iv.toString('hex'),
    authTag:       authTag.toString('hex'),
  };
}

// ────────────────────────────────────────────────────────────
// HELPER: decrypt cipher text with AES-256-GCM
//
// Throws if the auth tag fails (data tampered / wrong key).
// ────────────────────────────────────────────────────────────
function decryptBuffer(encryptedHex, ivHex, authTagHex, privateKeyHex) {
  const key       = Buffer.from(privateKeyHex, 'hex');
  const iv        = Buffer.from(ivHex,         'hex');
  const authTag   = Buffer.from(authTagHex,    'hex');
  const encrypted = Buffer.from(encryptedHex,  'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
    authTagLength: TAG_LENGTH,
  });
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

// ============================================================
// POST /api/upload
// Body: multipart/form-data  { file, expiresIn }
// ============================================================
exports.uploadFile = async (req, res) => {
  try {
    // ── 1. Validate incoming file ─────────────────────────────
    if (!req.file) {
      return res.status(400).json({ error: 'No file provided.' });
    }

    if (req.file.size > MAX_BYTES) {
      return res.status(413).json({ error: `File exceeds ${MAX_MB} MB limit.` });
    }

    // ── 2. Parse expiry ───────────────────────────────────────
    const expiryKey  = req.body.expiresIn || '24h';
    const expiryMins = EXPIRY_OPTIONS[expiryKey] || EXPIRY_OPTIONS['24h'];
    const expiresAt  = new Date(Date.now() + expiryMins * 60 * 1000);

    // ── 3. Generate private key (NEVER stored on server) ──────
    // 32 cryptographically random bytes → 64-char hex string
    const privateKey = crypto.randomBytes(KEY_BYTES).toString('hex');

    // ── 4. Encrypt the file buffer ───────────────────────────
    const { encryptedData, iv, authTag } = encryptBuffer(req.file.buffer, privateKey);

    // ── 5. Generate public key (shareable download ID) ────────
    const publicKey = uuidv4().replace(/-/g, ''); // 32-char hex UUID

    // ── 6. Persist encrypted record (NO private key stored) ───
    const fileDoc = new File({
      publicKey,
      originalName:  req.file.originalname,
      mimeType:      req.file.mimetype,
      fileSize:      req.file.size,
      encryptedData,
      iv,
      authTag,
      expiresAt,
    });
    await fileDoc.save();

    // ── 7. Respond with public key + private key (shown once) ─
    return res.status(201).json({
      success:    true,
      publicKey,        // share this with the receiver
      privateKey,       // SHOWN ONCE — receiver needs this to decrypt
      expiresAt,
      fileName:   req.file.originalname,
      fileSize:   req.file.size,
      message:    'File encrypted and stored. Share BOTH keys with the receiver.',
    });
  } catch (err) {
    console.error('[UPLOAD ERROR]', err.message);
    return res.status(500).json({ error: 'Upload failed. ' + err.message });
  }
};

// ============================================================
// POST /api/decrypt
// Body: JSON  { publicKey, privateKey }
// ============================================================
exports.decryptFile = async (req, res) => {
  try {
    const { publicKey, privateKey } = req.body;

    // ── 1. Input validation ───────────────────────────────────
    if (!publicKey || typeof publicKey !== 'string' || publicKey.trim().length === 0) {
      return res.status(400).json({ error: 'Public key is required.' });
    }
    if (!privateKey || typeof privateKey !== 'string' || privateKey.trim().length === 0) {
      return res.status(400).json({ error: 'Private key is required.' });
    }

    // Strip any whitespace the user might have accidentally included
    const cleanPublicKey  = publicKey.trim();
    const cleanPrivateKey = privateKey.trim();

    // Validate key formats
    if (!/^[a-f0-9]{32}$/i.test(cleanPublicKey)) {
      return res.status(400).json({ error: 'Invalid public key format.' });
    }
    if (!/^[a-f0-9]{64}$/i.test(cleanPrivateKey)) {
      return res.status(400).json({ error: 'Invalid private key format.' });
    }

    // ── 2. Look up record ─────────────────────────────────────
    const fileDoc = await File.findOne({ publicKey: cleanPublicKey });
    if (!fileDoc) {
      return res.status(404).json({ error: 'File not found. The link may be invalid or already deleted.' });
    }

    // ── 3. Expiry check ───────────────────────────────────────
    if (fileDoc.expiresAt < new Date()) {
      await File.deleteOne({ _id: fileDoc._id }); // clean up
      return res.status(410).json({ error: 'This file has expired and has been deleted.' });
    }

    // ── 4. Decrypt ────────────────────────────────────────────
    let decryptedBuffer;
    try {
      decryptedBuffer = decryptBuffer(
        fileDoc.encryptedData,
        fileDoc.iv,
        fileDoc.authTag,
        cleanPrivateKey
      );
    } catch (_) {
      // GCM auth tag mismatch → wrong key or tampered data
      return res.status(403).json({ error: 'Decryption failed. Incorrect private key or data is corrupted.' });
    }

    // ── 5. Update download counter ────────────────────────────
    fileDoc.downloaded    = true;
    fileDoc.downloadCount += 1;
    await fileDoc.save();

    // ── 6. Stream decrypted file to client ───────────────────
    res.setHeader('Content-Type',        fileDoc.mimeType);
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${encodeURIComponent(fileDoc.originalName)}"`
    );
    res.setHeader('Content-Length',      decryptedBuffer.length);
    res.setHeader('X-File-Name',         fileDoc.originalName);
    return res.send(decryptedBuffer);
  } catch (err) {
    console.error('[DECRYPT ERROR]', err.message);
    return res.status(500).json({ error: 'Decryption failed. ' + err.message });
  }
};

// ============================================================
// GET /api/file/:id
// Returns file metadata (no encrypted payload) for UI preview
// ============================================================
exports.getFileInfo = async (req, res) => {
  try {
    const { id } = req.params;

    if (!/^[a-f0-9]{32}$/i.test(id)) {
      return res.status(400).json({ error: 'Invalid file ID format.' });
    }

    const fileDoc = await File.findOne({ publicKey: id }).select(
      'publicKey originalName mimeType fileSize expiresAt downloadCount createdAt'
    );

    if (!fileDoc) {
      return res.status(404).json({ error: 'File not found.' });
    }

    if (fileDoc.expiresAt < new Date()) {
      return res.status(410).json({ error: 'File has expired.' });
    }

    return res.json({
      publicKey:     fileDoc.publicKey,
      fileName:      fileDoc.originalName,
      mimeType:      fileDoc.mimeType,
      fileSize:      fileDoc.fileSize,
      expiresAt:     fileDoc.expiresAt,
      downloadCount: fileDoc.downloadCount,
      createdAt:     fileDoc.createdAt,
    });
  } catch (err) {
    console.error('[FILE INFO ERROR]', err.message);
    return res.status(500).json({ error: 'Could not retrieve file info.' });
  }
};
