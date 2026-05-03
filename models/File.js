// ============================================================
// models/File.js — Mongoose schema for encrypted file records
// ============================================================

const mongoose = require('mongoose');

/**
 * SECURITY NOTE:
 * ─────────────
 * The AES-256 private (encryption) KEY is NEVER stored here.
 * Only the following are stored:
 *   • publicKey  — a UUID used as the shareable download ID
 *   • iv         — Initialisation Vector (safe to store; needed for decryption)
 *   • encryptedData — the AES-256-CBC encrypted file bytes (as hex string)
 *   • authTag    — GCM authentication tag for integrity verification
 *
 * Without the private key the stored data is computationally useless.
 */
const fileSchema = new mongoose.Schema(
  {
    // ── Identity ──────────────────────────────────────────────
    publicKey: {
      type:     String,
      required: true,
      unique:   true,
      index:    true,
    },

    // ── Original file metadata ────────────────────────────────
    originalName: {
      type:     String,
      required: true,
      trim:     true,
    },
    mimeType: {
      type:    String,
      default: 'application/octet-stream',
    },
    fileSize: {
      type: Number, // bytes (original, before encryption)
    },

    // ── AES-256-GCM encrypted payload ─────────────────────────
    // encryptedData: hex-encoded cipher text
    encryptedData: {
      type:     String,
      required: true,
    },
    // iv: hex-encoded 12-byte initialisation vector (GCM standard)
    iv: {
      type:     String,
      required: true,
    },
    // authTag: hex-encoded 16-byte GCM authentication tag
    authTag: {
      type:     String,
      required: true,
    },

    // ── Expiration ────────────────────────────────────────────
    expiresAt: {
      type:    Date,
      default: () => new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 h default
      // index defined below as TTL — do NOT also set index:true here
    },

    // ── Usage tracking ────────────────────────────────────────
    downloaded: {
      type:    Boolean,
      default: false,
    },
    downloadCount: {
      type:    Number,
      default: 0,
    },
  },
  { timestamps: true } // adds createdAt + updatedAt automatically
);

// ── TTL Index: MongoDB auto-deletes expired docs ─────────────
// The document is removed `expiresAt` seconds after that date
fileSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// ── Virtual: isExpired helper ─────────────────────────────────
fileSchema.virtual('isExpired').get(function () {
  return this.expiresAt < new Date();
});

module.exports = mongoose.model('File', fileSchema);
