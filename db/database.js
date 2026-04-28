const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = path.join(__dirname, 'users.db');
let db;

function getDb() {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    initializeSchema();
  }
  return db;
}

function initializeSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      two_fa_secret TEXT DEFAULT NULL,
      two_fa_enabled INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      last_login TEXT DEFAULT NULL
    );
  `);
}

function createUser(username, email, passwordHash) {
  return db.prepare(
    'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'
  ).run(username, email, passwordHash);
}

function findUserByEmail(email) {
  return db.prepare('SELECT * FROM users WHERE email = ?').get(email);
}

function findUserByUsername(username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

function findUserById(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}

function updateLastLogin(id) {
  db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(id);
}

function save2FASecret(userId, secret) {
  db.prepare('UPDATE users SET two_fa_secret = ?, two_fa_enabled = 1 WHERE id = ?').run(secret, userId);
}

function disable2FA(userId) {
  db.prepare('UPDATE users SET two_fa_secret = NULL, two_fa_enabled = 0 WHERE id = ?').run(userId);
}

module.exports = {
  getDb, createUser, findUserByEmail,
  findUserByUsername, findUserById,
  updateLastLogin, save2FASecret, disable2FA,
};
