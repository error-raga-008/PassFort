-- schema.sql
-- SQLite schema for Password Manager

PRAGMA foreign_keys = OFF;
BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS password_entry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(80) NOT NULL,
    website VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    safety_key VARCHAR(10) NOT NULL,
    note TEXT,
    created_at DATETIME DEFAULT (datetime('now'))
);

COMMIT;
