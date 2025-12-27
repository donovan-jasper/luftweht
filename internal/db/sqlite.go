package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps the SQL database connection
type DB struct {
	*sql.DB
}

// New creates a new database connection with WAL mode enabled
func New(dbPath string) (*DB, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	// Open database with WAL mode for better concurrency
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection pool settings for concurrent access
	db.SetMaxOpenConns(1) // SQLite only supports one writer at a time
	db.SetMaxIdleConns(1)

	// Test the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{db}, nil
}

// Migrate runs database migrations to create/update schema
func (db *DB) Migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS hosts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT UNIQUE NOT NULL,
		hostname TEXT,
		subnet TEXT,
		status TEXT DEFAULT 'discovered',
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		completed_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS ports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host_id INTEGER NOT NULL REFERENCES hosts(id),
		port INTEGER NOT NULL,
		protocol TEXT NOT NULL,
		state TEXT NOT NULL,
		service TEXT,
		version TEXT,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(host_id, port, protocol)
	);

	CREATE TABLE IF NOT EXISTS scan_progress (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host_id INTEGER REFERENCES hosts(id),
		subnet TEXT,
		scan_type TEXT NOT NULL,
		port_start INTEGER,
		port_end INTEGER,
		status TEXT DEFAULT 'pending',
		started_at DATETIME,
		completed_at DATETIME,
		error TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);
	CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
	CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
	CREATE INDEX IF NOT EXISTS idx_ports_state ON ports(state);
	CREATE INDEX IF NOT EXISTS idx_scan_progress_status ON scan_progress(status);
	CREATE INDEX IF NOT EXISTS idx_scan_progress_type ON scan_progress(scan_type);
	`

	_, err := db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

// HasIncompleteScans checks if there are any incomplete scans from a previous run
func (db *DB) HasIncompleteScans() (bool, int, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM scan_progress
		WHERE status IN ('pending', 'running')
	`).Scan(&count)
	if err != nil {
		return false, 0, err
	}
	return count > 0, count, nil
}

// ResetRunningScans marks any 'running' scans as 'pending' for recovery
func (db *DB) ResetRunningScans() error {
	_, err := db.Exec(`
		UPDATE scan_progress
		SET status = 'pending', started_at = NULL
		WHERE status = 'running'
	`)
	return err
}

// ClearAllData removes all scan data for a fresh start
func (db *DB) ClearAllData() error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	tables := []string{"scan_progress", "ports", "hosts"}
	for _, table := range tables {
		if _, err := tx.Exec("DELETE FROM " + table); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.DB.Close()
}
