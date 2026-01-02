package main

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed frontend/dist/*
var frontendFS embed.FS

type Host struct {
	ID              int64   `json:"id"`
	IP              string  `json:"ip"`
	Hostname        string  `json:"hostname"`
	Subnet          string  `json:"subnet"`
	Status          string  `json:"status"`
	OSGuess         string  `json:"os_guess"`
	OSType          string  `json:"os_type"`
	OSDetails       string  `json:"os_details"`
	DiscoveredAt    string  `json:"discovered_at"`
	CompletedAt     *string `json:"completed_at"`
	OpenPorts       int     `json:"open_ports"`
	CommentCount    int     `json:"comment_count"`
	CredentialCount int     `json:"credential_count"`
}

type Port struct {
	ID           int64  `json:"id"`
	HostID       int64  `json:"host_id"`
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"`
	State        string `json:"state"`
	Service      string `json:"service"`
	Version      string `json:"version"`
	DiscoveredAt string `json:"discovered_at"`
}

type Comment struct {
	ID        int64   `json:"id"`
	HostID    *int64  `json:"host_id"`
	Content   string  `json:"content"`
	Author    string  `json:"author"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
}

type Credential struct {
	ID        int64   `json:"id"`
	HostID    *int64  `json:"host_id"`
	Username  string  `json:"username"`
	Password  string  `json:"password"`
	Hash      string  `json:"hash"`
	Domain    string  `json:"domain"`
	CredType  string  `json:"cred_type"`
	Notes     string  `json:"notes"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
}

type Stats struct {
	TotalHosts     int            `json:"total_hosts"`
	TotalOpenPorts int            `json:"total_open_ports"`
	HostsByStatus  map[string]int `json:"hosts_by_status"`
	HostsBySubnet  map[string]int `json:"hosts_by_subnet"`
	ScansCompleted int            `json:"scans_completed"`
	ScansPending   int            `json:"scans_pending"`
	ScansFailed    int            `json:"scans_failed"`
}

type SSEClient struct {
	id     string
	events chan []byte
}

type Session struct {
	Username string
	Expiry   time.Time
}

type Server struct {
	db          *sql.DB
	dbPath      string
	clients     map[string]*SSEClient
	clientsMux  sync.RWMutex
	lastUpdate  time.Time
	password    string                 // Empty means no auth required
	sessions    map[string]Session     // Session token -> session data
	sessionsMux sync.RWMutex
}

func NewServer(dbPath string, password string) (*Server, error) {
	// Use read-write mode if we have a password (auth enabled = can write)
	mode := "ro"
	if password != "" {
		mode = "rwc"
	}

	db, err := sql.Open("sqlite3", dbPath+"?mode="+mode+"&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}

	s := &Server{
		db:       db,
		dbPath:   dbPath,
		clients:  make(map[string]*SSEClient),
		password: password,
		sessions: make(map[string]Session),
	}

	// Run migrations (will fail silently in read-only mode, but that's ok)
	s.runMigrations()

	// Start polling for changes
	go s.pollChanges()

	// Start session cleanup
	go s.cleanupSessions()

	return s, nil
}

func (s *Server) runMigrations() {
	// Create tables if they don't exist
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS comments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			host_id INTEGER REFERENCES hosts(id),
			content TEXT NOT NULL,
			author TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_comments_host ON comments(host_id)`,
		`CREATE TABLE IF NOT EXISTS credentials (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			host_id INTEGER REFERENCES hosts(id),
			username TEXT,
			password TEXT,
			hash TEXT,
			domain TEXT,
			cred_type TEXT,
			notes TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_host ON credentials(host_id)`,
		// Add os_type and os_details columns if they don't exist
		`ALTER TABLE hosts ADD COLUMN os_type TEXT`,
		`ALTER TABLE hosts ADD COLUMN os_details TEXT`,
	}

	for _, m := range migrations {
		s.db.Exec(m) // Ignore errors - column/table may already exist
	}
}

func (s *Server) cleanupSessions() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.sessionsMux.Lock()
		now := time.Now()
		for token, session := range s.sessions {
			if now.After(session.Expiry) {
				delete(s.sessions, token)
			}
		}
		s.sessionsMux.Unlock()
	}
}

// generateToken creates a random session token
func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// isAuthenticated checks if the request has a valid session
func (s *Server) isAuthenticated(r *http.Request) bool {
	// No password = no auth required
	if s.password == "" {
		return true
	}

	cookie, err := r.Cookie("session")
	if err != nil {
		return false
	}

	s.sessionsMux.RLock()
	session, exists := s.sessions[cookie.Value]
	s.sessionsMux.RUnlock()

	if !exists || time.Now().After(session.Expiry) {
		return false
	}

	// Refresh session on activity
	s.sessionsMux.Lock()
	session.Expiry = time.Now().Add(24 * time.Hour)
	s.sessions[cookie.Value] = session
	s.sessionsMux.Unlock()

	return true
}

// getUsername returns the username for the current session
func (s *Server) getUsername(r *http.Request) string {
	cookie, err := r.Cookie("session")
	if err != nil {
		return ""
	}

	s.sessionsMux.RLock()
	session, exists := s.sessions[cookie.Value]
	s.sessionsMux.RUnlock()

	if !exists {
		return ""
	}
	return session.Username
}

// requireAuth wraps a handler to require authentication
func (s *Server) requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.isAuthenticated(r) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

// requireWriteAuth wraps a handler to require auth for write operations
func (s *Server) requireWriteAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Write operations require password to be set
		if s.password == "" {
			http.Error(w, `{"error":"read-only mode"}`, http.StatusForbidden)
			return
		}
		if !s.isAuthenticated(r) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

func (s *Server) pollChanges() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats, err := s.getStats()
		if err != nil {
			continue
		}

		data, _ := json.Marshal(map[string]interface{}{
			"type":  "stats",
			"stats": stats,
		})

		s.broadcast(data)
	}
}

func (s *Server) broadcast(data []byte) {
	s.clientsMux.RLock()
	defer s.clientsMux.RUnlock()

	for _, client := range s.clients {
		select {
		case client.events <- data:
		default:
			// Client buffer full, skip
		}
	}
}

func (s *Server) getStats() (*Stats, error) {
	stats := &Stats{
		HostsByStatus: make(map[string]int),
		HostsBySubnet: make(map[string]int),
	}

	// Total hosts
	s.db.QueryRow("SELECT COUNT(*) FROM hosts").Scan(&stats.TotalHosts)

	// Total open ports
	s.db.QueryRow("SELECT COUNT(*) FROM ports WHERE state = 'open'").Scan(&stats.TotalOpenPorts)

	// Hosts by status
	rows, err := s.db.Query("SELECT status, COUNT(*) FROM hosts GROUP BY status")
	if err == nil {
		for rows.Next() {
			var status string
			var count int
			rows.Scan(&status, &count)
			stats.HostsByStatus[status] = count
		}
		rows.Close()
	}

	// Hosts by subnet
	rows, err = s.db.Query("SELECT subnet, COUNT(*) FROM hosts GROUP BY subnet")
	if err == nil {
		for rows.Next() {
			var subnet string
			var count int
			rows.Scan(&subnet, &count)
			stats.HostsBySubnet[subnet] = count
		}
		rows.Close()
	}

	// Scan progress based on host status
	s.db.QueryRow("SELECT COUNT(*) FROM hosts WHERE status = 'complete'").Scan(&stats.ScansCompleted)
	s.db.QueryRow("SELECT COUNT(*) FROM hosts WHERE status NOT IN ('complete', 'discovered')").Scan(&stats.ScansPending)
	s.db.QueryRow("SELECT COUNT(*) FROM hosts WHERE status = 'discovered'").Scan(&stats.ScansFailed) // Actually discovered count

	return stats, nil
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.getStats()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	subnet := r.URL.Query().Get("subnet")

	query := `
		SELECT h.id, h.ip, h.hostname, h.subnet, h.status, h.discovered_at, h.completed_at,
			   COALESCE(h.os_type, '') as os_type, COALESCE(h.os_details, '') as os_details,
			   (SELECT COUNT(*) FROM ports p WHERE p.host_id = h.id AND p.state = 'open') as open_ports,
			   (SELECT COUNT(*) FROM comments c WHERE c.host_id = h.id) as comment_count,
			   (SELECT COUNT(*) FROM credentials cr WHERE cr.host_id = h.id) as credential_count
		FROM hosts h
	`
	args := []interface{}{}

	if subnet != "" {
		query += " WHERE h.subnet = ?"
		args = append(args, subnet)
	}

	query += " ORDER BY h.subnet, h.ip"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	hosts := []Host{}
	for rows.Next() {
		var h Host
		var completedAt sql.NullString
		err := rows.Scan(&h.ID, &h.IP, &h.Hostname, &h.Subnet, &h.Status,
			&h.DiscoveredAt, &completedAt, &h.OSType, &h.OSDetails,
			&h.OpenPorts, &h.CommentCount, &h.CredentialCount)
		if err != nil {
			continue
		}
		if completedAt.Valid {
			h.CompletedAt = &completedAt.String
		}
		// Compute OS guess based on open ports
		h.OSGuess = s.guessOS(h.ID)
		hosts = append(hosts, h)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hosts)
}

func (s *Server) handleUpdateHost(w http.ResponseWriter, r *http.Request) {
	if r.Method != "PUT" && r.Method != "PATCH" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct {
		ID        int64  `json:"id"`
		OSType    string `json:"os_type"`
		OSDetails string `json:"os_details"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", 400)
		return
	}

	_, err := s.db.Exec("UPDATE hosts SET os_type = ?, os_details = ? WHERE id = ?",
		req.OSType, req.OSDetails, req.ID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	// Get the database path from the server
	dbPath := s.dbPath

	// Read the database file
	data, err := os.ReadFile(dbPath)
	if err != nil {
		http.Error(w, "Failed to read database: "+err.Error(), 500)
		return
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("2006-01-02_150405")
	filename := fmt.Sprintf("luftweht_backup_%s.db", timestamp)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Write(data)
}

func (s *Server) handlePorts(w http.ResponseWriter, r *http.Request) {
	hostID := r.URL.Query().Get("host_id")
	if hostID == "" {
		http.Error(w, "host_id required", 400)
		return
	}

	rows, err := s.db.Query(`
		SELECT id, host_id, port, protocol, state, service, version, discovered_at
		FROM ports WHERE host_id = ?
		ORDER BY protocol, port
	`, hostID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	ports := []Port{}
	for rows.Next() {
		var p Port
		var service, version sql.NullString
		err := rows.Scan(&p.ID, &p.HostID, &p.Port, &p.Protocol, &p.State,
			&service, &version, &p.DiscoveredAt)
		if err != nil {
			continue
		}
		if service.Valid {
			p.Service = service.String
		}
		if version.Valid {
			p.Version = version.String
		}
		ports = append(ports, p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ports)
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", 500)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	client := &SSEClient{
		id:     fmt.Sprintf("%d", time.Now().UnixNano()),
		events: make(chan []byte, 10),
	}

	s.clientsMux.Lock()
	s.clients[client.id] = client
	s.clientsMux.Unlock()

	defer func() {
		s.clientsMux.Lock()
		delete(s.clients, client.id)
		s.clientsMux.Unlock()
	}()

	// Send initial stats
	stats, _ := s.getStats()
	data, _ := json.Marshal(map[string]interface{}{
		"type":  "stats",
		"stats": stats,
	})
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case data := <-client.events:
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (s *Server) handleSubnets(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query("SELECT DISTINCT subnet FROM hosts ORDER BY subnet")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	subnets := []string{}
	for rows.Next() {
		var subnet string
		rows.Scan(&subnet)
		subnets = append(subnets, subnet)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(subnets)
}

// Auth endpoints

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated":  s.isAuthenticated(r),
		"auth_required":  s.password != "",
		"write_enabled":  s.password != "",
		"username":       s.getUsername(r),
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Password string `json:"password"`
		Username string `json:"username"`
	}

	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &req)

	if req.Password != s.password {
		http.Error(w, `{"error":"invalid password"}`, http.StatusUnauthorized)
		return
	}

	// Default username if not provided
	username := req.Username
	if username == "" {
		username = "Anonymous"
	}

	token := generateToken()
	s.sessionsMux.Lock()
	s.sessions[token] = Session{
		Username: username,
		Expiry:   time.Now().Add(24 * time.Hour),
	}
	s.sessionsMux.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400, // 24 hours
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "username": username})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		s.sessionsMux.Lock()
		delete(s.sessions, cookie.Value)
		s.sessionsMux.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// Comments CRUD

func (s *Server) handleComments(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getComments(w, r)
	case http.MethodPost:
		s.createComment(w, r)
	case http.MethodPut:
		s.updateComment(w, r)
	case http.MethodDelete:
		s.deleteComment(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getComments(w http.ResponseWriter, r *http.Request) {
	hostIDStr := r.URL.Query().Get("host_id")
	global := r.URL.Query().Get("global") == "true"

	var rows *sql.Rows
	var err error

	if hostIDStr != "" {
		hostID, _ := strconv.ParseInt(hostIDStr, 10, 64)
		rows, err = s.db.Query(`
			SELECT id, host_id, content, author, created_at, updated_at
			FROM comments WHERE host_id = ? ORDER BY created_at DESC
		`, hostID)
	} else if global {
		rows, err = s.db.Query(`
			SELECT id, host_id, content, author, created_at, updated_at
			FROM comments WHERE host_id IS NULL ORDER BY created_at DESC
		`)
	} else {
		rows, err = s.db.Query(`
			SELECT id, host_id, content, author, created_at, updated_at
			FROM comments ORDER BY created_at DESC
		`)
	}

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	comments := []Comment{}
	for rows.Next() {
		var c Comment
		var hostID sql.NullInt64
		var author sql.NullString
		rows.Scan(&c.ID, &hostID, &c.Content, &author, &c.CreatedAt, &c.UpdatedAt)
		if hostID.Valid {
			c.HostID = &hostID.Int64
		}
		if author.Valid {
			c.Author = author.String
		}
		comments = append(comments, c)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(comments)
}

func (s *Server) createComment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		HostID  *int64 `json:"host_id"`
		Content string `json:"content"`
		Author  string `json:"author"`
	}

	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &req)

	if req.Content == "" {
		http.Error(w, `{"error":"content required"}`, http.StatusBadRequest)
		return
	}

	result, err := s.db.Exec(`
		INSERT INTO comments (host_id, content, author)
		VALUES (?, ?, ?)
	`, req.HostID, req.Content, req.Author)

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	id, _ := result.LastInsertId()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{"id": id})
}

func (s *Server) updateComment(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, `{"error":"id required"}`, http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(idStr, 10, 64)

	var req struct {
		Content string `json:"content"`
	}

	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &req)

	_, err := s.db.Exec(`
		UPDATE comments SET content = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, req.Content, id)

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) deleteComment(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, `{"error":"id required"}`, http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(idStr, 10, 64)

	_, err := s.db.Exec("DELETE FROM comments WHERE id = ?", id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// Credentials CRUD

func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getCredentials(w, r)
	case http.MethodPost:
		s.createCredential(w, r)
	case http.MethodPut:
		s.updateCredential(w, r)
	case http.MethodDelete:
		s.deleteCredential(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getCredentials(w http.ResponseWriter, r *http.Request) {
	hostIDStr := r.URL.Query().Get("host_id")
	global := r.URL.Query().Get("global") == "true"

	var rows *sql.Rows
	var err error

	if hostIDStr != "" {
		hostID, _ := strconv.ParseInt(hostIDStr, 10, 64)
		rows, err = s.db.Query(`
			SELECT id, host_id, username, password, hash, domain, cred_type, notes, created_at, updated_at
			FROM credentials WHERE host_id = ? ORDER BY created_at DESC
		`, hostID)
	} else if global {
		rows, err = s.db.Query(`
			SELECT id, host_id, username, password, hash, domain, cred_type, notes, created_at, updated_at
			FROM credentials WHERE host_id IS NULL ORDER BY created_at DESC
		`)
	} else {
		rows, err = s.db.Query(`
			SELECT id, host_id, username, password, hash, domain, cred_type, notes, created_at, updated_at
			FROM credentials ORDER BY created_at DESC
		`)
	}

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	creds := []Credential{}
	for rows.Next() {
		var c Credential
		var hostID sql.NullInt64
		var username, password, hash, domain, credType, notes sql.NullString
		rows.Scan(&c.ID, &hostID, &username, &password, &hash, &domain, &credType, &notes, &c.CreatedAt, &c.UpdatedAt)
		if hostID.Valid {
			c.HostID = &hostID.Int64
		}
		if username.Valid {
			c.Username = username.String
		}
		if password.Valid {
			c.Password = password.String
		}
		if hash.Valid {
			c.Hash = hash.String
		}
		if domain.Valid {
			c.Domain = domain.String
		}
		if credType.Valid {
			c.CredType = credType.String
		}
		if notes.Valid {
			c.Notes = notes.String
		}
		creds = append(creds, c)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(creds)
}

func (s *Server) createCredential(w http.ResponseWriter, r *http.Request) {
	var req Credential

	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &req)

	result, err := s.db.Exec(`
		INSERT INTO credentials (host_id, username, password, hash, domain, cred_type, notes)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, req.HostID, req.Username, req.Password, req.Hash, req.Domain, req.CredType, req.Notes)

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	id, _ := result.LastInsertId()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{"id": id})
}

func (s *Server) updateCredential(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, `{"error":"id required"}`, http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(idStr, 10, 64)

	var req Credential
	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &req)

	_, err := s.db.Exec(`
		UPDATE credentials SET username = ?, password = ?, hash = ?, domain = ?,
		cred_type = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, req.Username, req.Password, req.Hash, req.Domain, req.CredType, req.Notes, id)

	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) deleteCredential(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, `{"error":"id required"}`, http.StatusBadRequest)
		return
	}
	id, _ := strconv.ParseInt(idStr, 10, 64)

	_, err := s.db.Exec("DELETE FROM credentials WHERE id = ?", id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// OS Heuristics

func (s *Server) guessOS(hostID int64) string {
	rows, err := s.db.Query(`
		SELECT port, service, version FROM ports
		WHERE host_id = ? AND state = 'open'
	`, hostID)
	if err != nil {
		return ""
	}
	defer rows.Close()

	windowsScore := 0
	linuxScore := 0

	for rows.Next() {
		var port int
		var service, version sql.NullString
		rows.Scan(&port, &service, &version)

		svc := ""
		ver := ""
		if service.Valid {
			svc = strings.ToLower(service.String)
		}
		if version.Valid {
			ver = strings.ToLower(version.String)
		}

		// Windows indicators
		if port == 135 || port == 139 || port == 445 || port == 3389 || port == 5985 || port == 5986 {
			windowsScore += 2
		}
		if strings.Contains(svc, "microsoft") || strings.Contains(ver, "microsoft") ||
			strings.Contains(svc, "windows") || strings.Contains(ver, "windows") {
			windowsScore += 3
		}
		if strings.Contains(svc, "netbios") || strings.Contains(svc, "smb") {
			windowsScore++
		}

		// Linux indicators
		if port == 22 && (strings.Contains(svc, "ssh") || strings.Contains(ver, "openssh")) {
			linuxScore += 2
		}
		if port == 111 { // rpcbind - more common on Linux
			linuxScore++
		}
		if strings.Contains(ver, "ubuntu") || strings.Contains(ver, "debian") ||
			strings.Contains(ver, "centos") || strings.Contains(ver, "linux") ||
			strings.Contains(ver, "fedora") || strings.Contains(ver, "redhat") {
			linuxScore += 3
		}
		if strings.Contains(svc, "apache") || strings.Contains(svc, "nginx") {
			linuxScore++ // Could be either, but more common on Linux
		}
	}

	if windowsScore > linuxScore && windowsScore >= 2 {
		return "windows"
	}
	if linuxScore > windowsScore && linuxScore >= 2 {
		return "linux"
	}
	return ""
}

func main() {
	dbPath := flag.String("db", "scan_results.db", "Path to SQLite database")
	port := flag.Int("port", 8080, "Port to serve on")
	password := flag.String("password", "", "Password for authentication (enables write mode)")
	flag.Parse()

	server, err := NewServer(*dbPath, *password)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// API routes - read-only (no auth required)
	http.HandleFunc("/api/stats", server.handleStats)
	http.HandleFunc("/api/hosts", server.handleHosts)
	http.HandleFunc("/api/ports", server.handlePorts)
	http.HandleFunc("/api/subnets", server.handleSubnets)
	http.HandleFunc("/api/events", server.handleSSE)

	// Auth routes
	http.HandleFunc("/api/auth-status", server.handleAuthStatus)
	http.HandleFunc("/api/login", server.handleLogin)
	http.HandleFunc("/api/logout", server.handleLogout)

	// Comments - GET is public, write requires auth
	http.HandleFunc("/api/comments", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			server.handleComments(w, r)
		} else {
			server.requireWriteAuth(server.handleComments)(w, r)
		}
	})

	// Credentials - GET is public (for viewing), write requires auth
	http.HandleFunc("/api/credentials", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			server.handleCredentials(w, r)
		} else {
			server.requireWriteAuth(server.handleCredentials)(w, r)
		}
	})

	// Host update - requires auth
	http.HandleFunc("/api/hosts/update", server.requireWriteAuth(server.handleUpdateHost))

	// Backup - download database file (no auth required for convenience)
	http.HandleFunc("/api/backup", server.handleBackup)

	// Serve frontend
	frontendDist, err := fs.Sub(frontendFS, "frontend/dist")
	if err != nil {
		// Frontend not embedded, serve from filesystem for dev
		http.Handle("/", http.FileServer(http.Dir("viewer/frontend/dist")))
	} else {
		http.Handle("/", http.FileServer(http.FS(frontendDist)))
	}

	fmt.Printf("Luftweht Viewer running at http://localhost:%d\n", *port)
	fmt.Printf("Watching database: %s\n", *dbPath)
	if *password != "" {
		fmt.Println("Authentication enabled (write mode)")
	} else {
		fmt.Println("Read-only mode (no password set)")
	}
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}
