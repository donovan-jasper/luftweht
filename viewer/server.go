package main

import (
	"database/sql"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed frontend/dist/*
var frontendFS embed.FS

type Host struct {
	ID           int64   `json:"id"`
	IP           string  `json:"ip"`
	Hostname     string  `json:"hostname"`
	Subnet       string  `json:"subnet"`
	Status       string  `json:"status"`
	DiscoveredAt string  `json:"discovered_at"`
	CompletedAt  *string `json:"completed_at"`
	OpenPorts    int     `json:"open_ports"`
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

type Server struct {
	db         *sql.DB
	dbPath     string
	clients    map[string]*SSEClient
	clientsMux sync.RWMutex
	lastUpdate time.Time
}

func NewServer(dbPath string) (*Server, error) {
	db, err := sql.Open("sqlite3", dbPath+"?mode=ro&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}

	s := &Server{
		db:      db,
		dbPath:  dbPath,
		clients: make(map[string]*SSEClient),
	}

	// Start polling for changes
	go s.pollChanges()

	return s, nil
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
	rows, _ := s.db.Query("SELECT status, COUNT(*) FROM hosts GROUP BY status")
	for rows.Next() {
		var status string
		var count int
		rows.Scan(&status, &count)
		stats.HostsByStatus[status] = count
	}
	rows.Close()

	// Hosts by subnet
	rows, _ = s.db.Query("SELECT subnet, COUNT(*) FROM hosts GROUP BY subnet")
	for rows.Next() {
		var subnet string
		var count int
		rows.Scan(&subnet, &count)
		stats.HostsBySubnet[subnet] = count
	}
	rows.Close()

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
			   (SELECT COUNT(*) FROM ports p WHERE p.host_id = h.id AND p.state = 'open') as open_ports
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
			&h.DiscoveredAt, &completedAt, &h.OpenPorts)
		if err != nil {
			continue
		}
		if completedAt.Valid {
			h.CompletedAt = &completedAt.String
		}
		hosts = append(hosts, h)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hosts)
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

func main() {
	dbPath := flag.String("db", "scan_results.db", "Path to SQLite database")
	port := flag.Int("port", 8080, "Port to serve on")
	flag.Parse()

	server, err := NewServer(*dbPath)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// API routes
	http.HandleFunc("/api/stats", server.handleStats)
	http.HandleFunc("/api/hosts", server.handleHosts)
	http.HandleFunc("/api/ports", server.handlePorts)
	http.HandleFunc("/api/subnets", server.handleSubnets)
	http.HandleFunc("/api/events", server.handleSSE)

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
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}
