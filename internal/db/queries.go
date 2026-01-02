package db

import (
	"database/sql"
	"time"

	"github.com/donovan-jasper/luftweht/internal/models"
)

// InsertHost inserts a new host or returns existing one
func (db *DB) InsertHost(ip, hostname, subnet string) (*models.Host, error) {
	result, err := db.Exec(`
		INSERT INTO hosts (ip, hostname, subnet, status, discovered_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			hostname = COALESCE(NULLIF(excluded.hostname, ''), hostname),
			subnet = COALESCE(NULLIF(excluded.subnet, ''), subnet)
	`, ip, hostname, subnet, models.HostStatusDiscovered, time.Now())
	if err != nil {
		return nil, err
	}

	// Get the host (either inserted or existing)
	host, err := db.GetHostByIP(ip)
	if err != nil {
		return nil, err
	}

	// If we inserted a new row, update the ID
	if id, err := result.LastInsertId(); err == nil && id > 0 {
		host.ID = id
	}

	return host, nil
}

// GetHostByIP retrieves a host by IP address
func (db *DB) GetHostByIP(ip string) (*models.Host, error) {
	host := &models.Host{}
	var completedAt sql.NullTime

	err := db.QueryRow(`
		SELECT id, ip, hostname, subnet, status, discovered_at, completed_at
		FROM hosts WHERE ip = ?
	`, ip).Scan(
		&host.ID, &host.IP, &host.Hostname, &host.Subnet,
		&host.Status, &host.DiscoveredAt, &completedAt,
	)
	if err != nil {
		return nil, err
	}

	if completedAt.Valid {
		host.CompletedAt = &completedAt.Time
	}

	return host, nil
}

// GetHostByID retrieves a host by ID
func (db *DB) GetHostByID(id int64) (*models.Host, error) {
	host := &models.Host{}
	var completedAt sql.NullTime

	err := db.QueryRow(`
		SELECT id, ip, hostname, subnet, status, discovered_at, completed_at
		FROM hosts WHERE id = ?
	`, id).Scan(
		&host.ID, &host.IP, &host.Hostname, &host.Subnet,
		&host.Status, &host.DiscoveredAt, &completedAt,
	)
	if err != nil {
		return nil, err
	}

	if completedAt.Valid {
		host.CompletedAt = &completedAt.Time
	}

	return host, nil
}

// UpdateHostStatus updates the status of a host
func (db *DB) UpdateHostStatus(hostID int64, status models.HostStatus) error {
	var completedAt interface{}
	if status == models.HostStatusComplete {
		completedAt = time.Now()
	}

	_, err := db.Exec(`
		UPDATE hosts SET status = ?, completed_at = ?
		WHERE id = ?
	`, status, completedAt, hostID)
	return err
}

// GetHostsByStatus retrieves all hosts with a given status
func (db *DB) GetHostsByStatus(status models.HostStatus) ([]models.Host, error) {
	rows, err := db.Query(`
		SELECT id, ip, hostname, subnet, status, discovered_at, completed_at
		FROM hosts WHERE status = ?
	`, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []models.Host
	for rows.Next() {
		var host models.Host
		var completedAt sql.NullTime

		if err := rows.Scan(
			&host.ID, &host.IP, &host.Hostname, &host.Subnet,
			&host.Status, &host.DiscoveredAt, &completedAt,
		); err != nil {
			return nil, err
		}

		if completedAt.Valid {
			host.CompletedAt = &completedAt.Time
		}
		hosts = append(hosts, host)
	}

	return hosts, rows.Err()
}

// GetAllHosts retrieves all hosts
func (db *DB) GetAllHosts() ([]models.Host, error) {
	rows, err := db.Query(`
		SELECT id, ip, hostname, subnet, status, discovered_at, completed_at
		FROM hosts ORDER BY discovered_at
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []models.Host
	for rows.Next() {
		var host models.Host
		var completedAt sql.NullTime

		if err := rows.Scan(
			&host.ID, &host.IP, &host.Hostname, &host.Subnet,
			&host.Status, &host.DiscoveredAt, &completedAt,
		); err != nil {
			return nil, err
		}

		if completedAt.Valid {
			host.CompletedAt = &completedAt.Time
		}
		hosts = append(hosts, host)
	}

	return hosts, rows.Err()
}

// InsertPort inserts or updates a port record
func (db *DB) InsertPort(hostID int64, port int, protocol, state, service, version string) error {
	_, err := db.Exec(`
		INSERT INTO ports (host_id, port, protocol, state, service, version, discovered_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host_id, port, protocol) DO UPDATE SET
			state = excluded.state,
			service = COALESCE(NULLIF(excluded.service, ''), service),
			version = COALESCE(NULLIF(excluded.version, ''), version)
	`, hostID, port, protocol, state, service, version, time.Now())
	return err
}

// InsertPorts inserts multiple ports in a transaction
func (db *DB) InsertPorts(ports []models.Port) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO ports (host_id, port, protocol, state, service, version, discovered_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host_id, port, protocol) DO UPDATE SET
			state = excluded.state,
			service = COALESCE(NULLIF(excluded.service, ''), service),
			version = COALESCE(NULLIF(excluded.version, ''), version)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, p := range ports {
		_, err := stmt.Exec(p.HostID, p.Port, p.Protocol, p.State, p.Service, p.Version, time.Now())
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetOpenPorts retrieves all open ports for a host
func (db *DB) GetOpenPorts(hostID int64, protocol string) ([]models.Port, error) {
	rows, err := db.Query(`
		SELECT id, host_id, port, protocol, state, service, version, discovered_at
		FROM ports
		WHERE host_id = ? AND protocol = ? AND state = 'open'
		ORDER BY port
	`, hostID, protocol)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ports []models.Port
	for rows.Next() {
		var p models.Port
		if err := rows.Scan(
			&p.ID, &p.HostID, &p.Port, &p.Protocol,
			&p.State, &p.Service, &p.Version, &p.DiscoveredAt,
		); err != nil {
			return nil, err
		}
		ports = append(ports, p)
	}

	return ports, rows.Err()
}

// GetPortsForHost retrieves all ports for a host
func (db *DB) GetPortsForHost(hostID int64) ([]models.Port, error) {
	rows, err := db.Query(`
		SELECT id, host_id, port, protocol, state, service, version, discovered_at
		FROM ports
		WHERE host_id = ?
		ORDER BY protocol, port
	`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ports []models.Port
	for rows.Next() {
		var p models.Port
		if err := rows.Scan(
			&p.ID, &p.HostID, &p.Port, &p.Protocol,
			&p.State, &p.Service, &p.Version, &p.DiscoveredAt,
		); err != nil {
			return nil, err
		}
		ports = append(ports, p)
	}

	return ports, rows.Err()
}

// CreateScanProgress creates a scan progress record
func (db *DB) CreateScanProgress(hostID *int64, subnet string, scanType models.ScanType, portStart, portEnd int) (int64, error) {
	result, err := db.Exec(`
		INSERT INTO scan_progress (host_id, subnet, scan_type, port_start, port_end, status)
		VALUES (?, ?, ?, ?, ?, ?)
	`, hostID, subnet, scanType, portStart, portEnd, models.ProgressStatusPending)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// UpdateScanProgressStatus updates the status of a scan progress record
func (db *DB) UpdateScanProgressStatus(id int64, status models.ProgressStatus, errMsg string) error {
	var startedAt, completedAt interface{}
	now := time.Now()

	if status == models.ProgressStatusRunning {
		startedAt = now
	}
	if status == models.ProgressStatusComplete || status == models.ProgressStatusFailed {
		completedAt = now
	}

	_, err := db.Exec(`
		UPDATE scan_progress
		SET status = ?,
			started_at = COALESCE(?, started_at),
			completed_at = ?,
			error = ?
		WHERE id = ?
	`, status, startedAt, completedAt, errMsg, id)
	return err
}

// GetNextPendingScan retrieves the next scan to execute
func (db *DB) GetNextPendingScan() (*models.ScanProgress, error) {
	sp := &models.ScanProgress{}
	var hostID sql.NullInt64
	var subnet sql.NullString
	var startedAt, completedAt sql.NullTime
	var errStr sql.NullString

	err := db.QueryRow(`
		SELECT id, host_id, subnet, scan_type, port_start, port_end,
			   status, started_at, completed_at, error
		FROM scan_progress
		WHERE status = 'pending'
		ORDER BY
			CASE scan_type
				WHEN 'discovery' THEN 0
				WHEN 'tcp' THEN 1
				WHEN 'svc' THEN 2
				WHEN 'udp' THEN 3
			END,
			port_start,
			host_id
		LIMIT 1
	`).Scan(
		&sp.ID, &hostID, &subnet, &sp.ScanType, &sp.PortStart, &sp.PortEnd,
		&sp.Status, &startedAt, &completedAt, &errStr,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if hostID.Valid {
		sp.HostID = &hostID.Int64
	}
	if subnet.Valid {
		sp.Subnet = subnet.String
	}
	if startedAt.Valid {
		sp.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		sp.CompletedAt = &completedAt.Time
	}
	if errStr.Valid {
		sp.Error = errStr.String
	}

	return sp, nil
}

// GetPendingScansByType retrieves all pending scans of a given type
func (db *DB) GetPendingScansByType(scanType models.ScanType) ([]models.ScanProgress, error) {
	rows, err := db.Query(`
		SELECT id, host_id, subnet, scan_type, port_start, port_end,
			   status, started_at, completed_at, error
		FROM scan_progress
		WHERE scan_type = ? AND status = 'pending'
		ORDER BY id
	`, scanType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []models.ScanProgress
	for rows.Next() {
		var sp models.ScanProgress
		var hostID sql.NullInt64
		var subnet sql.NullString
		var startedAt, completedAt sql.NullTime
		var errStr sql.NullString

		if err := rows.Scan(
			&sp.ID, &hostID, &subnet, &sp.ScanType, &sp.PortStart, &sp.PortEnd,
			&sp.Status, &startedAt, &completedAt, &errStr,
		); err != nil {
			return nil, err
		}

		if hostID.Valid {
			sp.HostID = &hostID.Int64
		}
		if subnet.Valid {
			sp.Subnet = subnet.String
		}
		if startedAt.Valid {
			sp.StartedAt = &startedAt.Time
		}
		if completedAt.Valid {
			sp.CompletedAt = &completedAt.Time
		}
		if errStr.Valid {
			sp.Error = errStr.String
		}

		scans = append(scans, sp)
	}

	return scans, rows.Err()
}

// GetScanStats returns statistics about the current scan
func (db *DB) GetScanStats() (map[string]int, error) {
	stats := make(map[string]int)

	// Host counts by status
	rows, err := db.Query(`SELECT status, COUNT(*) FROM hosts GROUP BY status`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			rows.Close()
			return nil, err
		}
		stats["hosts_"+status] = count
	}
	rows.Close()

	// Total open ports
	var openPorts int
	err = db.QueryRow(`SELECT COUNT(*) FROM ports WHERE state = 'open'`).Scan(&openPorts)
	if err != nil {
		return nil, err
	}
	stats["open_ports"] = openPorts

	// Scan progress counts
	rows, err = db.Query(`SELECT status, COUNT(*) FROM scan_progress GROUP BY status`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			rows.Close()
			return nil, err
		}
		stats["scans_"+status] = count
	}
	rows.Close()

	return stats, nil
}

// CreateChunkJobs creates scan progress records for all chunks
func (db *DB) CreateChunkJobs(hostID int64, scanType models.ScanType, chunks []models.PortChunk) ([]int64, error) {
	var ids []int64
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO scan_progress (host_id, scan_type, port_start, port_end, status)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	for _, chunk := range chunks {
		result, err := stmt.Exec(hostID, scanType, chunk.Start, chunk.End, models.ProgressStatusPending)
		if err != nil {
			return nil, err
		}
		id, _ := result.LastInsertId()
		ids = append(ids, id)
	}

	return ids, tx.Commit()
}

// GetHostChunkProgress retrieves chunk progress for a host and scan type
func (db *DB) GetHostChunkProgress(hostID int64, scanType models.ScanType) (*models.HostChunkProgress, error) {
	rows, err := db.Query(`
		SELECT port_start, port_end, status, id
		FROM scan_progress
		WHERE host_id = ? AND scan_type = ?
		ORDER BY port_start
	`, hostID, scanType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	progress := &models.HostChunkProgress{
		HostID:          hostID,
		ScanType:        scanType,
		CompletedChunks: make(map[int]bool),
	}

	chunkIndex := 0
	for rows.Next() {
		var start, end int
		var status models.ProgressStatus
		var id int64

		if err := rows.Scan(&start, &end, &status, &id); err != nil {
			return nil, err
		}

		if status == models.ProgressStatusComplete {
			progress.CompletedChunks[chunkIndex] = true
		}
		chunkIndex++
	}

	progress.TotalChunks = chunkIndex
	return progress, rows.Err()
}

// GetNewPortsForServiceDetection retrieves ports discovered after a given time without service info
func (db *DB) GetNewPortsForServiceDetection(hostID int64, afterTime time.Time) ([]models.Port, error) {
	rows, err := db.Query(`
		SELECT id, host_id, port, protocol, state, service, version, discovered_at
		FROM ports
		WHERE host_id = ? AND state = 'open' AND discovered_at >= ?
			  AND (service IS NULL OR service = '')
		ORDER BY protocol, port
	`, hostID, afterTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ports []models.Port
	for rows.Next() {
		var p models.Port
		if err := rows.Scan(&p.ID, &p.HostID, &p.Port, &p.Protocol,
			&p.State, &p.Service, &p.Version, &p.DiscoveredAt); err != nil {
			return nil, err
		}
		ports = append(ports, p)
	}

	return ports, rows.Err()
}

// GetChunkProgressID retrieves the scan_progress ID for a specific chunk
func (db *DB) GetChunkProgressID(hostID int64, scanType models.ScanType, portStart, portEnd int) (int64, error) {
	var id int64
	err := db.QueryRow(`
		SELECT id FROM scan_progress
		WHERE host_id = ? AND scan_type = ? AND port_start = ? AND port_end = ?
	`, hostID, scanType, portStart, portEnd).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}
