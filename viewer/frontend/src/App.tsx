import { useState, useEffect, useCallback, useMemo } from 'react'
import './App.css'

interface Host {
  id: number
  ip: string
  hostname: string
  subnet: string
  status: string
  discovered_at: string
  completed_at: string | null
  open_ports: number
}

interface Port {
  id: number
  host_id: number
  port: number
  protocol: string
  state: string
  service: string
  version: string
  discovered_at: string
}

interface Stats {
  total_hosts: number
  total_open_ports: number
  hosts_by_status: Record<string, number>
  hosts_by_subnet: Record<string, number>
  scans_completed: number
  scans_pending: number
  scans_failed: number
}

// Cache for host ports (to enable port filtering)
const hostPortsCache: Record<number, Port[]> = {}

const StatusBadge = ({ status, onClick, active }: { status: string, onClick?: () => void, active?: boolean }) => {
  const colors: Record<string, string> = {
    discovered: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    tcp_scanning: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    tcp_done: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    svc_scanning: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
    svc_done: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
    udp_scanning: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    complete: 'bg-green-500/20 text-green-400 border-green-500/30',
  }

  const isScanning = status.includes('scanning')
  const baseClass = onClick ? 'cursor-pointer hover:opacity-80' : ''
  const activeClass = active ? 'ring-2 ring-white/50' : ''

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${colors[status] || 'bg-slate-700 text-slate-400 border-slate-600'} ${baseClass} ${activeClass}`}
      onClick={onClick}
    >
      {isScanning && (
        <svg className="w-3 h-3 animate-spin" viewBox="0 0 24 24" fill="none">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      )}
      {status.replace(/_/g, ' ')}
    </span>
  )
}

const HostCard = ({ host, expanded, onToggle, highlightPort }: { host: Host, expanded: boolean, onToggle: () => void, highlightPort?: number }) => {
  const [ports, setPorts] = useState<Port[]>([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (expanded && ports.length === 0 && !hostPortsCache[host.id]) {
      setLoading(true)
      fetch(`/api/ports?host_id=${host.id}`)
        .then(r => r.json())
        .then(data => {
          const portData = data || []
          setPorts(portData)
          hostPortsCache[host.id] = portData
          setLoading(false)
        })
        .catch(() => setLoading(false))
    } else if (hostPortsCache[host.id]) {
      setPorts(hostPortsCache[host.id])
    }
  }, [expanded, host.id, ports.length])

  return (
    <div className="bg-slate-800/60 rounded-xl border border-slate-700/50 overflow-hidden shadow-lg">
      <div
        className="flex items-center justify-between p-4 cursor-pointer hover:bg-slate-700/40 transition-all"
        onClick={onToggle}
      >
        <div className="flex items-center gap-4">
          <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${host.open_ports > 0 ? 'bg-emerald-500/20' : 'bg-slate-700/50'}`}>
            <svg className={`w-5 h-5 ${host.open_ports > 0 ? 'text-emerald-400' : 'text-slate-500'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
            </svg>
          </div>
          <div>
            <div className="font-mono text-base font-semibold">{host.ip}</div>
            {host.hostname && <div className="text-sm text-slate-500">{host.hostname}</div>}
          </div>
        </div>
        <div className="flex items-center gap-4">
          {host.open_ports > 0 && (
            <span className="px-3 py-1.5 bg-emerald-500/20 text-emerald-400 rounded-lg text-sm font-semibold">
              {host.open_ports} open
            </span>
          )}
          <StatusBadge status={host.status} />
          <svg className={`w-5 h-5 text-slate-500 transition-transform ${expanded ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </div>

      {expanded && (
        <div className="border-t border-slate-700/50 bg-slate-900/60">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <svg className="w-8 h-8 animate-spin text-cyan-500" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
            </div>
          ) : ports.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-xs text-slate-500 uppercase tracking-wider bg-slate-800/50">
                    <th className="px-4 py-3 text-left font-semibold">Port</th>
                    <th className="px-4 py-3 text-left font-semibold">Proto</th>
                    <th className="px-4 py-3 text-left font-semibold">State</th>
                    <th className="px-4 py-3 text-left font-semibold">Service</th>
                    <th className="px-4 py-3 text-left font-semibold">Version</th>
                  </tr>
                </thead>
                <tbody>
                  {ports.map(port => (
                    <tr
                      key={port.id}
                      className={`border-b border-slate-700/50 hover:bg-slate-800/50 transition-colors ${highlightPort === port.port ? 'bg-cyan-500/20' : ''}`}
                    >
                      <td className="px-4 py-2.5 font-mono text-sm font-medium">{port.port}</td>
                      <td className="px-4 py-2.5 text-xs uppercase text-slate-400">{port.protocol}</td>
                      <td className={`px-4 py-2.5 text-sm font-medium ${port.state === 'open' ? 'text-green-400' : port.state === 'filtered' ? 'text-yellow-400' : 'text-red-400'}`}>{port.state}</td>
                      <td className="px-4 py-2.5 text-sm text-cyan-400">{port.service || '-'}</td>
                      <td className="px-4 py-2.5 text-xs text-slate-500 truncate max-w-md">{port.version || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-12 text-slate-500">
              <svg className="w-12 h-12 mx-auto mb-3 text-slate-700" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
              <p className="text-sm">No ports discovered yet</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

const SubnetSection = ({ subnet, hosts, highlightPort }: { subnet: string, hosts: Host[], highlightPort?: number }) => {
  const [collapsed, setCollapsed] = useState(false)
  const [expandedHost, setExpandedHost] = useState<number | null>(null)

  const openPorts = hosts.reduce((sum, h) => sum + h.open_ports, 0)
  const scanning = hosts.filter(h => h.status.includes('scanning')).length
  const complete = hosts.filter(h => h.status === 'complete').length

  return (
    <div className="mb-8">
      <div
        className="flex items-center justify-between mb-4 cursor-pointer group"
        onClick={() => setCollapsed(!collapsed)}
      >
        <div className="flex items-center gap-3">
          <svg className={`w-5 h-5 text-slate-500 transition-transform ${collapsed ? '-rotate-90' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
          <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center">
            <svg className="w-5 h-5 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
            </svg>
          </div>
          <div>
            <h2 className="text-xl font-bold">{subnet}</h2>
            <p className="text-sm text-slate-500">{hosts.length} hosts</p>
          </div>
        </div>
        <div className="flex items-center gap-4 text-sm">
          {scanning > 0 && (
            <span className="flex items-center gap-2 text-yellow-400 bg-yellow-500/10 px-3 py-1.5 rounded-lg">
              <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              {scanning} scanning
            </span>
          )}
          {complete > 0 && (
            <span className="text-green-400 bg-green-500/10 px-3 py-1.5 rounded-lg">
              {complete} complete
            </span>
          )}
          {openPorts > 0 && (
            <span className="text-emerald-400 bg-emerald-500/10 px-3 py-1.5 rounded-lg font-semibold">
              {openPorts} open ports
            </span>
          )}
        </div>
      </div>

      {!collapsed && (
        <div className="space-y-3 pl-8">
          {hosts
            .sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }))
            .map(host => (
            <HostCard
              key={host.id}
              host={host}
              expanded={expandedHost === host.id}
              onToggle={() => setExpandedHost(expandedHost === host.id ? null : host.id)}
              highlightPort={highlightPort}
            />
          ))}
        </div>
      )}
    </div>
  )
}

const StatCard = ({ label, value, color, icon }: { label: string, value: number, color: string, icon: React.ReactNode }) => (
  <div className="bg-slate-800/60 rounded-xl p-5 border border-slate-700/50 shadow-lg">
    <div className="flex items-center justify-between">
      <div>
        <div className="text-3xl font-bold">{value.toLocaleString()}</div>
        <div className="text-sm text-slate-500 uppercase tracking-wide mt-1">{label}</div>
      </div>
      <div className={`w-14 h-14 rounded-xl flex items-center justify-center ${color}`}>
        {icon}
      </div>
    </div>
  </div>
)

const ALL_STATUSES = ['discovered', 'tcp_scanning', 'tcp_done', 'svc_scanning', 'svc_done', 'udp_scanning', 'complete']

function App() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [hosts, setHosts] = useState<Host[]>([])
  const [loading, setLoading] = useState(true)

  // Filter states
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<string | null>(null)
  const [portFilter, setPortFilter] = useState('')
  const [hostsWithPort, setHostsWithPort] = useState<Set<number>>(new Set())

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, hostsRes] = await Promise.all([
        fetch('/api/stats'),
        fetch('/api/hosts'),
      ])
      const statsData = await statsRes.json()
      const hostsData = await hostsRes.json()
      setStats(statsData)
      setHosts(hostsData || [])
    } catch (err) {
      console.error('Failed to fetch data:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()

    // Set up SSE for real-time updates
    const eventSource = new EventSource('/api/events')

    eventSource.onmessage = (event) => {
      const data = JSON.parse(event.data)
      if (data.type === 'stats') {
        setStats(data.stats)
        // Refresh hosts when stats change
        fetch('/api/hosts')
          .then(r => r.json())
          .then(data => setHosts(data || []))
      }
    }

    eventSource.onerror = () => {
      // Fallback to polling if SSE fails
      const interval = setInterval(fetchData, 5000)
      return () => clearInterval(interval)
    }

    return () => eventSource.close()
  }, [fetchData])

  // Fetch hosts with specific port when port filter changes
  useEffect(() => {
    const portNum = parseInt(portFilter)
    if (portNum > 0 && portNum <= 65535) {
      // We need to check which hosts have this port
      // For now, we'll load ports for all hosts that have open_ports > 0
      const hostsToCheck = hosts.filter(h => h.open_ports > 0)
      const checkPromises = hostsToCheck.map(async (host) => {
        if (!hostPortsCache[host.id]) {
          const res = await fetch(`/api/ports?host_id=${host.id}`)
          const ports = await res.json()
          hostPortsCache[host.id] = ports || []
        }
        return { hostId: host.id, ports: hostPortsCache[host.id] }
      })

      Promise.all(checkPromises).then(results => {
        const matchingHosts = new Set<number>()
        results.forEach(({ hostId, ports }) => {
          if (ports.some((p: Port) => p.port === portNum && p.state === 'open')) {
            matchingHosts.add(hostId)
          }
        })
        setHostsWithPort(matchingHosts)
      })
    } else {
      setHostsWithPort(new Set())
    }
  }, [portFilter, hosts])

  // Filter hosts based on search, status, and port
  const filteredHosts = useMemo(() => {
    let result = hosts

    // Search filter (IP, hostname)
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase()
      result = result.filter(h =>
        h.ip.toLowerCase().includes(query) ||
        (h.hostname && h.hostname.toLowerCase().includes(query)) ||
        h.subnet.toLowerCase().includes(query)
      )
    }

    // Status filter
    if (statusFilter) {
      result = result.filter(h => h.status === statusFilter)
    }

    // Port filter
    const portNum = parseInt(portFilter)
    if (portNum > 0 && portNum <= 65535 && hostsWithPort.size > 0) {
      result = result.filter(h => hostsWithPort.has(h.id))
    }

    return result
  }, [hosts, searchQuery, statusFilter, portFilter, hostsWithPort])

  // Group filtered hosts by subnet
  const hostsBySubnet = filteredHosts.reduce((acc, host) => {
    if (!acc[host.subnet]) acc[host.subnet] = []
    acc[host.subnet].push(host)
    return acc
  }, {} as Record<string, Host[]>)

  // Get unique statuses from current hosts
  const availableStatuses = useMemo(() => {
    const statuses = new Set(hosts.map(h => h.status))
    return ALL_STATUSES.filter(s => statuses.has(s))
  }, [hosts])

  const clearFilters = () => {
    setSearchQuery('')
    setStatusFilter(null)
    setPortFilter('')
  }

  const hasActiveFilters = searchQuery || statusFilter || portFilter

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-900">
        <div className="text-center">
          <svg className="w-12 h-12 animate-spin text-cyan-500 mx-auto mb-4" viewBox="0 0 24 24" fill="none">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          <p className="text-slate-500">Loading scan results...</p>
        </div>
      </div>
    )
  }

  const totalScans = stats ? stats.scans_completed + stats.scans_pending + stats.scans_failed : 0
  const progressPercent = totalScans > 0 ? (stats!.scans_completed / totalScans) * 100 : 0
  const portNum = parseInt(portFilter)

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
              <div>
                <h1 className="text-xl font-bold">Luftweht</h1>
                <p className="text-xs text-slate-500">Network Scanner</p>
              </div>
            </div>
            {stats && stats.scans_pending > 0 && (
              <div className="flex items-center gap-2 text-sm text-yellow-400">
                <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Scanning in progress...
              </div>
            )}
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Stats Grid */}
        {stats && (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <StatCard
              label="Hosts"
              value={stats.total_hosts}
              color="bg-cyan-500/20"
              icon={<svg className="w-7 h-7 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" /></svg>}
            />
            <StatCard
              label="Open Ports"
              value={stats.total_open_ports}
              color="bg-emerald-500/20"
              icon={<svg className="w-7 h-7 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>}
            />
            <StatCard
              label="Completed"
              value={stats.scans_completed}
              color="bg-green-500/20"
              icon={<svg className="w-7 h-7 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>}
            />
            <StatCard
              label="Pending"
              value={stats.scans_pending}
              color="bg-yellow-500/20"
              icon={<svg className="w-7 h-7 text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>}
            />
          </div>
        )}

        {/* Progress Bar */}
        {stats && stats.scans_pending > 0 && (
          <div className="mb-8 bg-slate-800/60 rounded-xl p-4 border border-slate-700/50">
            <div className="flex justify-between text-sm mb-2">
              <span className="text-slate-400 font-medium">Scan Progress</span>
              <span className="text-slate-500">
                {stats.scans_completed.toLocaleString()} / {totalScans.toLocaleString()} chunks
              </span>
            </div>
            <div className="h-3 bg-slate-900 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-emerald-500 transition-all duration-700 ease-out rounded-full"
                style={{ width: `${progressPercent}%` }}
              />
            </div>
            <div className="text-right text-xs text-slate-500 mt-1">{progressPercent.toFixed(1)}%</div>
          </div>
        )}

        {/* Search and Filter Bar */}
        <div className="mb-6 bg-slate-800/60 rounded-xl p-4 border border-slate-700/50">
          <div className="flex flex-wrap gap-4 items-center">
            {/* Search Input */}
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
                <input
                  type="text"
                  placeholder="Search IP, hostname, subnet..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-900/60 border border-slate-700 rounded-lg text-sm focus:outline-none focus:border-cyan-500 transition-colors"
                />
              </div>
            </div>

            {/* Port Filter */}
            <div className="w-32">
              <input
                type="text"
                placeholder="Port #"
                value={portFilter}
                onChange={(e) => setPortFilter(e.target.value.replace(/\D/g, ''))}
                className="w-full px-4 py-2.5 bg-slate-900/60 border border-slate-700 rounded-lg text-sm focus:outline-none focus:border-cyan-500 transition-colors text-center font-mono"
              />
            </div>

            {/* Clear Filters */}
            {hasActiveFilters && (
              <button
                onClick={clearFilters}
                className="px-4 py-2.5 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm transition-colors flex items-center gap-2"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
                Clear
              </button>
            )}
          </div>

          {/* Status Filter Pills */}
          {availableStatuses.length > 0 && (
            <div className="flex flex-wrap gap-2 mt-4">
              <span className="text-xs text-slate-500 py-1">Status:</span>
              {availableStatuses.map(status => (
                <StatusBadge
                  key={status}
                  status={status}
                  onClick={() => setStatusFilter(statusFilter === status ? null : status)}
                  active={statusFilter === status}
                />
              ))}
            </div>
          )}

          {/* Filter Results Summary */}
          {hasActiveFilters && (
            <div className="mt-3 pt-3 border-t border-slate-700/50 text-sm text-slate-400">
              Showing {filteredHosts.length} of {hosts.length} hosts
              {statusFilter && <span className="ml-2">• Status: {statusFilter.replace(/_/g, ' ')}</span>}
              {portNum > 0 && <span className="ml-2">• Port: {portNum} ({hostsWithPort.size} hosts)</span>}
            </div>
          )}
        </div>

        {/* Hosts by Subnet */}
        {Object.keys(hostsBySubnet).length > 0 ? (
          Object.entries(hostsBySubnet)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([subnet, subnetHosts]) => (
              <SubnetSection
                key={subnet}
                subnet={subnet}
                hosts={subnetHosts}
                highlightPort={portNum > 0 ? portNum : undefined}
              />
            ))
        ) : (
          <div className="text-center py-20">
            <div className="w-20 h-20 rounded-2xl bg-slate-800 flex items-center justify-center mx-auto mb-6">
              <svg className="w-10 h-10 text-slate-700" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
              </svg>
            </div>
            <h3 className="text-xl font-semibold text-slate-400 mb-2">
              {hasActiveFilters ? 'No hosts match your filters' : 'No hosts discovered yet'}
            </h3>
            <p className="text-slate-600">
              {hasActiveFilters ? 'Try adjusting your search or filters' : 'Start a scan to see results here in real-time'}
            </p>
          </div>
        )}
      </main>
    </div>
  )
}

export default App
