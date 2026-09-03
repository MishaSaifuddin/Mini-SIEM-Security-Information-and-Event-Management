import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import { dashboardService } from '../services';
import { KpiCard, Badge, StatusBadge, Loading, Empty, Card, timeAgo } from '../components/UI';

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22c55e',
  info: '#3b82f6',
};

function Dashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
    try {
      const res = await dashboardService.getSummary(24);
      setData(res.data);
    } catch (e) {
      // handled by interceptor
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <Loading text="Loading security dashboard..." />;
  if (!data) return <Empty message="No data available. Start ingesting logs." />;

  const { kpis, event_timeline, alert_timeline, top_sources, top_event_types,
    event_severity, alert_severity, top_rules, recent_alerts } = data;

  const eventSeverityData = Object.entries(event_severity || {}).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
  }));

  const alertSeverityData = Object.entries(alert_severity || {}).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
  }));

  const combinedTimeline = useMemoTimeline(event_timeline, alert_timeline);

  return (
    <div>
      {/* KPI Cards */}
      <div className="kpi-grid">
        <KpiCard
          color="blue"
          label="Events (24h)"
          value={kpis.total_events.toLocaleString()}
          icon={<span>📊</span>}
        />
        <KpiCard
          color="teal"
          label="Events / Min"
          value={kpis.events_per_min}
          icon={<span>⚡</span>}
        />
        <KpiCard
          color="red"
          label="Alerts (24h)"
          value={kpis.total_alerts}
          icon={<span>🚨</span>}
        />
        <KpiCard
          color="yellow"
          label="Open Alerts"
          value={kpis.open_alerts}
          icon={<span>⏳</span>}
        />
        <KpiCard
          color="danger"
          label="Critical Alerts"
          value={kpis.critical_alerts}
          icon={<span>☠️</span>}
        />
        <KpiCard
          color="green"
          label="Active Sources"
          value={`${kpis.active_sources}/${kpis.total_sources}`}
          icon={<span>🖥️</span>}
        />
        <KpiCard
          color="purple"
          label="Active Rules"
          value={kpis.active_rules}
          icon={<span>🛡️</span>}
        />
      </div>

      {/* Charts */}
      <div className="chart-grid">
        <Card title="Event & Alert Activity (24h)">
          <ResponsiveContainer width="100%" height={280}>
            <LineChart data={combinedTimeline}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="label" stroke="#94a3b8" fontSize={11} />
              <YAxis stroke="#94a3b8" fontSize={11} />
              <Tooltip
                contentStyle={{ background: '#1e293b', border: '1px solid #334155' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
              <Legend />
              <Line type="monotone" dataKey="events" stroke="#3b82f6" dot={false} name="Events" />
              <Line type="monotone" dataKey="alerts" stroke="#ef4444" dot={false} name="Alerts" />
            </LineChart>
          </ResponsiveContainer>
        </Card>

        <Card title="Event Severity Distribution">
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={eventSeverityData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                outerRadius={90}
                label={(entry) => `${entry.name}`}
              >
                {eventSeverityData.map((entry, i) => (
                  <Cell key={i} fill={SEVERITY_COLORS[entry.name.toLowerCase()] || '#94a3b8'} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155' }} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </Card>
      </div>

      <div className="chart-grid">
        <Card title="Top Log Sources">
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={top_sources}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="name" stroke="#94a3b8" fontSize={10} tickFormatter={(v) => v.length > 14 ? v.substring(0, 12) + '...' : v} />
              <YAxis stroke="#94a3b8" fontSize={11} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155' }} />
              <Bar dataKey="count" fill="#0d9488" name="Events" />
            </BarChart>
          </ResponsiveContainer>
        </Card>

        <Card title="Top Event Types">
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Event Type</th>
                  <th style={{ textAlign: 'right' }}>Count</th>
                </tr>
              </thead>
              <tbody>
                {top_event_types.map((item, i) => (
                  <tr key={i}>
                    <td>{item.type}</td>
                    <td style={{ textAlign: 'right' }}>{item.count.toLocaleString()}</td>
                  </tr>
                ))}
                {!top_event_types.length && (
                  <tr><td colSpan={2} style={{ color: 'var(--text-muted)' }}>No events yet</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </div>

      <div className="chart-grid">
        <Card title="Alert Severity">
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={alertSeverityData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                outerRadius={80}
                label={(entry) => `${entry.name} (${entry.value})`}
              >
                {alertSeverityData.map((entry, i) => (
                  <Cell key={i} fill={SEVERITY_COLORS[entry.name.toLowerCase()] || '#94a3b8'} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155' }} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </Card>

        <Card title="Top Detected Rules">
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Detection Rule</th>
                  <th style={{ textAlign: 'right' }}>Triggers</th>
                                </tr>
              </thead>
              <tbody>
                {top_rules.map((item, i) => (
                  <tr key={i}>
                    <td>{item.rule}</td>
                    <td style={{ textAlign: 'right' }}>{item.count}</td>
                  </tr>
                ))}
                {!top_rules.length && (
                  <tr><td colSpan={2} style={{ color: 'var(--text-muted)' }}>No alerts triggered yet</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </div>

      {/* Recent Alerts */}
      <Card
        title="Recent Alerts"
        action={<Link to="/alerts" className="btn btn-sm btn-outline">View All</Link>}
      >
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Title</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {recent_alerts.map((alert) => (
                <tr key={alert.id}>
                  <td>
                    <Link to={`/alerts`} style={{ color: 'var(--text)', textDecoration: 'none' }}>
                      {alert.title}
                    </Link>
                  </td>
                  <td><Badge severity={alert.severity} /></td>
                  <td><StatusBadge status={alert.status} /></td>
                  <td>{timeAgo(alert.timestamp)}</td>
                </tr>
              ))}
              {!recent_alerts.length && (
                <tr><td colSpan={4} style={{ color: 'var(--text-muted)' }}>No alerts yet</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

function useMemoTimeline(events, alerts) {
  const map = {};
  (events || []).forEach((item) => {
    map[item.timestamp] = { label: item.timestamp, events: item.count, alerts: 0 };
  });
  (alerts || []).forEach((item) => {
    if (!map[item.timestamp]) map[item.timestamp] = { label: item.timestamp, events: 0 };
    map[item.timestamp].alerts = item.count;
  });
  return Object.values(map).sort((a, b) => a.label.localeCompare(b.label)).slice(-24);
}

export default Dashboard;
