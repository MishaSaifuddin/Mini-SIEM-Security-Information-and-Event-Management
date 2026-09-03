import React, { useState, useEffect } from 'react';
import { alertService } from '../services';
import { Badge, StatusBadge, Loading, Empty, Card, formatTime, timeAgo } from '../components/UI';

function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ status: '', severity: '', search: '' });
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [stats, setStats] = useState(null);

  useEffect(() => {
    loadAlerts();
    loadStats();
  }, [filters]);

  const loadAlerts = async () => {
    setLoading(true);
    try {
      const params = { limit: 50 };
      if (filters.status) params.status = filters.status;
      if (filters.severity) params.severity = filters.severity;
      if (filters.search) params.search = filters.search;
      const res = await alertService.getAlerts(params);
      setAlerts(res.data.alerts);
      setTotal(res.data.total);
    } catch (e) {
      // handled by interceptor
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      const res = await alertService.getStats(24);
      setStats(res.data);
    } catch (e) {}
  };

  const updateAlertStatus = async (id, status, notes) => {
    try {
      await alertService.updateAlert(id, { status, resolution_notes: notes });
      loadAlerts();
      loadStats();
      setSelectedAlert(null);
    } catch (e) {}
  };

  const handleFilterChange = (key, value) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
  };

  return (
    <div>
      {/* Stats overview */}
      {stats && (
        <div className="filter-bar" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '10px', padding: '16px', marginBottom: '16px', display: 'flex', gap: '24px', justifyContent: 'space-around' }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '24px', fontWeight: '700', color: 'var(--info)' }}>{stats.total}</div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Total (24h)</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '24px', fontWeight: '700', color: 'var(--danger)' }}>{stats.open}</div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Open</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '24px', fontWeight: '700', color: 'var(--danger)' }}>
              {(stats.severity_counts?.critical || 0)}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Critical</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '24px', fontWeight: '700', color: '#f97316' }}>
              {(stats.severity_counts?.high || 0)}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>High</div>
          </div>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: '24px', fontWeight: '700', color: 'var(--warning)' }}>
              {(stats.severity_counts?.medium || 0)}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Medium</div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="filter-bar">
        <input
          type="text"
          placeholder="Search alert title..."
          value={filters.search}
          onChange={(e) => handleFilterChange('search', e.target.value)}
          style={{ flex: 1, minWidth: '200px' }}
        />
        <select value={filters.status} onChange={(e) => handleFilterChange('status', e.target.value)}>
          <option value="">All Status</option>
          <option value="open">Open</option>
          <option value="in_progress">In Progress</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
        </select>
        <select value={filters.severity} onChange={(e) => handleFilterChange('severity', e.target.value)}>
          <option value="">All Severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <button className="btn" onClick={loadAlerts}>Refresh</button>
      </div>

      {/* Alerts Table */}
      <Card>
        <div className="card-title">
          <span>Alerts {total > 0 && <span style={{ color: 'var(--text-muted)', fontWeight: 'normal' }}>({total} total)</span>}</span>
        </div>
        {loading ? (
          <Loading text="Loading alerts..." />
        ) : alerts.length === 0 ? (
          <Empty message="No alerts. When detection rules trigger, alerts will appear here." />
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Alert</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Source</th>
                  <th>Host</th>
                  <th>MITRE</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <Row
                    key={alert.id}
                    alert={alert}
                    onView={() => setSelectedAlert(alert)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Detail Modal */}
      {selectedAlert && (
        <AlertDetail
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onUpdate={updateAlertStatus}
        />
      )}
    </div>
  );
}

function Row({ alert, onView }) {
  return (
    <tr style={{ cursor: 'pointer' }} onClick={onView}>
      <td>{timeAgo(alert.timestamp)}</td>
      <td style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        <b>{alert.title}</b>
      </td>
      <td><Badge severity={alert.severity} /></td>
      <td><StatusBadge status={alert.status} /></td>
      <td>{alert.source || '-'}</td>
      <td>{alert.hostname || '-'}</td>
      <td>{alert.mitre_technique || '-'}</td>
      <td>
        <button className="btn btn-sm btn-outline" onClick={(e) => { e.stopPropagation(); onView(); }}>
          Details
        </button>
      </td>
    </tr>
  );
}

function AlertDetail({ alert, onClose, onUpdate }) {
  const [notes, setNotes] = useState(alert.resolution_notes || '');
  const [related, setRelated] = useState([]);
  const [loadingRelated, setLoadingRelated] = useState(false);

  const loadRelated = async () => {
    setLoadingRelated(true);
    try {
      const res = await alertService.getRelatedEvents(alert.id);
      setRelated(res.data);
    } catch (e) {}
    finally {
      setLoadingRelated(false);
    }
  };

  useEffect(() => {
    loadRelated();
    // eslint-disable-next-line
  }, []);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ width: 800 }} onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Alert #{alert.id}</h2>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>

        <div style={{ display: 'flex', gap: '12px', marginBottom: '16px', flexWrap: 'wrap' }}>
          <Badge severity={alert.severity} />
          <StatusBadge status={alert.status} />
          {alert.mitre_technique && <Badge className="badge-warning">{alert.mitre_technique}</Badge>}
          {alert.mitre_tactic && <Badge className="badge-info">{alert.mitre_tactic}</Badge>}
          {alert.tags?.map((tag) => <Badge key={tag} className="badge-low">{tag}</Badge>)}
        </div>

        <div className="detail-row">
          <div className="detail-label">Title</div>
          <div className="detail-value" style={{ fontWeight: 600 }}>{alert.title}</div>
        </div>
        <div className="detail-row">
          <div className="detail-label">Rule</div>
          <div className="detail-value">{alert.rule_name}</div>
        </div>
        <div className="detail-row">
          <div className="detail-label">Timestamp</div>
          <div className="detail-value">{formatTime(alert.timestamp)}</div>
        </div>
        <div className="detail-row">
          <div className="detail-label">Source</div>
          <div className="detail-value">{alert.source || '-'}</div>
        </div>
        <div className="detail-row">
          <div className="detail-label">Hostname</div>
          <div className="detail-value">{alert.hostname || '-'}</div>
        </div>
        <div className="detail-row">
          <div className="detail-label">IP Address</div>
          <div className="detail-value">{alert.ip_address || '-'}</div>
        </div>
        <div className="detail-row">
          <div className="detail-label">Description</div>
          <div className="detail-value">{alert.description}</div>
        </div>
        <div className="detail-row">
          <div className="detail-label">Events</div>
          <div className="detail-value">{alert.event_count} event(s)</div>
        </div>

        {/* Match details */}
        <div style={{ marginTop: '16px', marginBottom: '16px' }}>
          <h3 style={{ fontSize: '14px', marginBottom: '10px' }}>Related Events</h3>
          {loadingRelated ? (
            <div className="loading">Loading related events...</div>
          ) : related.length > 0 ? (
            <div className="table-container" style={{ maxHeight: '200px', overflowY: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Event Type</th>
                    <th>User</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {related.slice(0, 20).map((ev) => (
                    <tr key={ev.id}>
                      <td>{ev.id}</td>
                      <td>{formatTime(ev.timestamp)}</td>
                      <td>{ev.source_name || '-'}</td>
                      <td>{ev.event_type || '-'}</td>
                      <td>{ev.user || '-'}</td>
                      <td style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {ev.description || '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty">No related events found</div>
          )}
        </div>

        {/* Resolutions */}
        {(['open', 'in_progress'].includes(alert.status)) && (
          <div>
            <div className="form-group">
              <label>Resolution Notes</label>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Document investigation findings..."
              />
            </div>
            <div className="modal-actions" style={{ marginTop: 10 }}>
              <button
                className="btn-outline"
                onClick={() => { onUpdate(alert.id, 'in_progress', notes); }}
              >
                Mark In Progress
              </button>
              <button
                className="btn-outline"
                onClick={() => { onUpdate(alert.id, 'false_positive', notes); }}
              >
                False Positive
              </button>
              <button
                className="btn"
                onClick={() => { onUpdate(alert.id, 'resolved', notes); }}
              >
                Resolve
              </button>
            </div>
          </div>
        )}

        <div className="modal-actions">
          <button className="btn-outline" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}

export default Alerts;
