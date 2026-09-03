import React, { useState, useEffect } from 'react';
import { sourceService, eventService } from '../services';
import { Loading, Empty, Card, Modal, formatTime, timeAgo } from '../components/UI';

const SOURCE_TYPE_ICONS = {
  windows: '🪟',
  auth: '🔑',
  firewall: '🔥',
  web_server: '🌐',
  syslog: '📋',
  custom_json: '📦',
  custom: '📄',
};

function Sources() {
  const [sources, setSources] = useState([]);
  const [eventCounts, setEventCounts] = useState({});
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);

  useEffect(() => {
    loadSources();
  }, []);

  const loadSources = async () => {
    setLoading(true);
    try {
      const res = await sourceService.getSources();
      setSources(res.data);
      // Get event counts per source
      const evRes = await eventService.getSources();
      const counts = {};
      evRes.data.forEach((s) => {
        counts[s.source_name] = { count: s.event_count, last: s.last_event };
      });
      setEventCounts(counts);
    } catch (e) {
    } finally {
      setLoading(false);
    }
  };

  const toggleSource = async (source) => {
    try {
      await sourceService.updateSource(source.id, { enabled: !source.enabled });
      loadSources();
    } catch (e) {}
  };

  const deleteSource = async (source) => {
    if (!window.confirm(`Delete source "${source.name}"?`)) return;
    try {
      await sourceService.deleteSource(source.id);
      loadSources();
    } catch (e) {}
  };

  return (
    <div>
      <div className="filter-bar" style={{ justifyContent: 'flex-end' }}>
        <button className="btn" onClick={() => setShowCreate(true)}>+ Register Source</button>
      </div>

      <Card>
        <div className="card-title">
          <span>Registered Log Sources ({sources.length})</span>
        </div>
        {loading ? (
          <Loading text="Loading sources..." />
        ) : sources.length === 0 ? (
          <Empty message="No log sources registered. Sources auto-register when they send events, or you can register them manually." />
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Type</th>
                  <th>Hostname</th>
                  <th>IP</th>
                  <th>Events</th>
                  <th>Last Event</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sources.map((source) => {
                  const stats = eventCounts[source.name] || { count: 0, last: null };
                  return (
                    <tr key={source.id}>
                      <td style={{ fontWeight: 500 }}>
                        {SOURCE_TYPE_ICONS[source.source_type] || '📄'} {source.name}
                      </td>
                      <td>{source.source_type}</td>
                      <td>{source.hostname || '-'}</td>
                      <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{source.ip_address || '-'}</td>
                      <td>{stats.count?.toLocaleString() || 0}</td>
                      <td>{stats.last ? timeAgo(stats.last) : '-'}</td>
                      <td>
                        <span className={`badge ${source.enabled ? 'badge-resolved' : 'badge-closed'}`}>
                          {source.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '6px' }}>
                          <button className="btn btn-sm btn-outline" onClick={() => toggleSource(source)}>
                            {source.enabled ? 'Disable' : 'Enable'}
                          </button>
                          <button className="btn btn-sm btn-danger" onClick={() => deleteSource(source)}>Del</button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {showCreate && <CreateSourceModal onClose={() => setShowCreate(false)} onSaved={() => { setShowCreate(false); loadSources(); }} />}
    </div>
  );
}

function CreateSourceModal({ onClose, onSaved }) {
  const [form, setForm] = useState({
    name: '',
    source_type: 'custom',
    hostname: '',
    ip_address: '',
    description: '',
  });
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.name) {
      setError('Name is required');
      return;
    }
    try {
      await sourceService.createSource(form);
      onSaved();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create source');
    }
  };

  return (
    <Modal title="Register Log Source" onClose={onClose}>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>Name *</label>
          <input type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g., web-server-01" />
        </div>
        <div className="form-group">
          <label>Source Type</label>
          <select value={form.source_type} onChange={(e) => setForm({ ...form, source_type: e.target.value })}>
            <option value="windows">Windows Event Log</option>
            <option value="auth">Auth Log</option>
            <option value="firewall">Firewall</option>
            <option value="web_server">Web Server</option>
            <option value="syslog">Syslog</option>
            <option value="custom_json">JSON App Log</option>
            <option value="custom">Custom</option>
          </select>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
          <div className="form-group">
            <label>Hostname</label>
            <input type="text" value={form.hostname} onChange={(e) => setForm({ ...form, hostname: e.target.value })} />
          </div>
          <div className="form-group">
            <label>IP Address</label>
            <input type="text" value={form.ip_address} onChange={(e) => setForm({ ...form, ip_address: e.target.value })} />
          </div>
        </div>
        <div className="form-group">
          <label>Description</label>
          <textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
        </div>
        {error && <div className="login-error">{error}</div>}
        <div className="modal-actions">
          <button type="button" className="btn-outline" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn">Register</button>
        </div>
      </form>
    </Modal>
  );
}

export default Sources;
