import React, { useState, useEffect } from 'react';
import { eventService } from '../services';
import { Badge, Loading, Empty, Card, formatTime } from '../components/UI';

function Events() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({
    search: '',
    source_type: '',
    event_type: '',
    severity: '',
    hostname: '',
    limit: 100,
  });
  const [selected, setSelected] = useState(null);
  const [eventTypes, setEventTypes] = useState([]);

  useEffect(() => {
    loadEvents();
  }, [filters]);

  const loadEvents = async () => {
    setLoading(true);
    try {
      const params = { ...filters };
      Object.keys(params).forEach((k) => {
        if (!params[k]) delete params[k];
      });
      const res = await eventService.getEvents(params);
      setEvents(res.data);
    } catch (e) {
      // handled by interceptor
    } finally {
      setLoading(false);
    }
  };

  const handleFilterChange = (key, value) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
  };

  const clearFilters = () => {
    setFilters({ search: '', source_type: '', event_type: '', severity: '', hostname: '', limit: 100 });
  };

  return (
    <div>
      {/* Filters */}
      <div className="filter-bar">
        <input
          type="text"
          placeholder="Search description, raw data..."
          value={filters.search}
          onChange={(e) => handleFilterChange('search', e.target.value)}
          style={{ flex: 1, minWidth: '200px' }}
        />
        <select value={filters.source_type} onChange={(e) => handleFilterChange('source_type', e.target.value)}>
          <option value="">All Sources</option>
          <option value="auth">Auth</option>
          <option value="windows">Windows</option>
          <option value="firewall">Firewall</option>
          <option value="web_server">Web Server</option>
          <option value="syslog">Syslog</option>
          <option value="custom_json">Custom JSON</option>
        </select>
        <select value={filters.severity} onChange={(e) => handleFilterChange('severity', e.target.value)}>
          <option value="">All Severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <input
          type="text"
          placeholder="Hostname"
          value={filters.hostname}
          onChange={(e) => handleFilterChange('hostname', e.target.value)}
          style={{ width: '150px' }}
        />
        <button className="btn-outline" onClick={clearFilters}>Clear</button>
        <button className="btn" onClick={loadEvents}>Refresh</button>
      </div>

      {/* Events Table */}
      <Card>
        {loading ? (
          <Loading text="Loading events..." />
        ) : events.length === 0 ? (
          <Empty message="No events match your filters. Try ingesting logs via the API or agent." />
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source</th>
                  <th>Type</th>
                  <th>Severity</th>
                  <th>Description</th>
                  <th>Host</th>
                  <th>User</th>
                  <th>IP</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev) => (
                  <tr key={ev.id} onClick={() => setSelected(ev)} style={{ cursor: 'pointer' }}>
                    <td>{formatTime(ev.timestamp)}</td>
                    <td>{ev.source_name || ev.source_type || '-'}</td>
                    <td>{ev.event_type || '-'}</td>
                    <td><Badge severity={ev.severity} /></td>
                    <td style={{ maxWidth: '350px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {ev.description || ev.raw_data || '-'}
                    </td>
                    <td>{ev.hostname || '-'}</td>
                    <td>{ev.user || '-'}</td>
                    <td>{ev.ip_address || ev.source_ip || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Event Details Modal */}
      {selected && (
        <EventDetail event={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

function EventDetail({ event, onClose }) {
  const extraFields = [
    ['Event ID', event.event_id],
    ['Source Name', event.source_name],
    ['Source Type', event.source_type],
    ['Hostname', event.hostname],
    ['IP Address', event.ip_address],
    ['Source IP', event.source_ip],
    ['Destination IP', event.destination_ip],
    ['Destination Port', event.destination_port],
    ['Process', event.process_name],
    ['Process ID', event.process_id],
    ['File Path', event.file_path],
    ['Command Line', event.command_line],
    ['Response Code', event.response_code],
    ['User', event.user],
  ].filter(([, v]) => v);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ width: 650 }} onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Event #{event.id}</h2>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        <div className="modal-actions" style={{ marginTop: 0, marginBottom: 16 }}>
          <Badge severity={event.severity} />
          <Badge className="badge-info">{event.event_type}</Badge>
        </div>
        <div className="detail-row">
          <div className="detail-label">Timestamp</div>
          <div className="detail-value">{formatTime(event.timestamp)}</div>
        </div>
        {extraFields.map(([label, value]) => (
          <div className="detail-row" key={label}>
            <div className="detail-label">{label}</div>
            <div className="detail-value" style={{ maxHeight: '60px', overflow: 'auto' }}>{value}</div>
          </div>
        ))}
        <div className="detail-row">
          <div className="detail-label">Description</div>
          <div className="detail-value">{event.description}</div>
        </div>
        {event.raw_data && (
          <div className="detail-row">
            <div className="detail-label">Raw Data</div>
            <div className="detail-value">
              <pre style={{ background: 'var(--bg)', padding: '12px', borderRadius: '6px', fontSize: '12px', overflowX: 'auto' }}>
                {event.raw_data}
              </pre>
            </div>
          </div>
        )}
        {event.extra_data && Object.keys(event.extra_data).length > 0 && (
          <div className="detail-row">
            <div className="detail-label">Extra Data</div>
            <div className="detail-value">
              <pre style={{ background: 'var(--bg)', padding: '12px', borderRadius: '6px', fontSize: '12px', overflowX: 'auto' }}>
                {JSON.stringify(event.extra_data, null, 2)}
              </pre>
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

export default Events;
