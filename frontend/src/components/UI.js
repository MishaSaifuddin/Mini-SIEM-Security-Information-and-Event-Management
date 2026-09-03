import React from 'react';

export function KpiCard({ icon, label, value, color = 'blue' }) {
  return (
    <div className="kpi-card">
      <div className={`kpi-icon ${color}`}>{icon}</div>
      <div>
        <div className="kpi-label">{label}</div>
        <div className="kpi-value">{value}</div>
      </div>
    </div>
  );
}

export function Badge({ severity, className = '', children }) {
  const sevClass = severity ? `badge-${severity.toLowerCase()}` : '';
  return <span className={`badge ${sevClass} ${className}`}>{children || severity}</span>;
}

export function StatusBadge({ status }) {
  const map = {
    open: 'badge-open',
    'in_progress': 'badge-in-progress',
    'in-progress': 'badge-in-progress',
    resolved: 'badge-resolved',
    false_positive: 'badge-false_positive',
    'false-positive': 'badge-false_positive',
    closed: 'badge-closed',
  };
  const cls = map[status] || 'badge-info';
  return <span className={`badge ${cls}`}>{status.replace('_', ' ')}</span>;
}

export function Loading({ text = 'Loading...' }) {
  return (
    <div className="loading">
      <div className="spinner" />
      <p>{text}</p>
    </div>
  );
}

export function Empty({ message = 'No data available' }) {
  return <div className="empty">{message}</div>;
}

export function Modal({ title, onClose, children, width = 500 }) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" style={{ width }} onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>{title}</h2>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function Card({ title, children, action }) {
  return (
    <div className="card">
      {title && (
        <div className="card-title">
          <span>{title}</span>
          {action}
        </div>
      )}
      {children}
    </div>
  );
}

export function formatTime(timestamp) {
  if (!timestamp) return '-';
  const dt = new Date(timestamp);
  if (isNaN(dt.getTime())) return timestamp;
  return dt.toLocaleString();
}

export function timeAgo(timestamp) {
  if (!timestamp) return '-';
  const seconds = Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function truncate(str, max = 60) {
  if (!str) return '';
  if (str.length <= max) return str;
  return str.substring(0, max) + '...';
}
