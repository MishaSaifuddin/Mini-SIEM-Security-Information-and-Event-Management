import React, { useState, useEffect } from 'react';
import { ruleService } from '../services';
import { Badge, Loading, Empty, Card, Modal } from '../components/UI';

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function Rules() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [showSigma, setShowSigma] = useState(false);
  const [testResult, setTestResult] = useState(null);

  useEffect(() => {
    loadRules();
  }, []);

  const loadRules = async () => {
    setLoading(true);
    try {
      const res = await ruleService.getRules();
      setRules(res.data.sort((a, b) =>
        (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
      ));
    } catch (e) {
    } finally {
      setLoading(false);
    }
  };

  const toggleRule = async (rule) => {
    try {
      await ruleService.updateRule(rule.id, { enabled: !rule.enabled });
      loadRules();
    } catch (e) {}
  };

  const deleteRule = async (rule) => {
    if (!window.confirm(`Delete rule "${rule.name}"?`)) return;
    try {
      await ruleService.deleteRule(rule.id);
      loadRules();
    } catch (e) {}
  };

  const testRule = async (data) => {
    try {
      const res = await ruleService.testRule(data);
      setTestResult(res.data);
    } catch (e) {}
  };

  return (
    <div>
      <div className="filter-bar" style={{ justifyContent: 'flex-end' }}>
        <button className="btn-outline" onClick={() => setShowSigma(true)}>Import Sigma Rule</button>
        <button className="btn" onClick={() => setShowCreate(true)}>+ New Rule</button>
      </div>

      {/* Count */}
      <Card>
        <div className="card-title">
          <span>
            Detection Rules
            <span style={{ color: 'var(--text-muted)', fontWeight: 'normal' }}>
              {' '}({rules.filter(r => r.enabled).length} of {rules.length} active)
            </span>
          </span>
        </div>
        {loading ? (
          <Loading text="Loading rules..." />
        ) : rules.length === 0 ? (
          <Empty message="No detection rules defined yet." />
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Rule ID</th>
                  <th>Name</th>
                  <th>Severity</th>
                  <th>Category</th>
                  <th>Threshold</th>
                  <th>Windows</th>
                  <th>MITRE</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id}>
                    <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{rule.rule_id}</td>
                    <td style={{ maxWidth: '280px' }}>{rule.name}</td>
                    <td><Badge severity={rule.severity} /></td>
                    <td>{rule.category || '-'}</td>
                    <td>{rule.threshold > 1 ? `${rule.threshold}/window` : 'Single'}</td>
                    <td>{rule.source_types?.join(', ') || 'Any'}</td>
                    <td style={{ fontSize: '12px', fontFamily: 'monospace' }}>{rule.mitre_technique || '-'}</td>
                    <td>
                      <span className={`badge ${rule.enabled ? 'badge-resolved' : 'badge-closed'}`}>
                        {rule.enabled ? 'Active' : 'Disabled'}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                        <button className="btn btn-sm btn-outline" onClick={() => testRule(rule)}>Test</button>
                        <button
                          className="btn btn-sm btn-outline"
                          onClick={() => toggleRule(rule)}
                        >
                          {rule.enabled ? 'Disable' : 'Enable'}
                        </button>
                        <button className="btn btn-sm btn-danger" onClick={() => deleteRule(rule)}>Del</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Test Result */}
      {testResult && (
        <Card title={`Test Result: ${testResult.rule_name}`} action={
          <button className="btn btn-sm btn-outline" onClick={() => setTestResult(null)}>Close</button>
        }>
          <div className={`badge ${testResult.matched ? 'badge-critical' : 'badge-resolved'}`}>
            {testResult.matched ? 'MATCHED' : 'NO MATCH'}
          </div>
          <p style={{ marginTop: '8px', color: 'var(--text-muted)', fontSize: '13px' }}>
            {testResult.details}
          </p>
          {testResult.matched_events?.length > 0 && (
            <div style={{ marginTop: '12px' }}>
              <h4 style={{ fontSize: '13px', marginBottom: '8px' }}>Matched Events:</h4>
              {testResult.matched_events.map((ev) => (
                <div key={ev.id} style={{ background: 'var(--bg)', padding: '8px 12px', borderRadius: '6px', marginBottom: '6px', fontSize: '12px' }}>
                  <b>#{ev.id}</b> {ev.timestamp && `- ${ev.timestamp}`} - {ev.description}
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      {showCreate && (
        <CreateRuleModal
          onClose={() => setShowCreate(false)}
          onSave={async (data) => {
            try {
              await ruleService.createRule(data);
              setShowCreate(false);
              loadRules();
              return true;
            } catch (e) {
              return false;
            }
          }}
        />
      )}

      {showSigma && (
        <SigmaImportModal
          onClose={() => setShowSigma(false)}
          onSave={async (data) => {
            try {
              await ruleService.importSigma(data);
              setShowSigma(false);
              loadRules();
              return true;
            } catch (e) {
              return false;
            }
          }}
        />
      )}
    </div>
  );
}

function CreateRuleModal({ onClose, onSave }) {
  const [form, setForm] = useState({
    name: '',
    rule_id: '',
    description: '',
    severity: 'medium',
    category: '',
    enabled: true,
    source_types: ['auth', 'windows', 'firewall', 'web_server'],
    event_types: [],
    conditions: { event_type: 'failed_login' },
    threshold: 1,
    time_window_seconds: 3600,
    group_by: '',
    mitre_technique: '',
    mitre_tactic: '',
  });
  const [error, setError] = useState('');

  const handleChange = (field, value) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.name || !form.rule_id) {
      setError('Name and Rule ID are required');
      return;
    }
    let conditions = form.conditions;
    if (typeof form.conditions === 'string') {
      try { conditions = JSON.parse(form.conditions); } catch { setError('Conditions must be valid JSON'); return; }
    }
    try {
      const ok = await onSave({ ...form, conditions });
      if (!ok) setError('Failed to save rule. Rule ID may already exist.');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to save rule');
    }
  };

  return (
    <Modal title="Create Detection Rule" onClose={onClose} width={600}>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>Rule Name *</label>
          <input type="text" value={form.name} onChange={(e) => handleChange('name', e.target.value)} placeholder="e.g., Multiple Failed Logins" />
        </div>
        <div className="form-group">
          <label>Rule ID *</label>
          <input type="text" value={form.rule_id} onChange={(e) => handleChange('rule_id', e.target.value)} placeholder="e.g., BRUTE-FORCE-002" />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
          <div className="form-group">
            <label>Severity</label>
            <select value={form.severity} onChange={(e) => handleChange('severity', e.target.value)}>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>
          <div className="form-group">
            <label>Category</label>
            <input type="text" value={form.category} onChange={(e) => handleChange('category', e.target.value)} placeholder="e.g., Credential Access" />
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
          <div className="form-group">
            <label>Threshold</label>
            <input type="number" value={form.threshold} onChange={(e) => handleChange('threshold', parseInt(e.target.value) || 1)} min="1" />
          </div>
          <div className="form-group">
            <label>Time Window (s)</label>
            <input type="number" value={form.time_window_seconds} onChange={(e) => handleChange('time_window_seconds', parseInt(e.target.value) || 3600)} />
          </div>
          <div className="form-group">
            <label>Group By</label>
            <input type="text" value={form.group_by} onChange={(e) => handleChange('group_by', e.target.value)} placeholder="e.g., source_ip" />
          </div>
        </div>
        <div className="form-group">
          <label>Source Types</label>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {['auth', 'windows', 'firewall', 'web_server', 'syslog', 'custom_json'].map((st) => (
              <label key={st} style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '13px' }}>
                <input
                  type="checkbox"
                  checked={form.source_types.includes(st)}
                  onChange={(e) => {
                    if (e.target.checked) handleChange('source_types', [...form.source_types, st]);
                    else handleChange('source_types', form.source_types.filter((s) => s !== st));
                  }}
                />
                {st}
              </label>
            ))}
          </div>
        </div>
        <div className="form-group">
          <label>Conditions (JSON)</label>
          <textarea
            value={typeof form.conditions === 'string' ? form.conditions : JSON.stringify(form.conditions, null, 2)}
            onChange={(e) => handleChange('conditions', e.target.value)}
            style={{ minHeight: '100px', fontFamily: 'monospace', fontSize: '12px' }}
          />
          <small style={{ color: 'var(--text-muted)', fontSize: '11px' }}>
            Example: {"{\"event_type\": \"failed_login\"}"} | Supports $or, contains, in, regex, etc.
          </small>
        </div>
        <div className="form-group">
          <label>Description</label>
          <textarea value={form.description} onChange={(e) => handleChange('description', e.target.value)} />
        </div>
        <div className="form-group">
          <label>MITRE Technique (T-code)</label>
          <input type="text" value={form.mitre_technique} onChange={(e) => handleChange('mitre_technique', e.target.value)} placeholder="e.g., T1110" />
        </div>
        {error && <div className="login-error">{error}</div>}
        <div className="modal-actions">
          <button type="button" className="btn-outline" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn">Create Rule</button>
        </div>
      </form>
    </Modal>
  );
}

function SigmaImportModal({ onClose, onSave }) {
  const [name, setName] = useState('');
  const [sigmaYaml, setSigmaYaml] = useState('');
  const [sourceTypes, setSourceTypes] = useState([]);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!sigmaYaml.trim()) {
      setError('Sigma YAML content is required');
      return;
    }
    try {
      const ok = await onSave({ name, sigma_rule: sigmaYaml, source_types: sourceTypes });
      if (!ok) setError('Failed to import Sigma rule. Check the YAML format.');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to import rule');
    }
  };

  return (
    <Modal title="Import Sigma Rule" onClose={onClose} width={700}>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>Override Name (optional)</label>
          <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="Leave blank to use rule title" />
        </div>
        <div className="form-group">
          <label>Source Types</label>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {['auth', 'windows', 'firewall', 'web_server', 'syslog'].map((st) => (
              <label key={st} style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '13px' }}>
                <input
                  type="checkbox"
                  checked={sourceTypes.includes(st)}
                  onChange={(e) => {
                    if (e.target.checked) setSourceTypes([...sourceTypes, st]);
                    else setSourceTypes(sourceTypes.filter((s) => s !== st));
                  }}
                />
                {st}
              </label>
            ))}
          </div>
        </div>
        <div className="form-group">
          <label>Sigma Rule (YAML) *</label>
          <textarea
            value={sigmaYaml}
            onChange={(e) => setSigmaYaml(e.target.value)}
            style={{ minHeight: '250px', fontFamily: 'monospace', fontSize: '12px' }}
            placeholder={`title: Suspicious PowerShell Command
id: demo-001
status: experimental
level: high
logsource:
    product: windows
detection:
    selection:
        process_name: powershell.exe
        command_line|contains: 'EncodedCommand'
    condition: selection`}
          />
        </div>
        <div id="sigma-help" style={{ marginBottom: '10px', fontSize: '12px', color: 'var(--text-muted)' }}>
          <p>Supports: selection fields, keyword matching, <code>|contains</code>, <code>|startswith</code>, <code>|endswith</code>, <code>|all</code>, <code>|re</code>, and "and/or/not" conditions.</p>
        </div>
        {error && <div className="login-error">{error}</div>}
        <div className="modal-actions">
          <button type="button" className="btn-outline" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn">Import Rule</button>
        </div>
      </form>
    </Modal>
  );
}

export default Rules;
