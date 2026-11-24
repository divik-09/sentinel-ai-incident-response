const API = '';
let dashboardState = { scenarios: [], incidents: [], selectedId: null, selectedDetail: null, incidentFilter: 'all', config: null, me: null };

const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value = '') => String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
const formatTime = (value) => value ? new Date(value).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—';
const titleCase = (value = '') => value.replaceAll('_', ' ').replace(/\b\w/g, (char) => char.toUpperCase());
const severityGlyph = (severity) => ({ critical: '!', high: '↗', medium: '◈', low: '·' }[severity] || '◈');
const scenarioGlyph = (id) => ({ 'payment-pool-exhaustion': '▤', 'inventory-dependency-latency': '⇄', 'orders-schema-mismatch': '⌘', 'catalog-cache-stampede': '◌', 'auth-memory-pressure': '▧' }[id] || '◈');
const showToast = (message, kind = '') => {
  const toast = document.createElement('div');
  toast.className = `toast ${kind}`;
  toast.textContent = message;
  $('#toast-region').appendChild(toast);
  setTimeout(() => toast.remove(), 3600);
};

const KEY_STORAGE = 'sentinel_api_key';
const getKey = () => sessionStorage.getItem(KEY_STORAGE) || '';
function promptForKey(reason) {
  const entered = window.prompt(reason || 'This Sentinel instance requires an API key.');
  if (entered && entered.trim()) { sessionStorage.setItem(KEY_STORAGE, entered.trim()); return true; }
  return false;
}

async function api(path, options = {}, retried = false) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (getKey()) headers.Authorization = `Bearer ${getKey()}`;
  const response = await fetch(`${API}${path}`, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401 && !retried) {
    sessionStorage.removeItem(KEY_STORAGE);
    if (promptForKey(getKey() ? 'API key rejected. Enter a valid key.' : 'This Sentinel instance requires an API key.')) return api(path, options, true);
  }
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
}

async function loadIdentity() {
  try {
    const [config, me] = await Promise.all([fetch('/api/config').then((r) => r.json()), api('/api/me')]);
    dashboardState.config = config;
    dashboardState.me = me;
    const initials = me.name.split(/[^a-zA-Z0-9]+/).filter(Boolean).slice(0, 2).map((p) => p[0].toUpperCase()).join('') || 'U';
    document.querySelectorAll('.avatar, .top-avatar').forEach((el) => { el.textContent = initials; el.title = `${me.name} (${me.role})`; });
    const chip = document.querySelector('.user-chip span b'); if (chip) chip.textContent = me.name;
    const small = document.querySelector('.user-chip span small'); if (small) small.textContent = `${me.role} · auth ${config.auth_mode === 'api_key' ? 'on' : 'OFF'}`;
    const pill = document.querySelector('.env-pill'); if (pill) pill.innerHTML = `<i></i> ${escapeHtml(config.environment.toUpperCase())}${config.auth_mode === 'api_key' ? '' : ' · AUTH OFF'}`;
  } catch (error) { /* surfaced by loadDashboard */ }
}

async function loadDashboard() {
  try {
    const data = await api('/api/dashboard');
    dashboardState.scenarios = data.scenarios || [];
    dashboardState.incidents = data.incidents || [];
    $('#stat-total').textContent = data.counts.total_incidents;
    $('#stat-open').textContent = data.counts.open_incidents;
    $('#stat-critical').textContent = data.counts.critical_open;
    $('#stat-approval').textContent = data.counts.awaiting_approval;
    $('#nav-open-count').textContent = data.counts.open_incidents;
    const degradedServices = (data.demo_services || []).filter((service) => service.status === 'degraded');
    $('#system-status-text').textContent = degradedServices.length ? `${degradedServices.length} service${degradedServices.length === 1 ? '' : 's'} degraded` : 'All services operational';
    $('#system-status-dot').classList.toggle('degraded', degradedServices.length > 0);
    $('#incident-list-count').textContent = `${dashboardState.incidents.length} incidents`;
    $('#queue-updated').textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    renderScenarios();
    renderIncidentList();
    if (dashboardState.selectedId) {
      const exists = dashboardState.incidents.some((incident) => incident.id === dashboardState.selectedId);
      if (exists) await selectIncident(dashboardState.selectedId, false);
      else clearSelection();
    }
  } catch (error) {
    showToast(`Could not load dashboard: ${error.message}`, 'error');
  }
}

function renderScenarios() {
  const container = $('#scenario-grid');
  container.innerHTML = dashboardState.scenarios.map((scenario) => `
    <button class="scenario-card" data-scenario="${escapeHtml(scenario.id)}" style="--scenario-color:${scenario.severity === 'critical' ? '#ff858b' : scenario.severity === 'high' ? '#f0bd75' : '#83a6ff'}">
      <div class="scenario-top"><span class="scenario-glyph">${scenarioGlyph(scenario.id)}</span><span class="severity ${escapeHtml(scenario.severity)}">${escapeHtml(scenario.severity)}</span></div>
      <b>${escapeHtml(scenario.title.split(':')[0])}</b>
      <p>${escapeHtml(scenario.summary)}</p>
      <div class="scenario-action"><span>INJECT FAILURE</span><span>→</span></div>
    </button>`).join('');
}

function renderIncidentList() {
  const container = $('#incident-list');
  if (!dashboardState.incidents.length) {
    container.innerHTML = '<div class="empty-state compact"><span class="empty-icon">◉</span><b>No incidents yet</b><p>Launch a scenario above to create your first incident.</p></div>';
    return;
  }
  const visibleIncidents = dashboardState.incidents.filter((incident) => {
    if (dashboardState.incidentFilter === 'open') return !['resolved', 'simulated', 'rejected'].includes(incident.status);
    if (dashboardState.incidentFilter === 'resolved') return ['resolved', 'simulated', 'rejected'].includes(incident.status);
    return true;
  });
  $('#incident-list-count').textContent = `${visibleIncidents.length} incidents`;
  if (!visibleIncidents.length) {
    container.innerHTML = '<div class="empty-state compact"><span class="empty-icon">◉</span><b>No matching incidents</b><p>Try another queue filter.</p></div>';
    return;
  }
  container.innerHTML = visibleIncidents.map((incident) => `
    <div class="incident-row ${dashboardState.selectedId === incident.id ? 'selected' : ''}" data-incident="${escapeHtml(incident.id)}" role="button" tabindex="0">
      <span class="incident-severity ${escapeHtml(incident.severity)}"></span>
      <div class="incident-row-main"><div class="incident-row-title">${escapeHtml(incident.title)}</div><div class="incident-row-meta"><span>${escapeHtml(incident.service)}</span><span>·</span><span>${formatTime(incident.created_at)}</span></div></div>
      <span class="row-status ${escapeHtml(incident.status)}">${escapeHtml(titleCase(incident.status))}</span>
    </div>`).join('');
}

async function createIncident(scenarioId) {
  try {
    const incident = await api('/api/incidents', { method: 'POST', body: JSON.stringify({ scenario_id: scenarioId }) });
    dashboardState.selectedId = incident.id;
    showToast('Scenario injected. Incident created.', 'success');
    await loadIdentity().then(loadDashboard);
    await selectIncident(incident.id);
  } catch (error) {
    showToast(`Could not create incident: ${error.message}`, 'error');
  }
}

async function selectIncident(id, render = true) {
  dashboardState.selectedId = id;
  if (render) renderIncidentList();
  try {
    dashboardState.selectedDetail = await api(`/api/incidents/${id}`);
    renderDetail(dashboardState.selectedDetail);
    renderIncidentList();
    verifyAudit();
  } catch (error) {
    showToast(`Could not load incident: ${error.message}`, 'error');
  }
}

async function verifyAudit() {
  const el = $('#audit-verify');
  if (!el) return;
  try {
    const result = await api('/api/audit/verify');
    el.textContent = result.valid ? `CHAIN VERIFIED · ${result.checked} EVENTS` : `CHAIN BROKEN AT EVENT ${result.first_invalid_event_id}`;
    el.style.color = result.valid ? '' : '#ff858b';
  } catch (error) { el.textContent = 'VERIFICATION UNAVAILABLE'; }
}

function clearSelection() {
  dashboardState.selectedId = null;
  dashboardState.selectedDetail = null;
  $('#detail-placeholder').classList.remove('hidden');
  $('#detail-content').classList.add('hidden');
  renderIncidentList();
}

function evidenceDescription(item) {
  if (item.kind === 'metric') return `${item.name}: ${item.value}${item.unit === 'ratio' ? ` (${(Number(item.value) * 100).toFixed(1)}%)` : ` ${item.unit || ''}`} · threshold ${item.threshold ?? '—'}`;
  if (item.kind === 'log') return `[${item.level}] ${item.code}: ${item.message}`;
  if (item.kind === 'trace') return `${item.operation} · ${item.duration_ms} ms · ${item.status}`;
  return `${item.version} · ${item.changes}`;
}

function renderDetail(data) {
  const { incident, telemetry = [], agent_run: agentRun, remediation, audit_events: auditEvents = [] } = data;
  $('#detail-placeholder').classList.add('hidden');
  const root = $('#detail-content');
  root.classList.remove('hidden');
  const diagnosis = incident.diagnosis || agentRun?.diagnosis;
  const evidence = diagnosis?.evidence || [];
  const tools = agentRun?.trace?.filter((step) => step.type === 'tool_call') || [];
  const runbooks = diagnosis?.runbooks || [];
  const proposal = remediation?.proposal || diagnosis?.remediation_proposal;
  const statusMessage = incident.status === 'awaiting_approval' ? 'Diagnosis complete. Review the evidence and approve or reject the proposed sandbox action.'
    : ['resolved', 'simulated'].includes(incident.status) ? 'The approved remediation passed its sandbox simulation. No production system was changed.'
    : incident.status === 'rejected' ? 'The remediation proposal was rejected. No system changes were made.'
    : incident.status === 'rolled_back' ? 'The simulated change was rolled back and the previous sandbox configuration restored.'
    : incident.status === 'diagnosed' ? 'Sentinel abstained: the available evidence was not strong or independent enough for a root-cause claim. No remediation can be approved.'
    : incident.status === 'investigating' ? 'The investigation workflow is running.'
    : 'Incident detected. Run the investigation to collect evidence and identify a likely cause.';
  const bannerClass = incident.status === 'awaiting_approval' ? 'waiting' : ['resolved', 'simulated'].includes(incident.status) ? 'resolved' : '';
  const evidenceHtml = evidence.length ? evidence.map((item) => `
    <div class="evidence-item"><span class="evidence-kind">${escapeHtml(item.kind)} · ${escapeHtml(item.service)}</span><p>${escapeHtml(evidenceDescription(item))}</p><span class="evidence-id">${escapeHtml(item.evidence_id)}</span></div>`).join('') : '<div class="evidence-item"><span class="evidence-kind">NO EVIDENCE CITED</span><p>Run the investigation to collect telemetry and build an evidence-backed diagnosis.</p></div>';
  const signals = diagnosis?.signals?.length ? `<ul class="signal-list">${diagnosis.signals.map((signal) => `<li>${escapeHtml(signal)}</li>`).join('')}</ul>` : '';
  const abstained = diagnosis && diagnosis.root_cause === 'unknown';
  const score = diagnosis?.confidence;
  const missing = diagnosis?.missing_signals?.length ? `<p class="diagnosis-summary"><b>${abstained ? 'To reach a diagnosis, collect:' : 'Not yet corroborated:'}</b> ${escapeHtml(diagnosis.missing_signals.join('; '))}</p>` : '';
  const warnings = (diagnosis?.warnings || []).map((w) => `<div class="status-banner"><span class="status-dot"></span>${escapeHtml(w.message)}</div>`).join('');
  const alternatives = (diagnosis?.alternative_hypotheses || []).length ? `<p class="diagnosis-summary"><b>Other hypotheses considered:</b> ${diagnosis.alternative_hypotheses.map((a) => `${escapeHtml(titleCase(a.root_cause))} (${Math.round((a.evidence_score || 0) * 100)}%)`).join(', ')}</p>` : '';
  const diagnosisHtml = diagnosis ? `
    <div class="diagnosis-card">
      <div class="diagnosis-top"><div><div class="eyebrow">${abstained ? 'NO DIAGNOSIS · ' + escapeHtml(titleCase(diagnosis.abstain_reason || 'insufficient_evidence')) : 'LIKELY ROOT CAUSE'}</div><div class="diagnosis-label">${escapeHtml(diagnosis.label || titleCase(diagnosis.root_cause))}</div></div><div class="confidence"><strong>${score == null ? '—' : Math.round(score * 100) + '%'}</strong><small title="Matched signal weight, not a calibrated probability">EVIDENCE SCORE</small></div></div>
      <div class="confidence-bar"><span style="width:${score == null ? 0 : Math.round(score * 100)}%"></span></div>
      <p class="diagnosis-summary">${escapeHtml(incident.impact || diagnosis.impact || 'Impact not quantified.')}</p>${signals}${missing}${alternatives}
      ${diagnosis.model_review ? `<p class="diagnosis-summary"><b>Optional model review:</b> ${escapeHtml(diagnosis.model_review.review)} <span class="evidence-id">Advisory only · ${escapeHtml(diagnosis.model_review.model || 'configured model')}</span></p>` : ''}
    </div>${warnings}` : '';
  const toolHtml = tools.length ? `<div class="tool-list">${tools.map((step) => `<div class="tool-row"><span class="tool-check">✓</span><span class="tool-name">${escapeHtml(step.tool)}</span><span class="tool-desc">${escapeHtml(step.result_count ?? '—')} records · ${escapeHtml(step.duration_ms ?? 0)} ms</span></div>`).join('')}</div>` : '<div class="evidence-item"><p>No agent trace yet. Start an investigation to see each diagnostic tool call.</p></div>';
  const runbookHtml = runbooks.length ? runbooks.map((book) => `<div class="evidence-item"><span class="evidence-kind">RUNBOOK · SCORE ${Math.round((book.retrieval_score || 0) * 100)}%</span><p><b>${escapeHtml(book.title)}</b></p><p>${escapeHtml((book.steps || []).slice(0, 2).join(' '))}</p></div>`).join('') : '';
  let proposalHtml = '';
  if (proposal) {
    const policyInfo = proposal.policy ? `<div class="approval-note" style="margin:8px 0">Policy ${escapeHtml(proposal.policy.policy_version || '')}: <b>${proposal.policy.allowed ? 'allowed' : 'blocked'}</b>${(proposal.policy.violations || []).length ? ' — ' + escapeHtml(proposal.policy.violations.join('; ')) : ''}${(proposal.policy.warnings || []).length ? ' · ' + escapeHtml(proposal.policy.warnings.join('; ')) : ''}</div>` : '';
    const canDecide = remediation?.status === 'proposed' && incident.status === 'awaiting_approval';
    const canRollback = remediation?.status === 'executed_in_sandbox';
    const actionButtons = canDecide ? `
      <div class="proposal-actions"><span class="approval-note">Human approval required before sandbox execution.</span><div><button class="mini-button danger" data-action="reject">Reject</button> <button class="mini-button primary" data-action="approve" ${proposal.policy && !proposal.policy.allowed ? 'disabled title="Blocked by policy"' : ''}>Approve & simulate</button></div></div>`
      : `<div class="proposal-actions"><span class="approval-note">Status: ${escapeHtml(titleCase(remediation?.status || 'proposed'))}${remediation?.approved_by ? ' · by ' + escapeHtml(remediation.approved_by) : ''}</span>${canRollback ? '<button class="mini-button danger" data-action="rollback">Roll back simulation</button>' : ''}<span class="risk-pill ${escapeHtml(proposal.risk || 'medium')}">${escapeHtml(proposal.risk || 'medium')} risk</span></div>`;
    proposalHtml = `<div class="proposal-card"><div class="proposal-heading"><span class="proposal-icon">⚒</span><div><b>${escapeHtml(proposal.title)}</b><small>${escapeHtml(proposal.execution_mode || 'Proposed action')} · ${escapeHtml(proposal.action)}</small></div><span class="risk-pill ${escapeHtml(proposal.risk || 'medium')}">${escapeHtml(proposal.risk || 'medium')}</span></div><p class="proposal-description">${escapeHtml(proposal.description)}</p><div class="proposal-change">${escapeHtml(proposal.change)}</div>${policyInfo}<div class="proposal-lists"><div><b>Validation plan</b><ul>${(proposal.tests || []).map((test) => `<li>${escapeHtml(test)}</li>`).join('')}</ul></div><div><b>Rollback plan</b><ul><li>${escapeHtml(proposal.rollback || 'No action has been taken.')}</li></ul></div></div>${actionButtons}</div>`;
  }
  const runInvestigationButton = !diagnosis && incident.status !== 'investigating' ? '<button class="mini-button primary" data-action="investigate">▶ Run investigation</button>' : '';
  const auditHtml = auditEvents.length ? `<div class="audit-list">${auditEvents.map((event) => `<div class="audit-row"><span class="audit-mark">●</span><span><b>${escapeHtml(event.action)}</b> · ${escapeHtml(event.actor)} · ${formatTime(event.created_at)}</span></div>`).join('')}</div>` : '';
  root.innerHTML = `
    <div class="detail-header"><div class="detail-title-wrap"><div class="eyebrow">INCIDENT ${escapeHtml(incident.id.slice(0, 8).toUpperCase())}</div><div class="detail-title">${escapeHtml(incident.title)}</div><div class="detail-meta"><span class="severity ${escapeHtml(incident.severity)}">${escapeHtml(incident.severity)}</span><span>·</span><span>${escapeHtml(incident.service)}</span><span>·</span><span>${formatTime(incident.created_at)}</span></div></div><div class="detail-actions">${runInvestigationButton}<button class="mini-button" data-action="refresh-detail">↻ Refresh</button></div></div>
    <div class="status-banner ${bannerClass}"><span class="status-dot"></span>${escapeHtml(statusMessage)}</div>
    ${diagnosisHtml}
    <div class="subsection"><div class="subsection-heading"><b>Evidence collected</b><span>${evidence.length} CITED / ${telemetry.length} TOTAL RECORDS</span></div><div class="evidence-grid">${evidenceHtml}</div></div>
    <div class="subsection"><div class="subsection-heading"><b>Agent execution trace</b><span>${tools.length} TOOL CALLS</span></div>${toolHtml}</div>
    ${proposalHtml ? `<div class="subsection"><div class="subsection-heading"><b>Remediation proposal</b><span>HUMAN-IN-THE-LOOP</span></div>${proposalHtml}</div>` : ''}
    ${runbookHtml ? `<div class="subsection"><div class="subsection-heading"><b>Retrieved runbooks</b><span>${runbooks.length} MATCHES</span></div><div class="evidence-grid">${runbookHtml}</div></div>` : ''}
    ${auditHtml ? `<div class="subsection"><div class="subsection-heading"><b>Audit trail</b><span id="audit-verify">HASH-CHAINED EVENT HISTORY</span></div>${auditHtml}</div>` : ''}
    ${incident.status === 'detected' ? '<div class="empty-state"><p>Diagnostic tools have read-only access. Remediation remains disabled until a human reviews the proposal.</p></div>' : ''}`;
}

async function investigateSelected() {
  const id = dashboardState.selectedId;
  if (!id) return;
  const button = $('[data-action="investigate"]');
  if (button) { button.disabled = true; button.textContent = 'Investigating…'; }
  try {
    await api(`/api/incidents/${id}/investigate`, { method: 'POST', body: '{}' });
    showToast('Investigation completed. Review the diagnosis and cited evidence.', 'success');
    await loadIdentity().then(loadDashboard);
    await selectIncident(id);
  } catch (error) {
    showToast(`Investigation failed: ${error.message}`, 'error');
    await selectIncident(id);
  }
}

async function approveSelected() {
  const data = dashboardState.selectedDetail;
  if (!data?.remediation) return;
  try {
    await api(`/api/incidents/${data.incident.id}/remediations/${data.remediation.id}/approve`, {
      method: 'POST', body: JSON.stringify({ note: 'Reviewed diagnosis, evidence and policy result; approved sandbox simulation.' }),
    });
    showToast('Approved. Sandbox simulation completed; production was not changed.', 'success');
    await loadIdentity().then(loadDashboard);
    await selectIncident(data.incident.id);
  } catch (error) { showToast(`Approval failed: ${error.message}`, 'error'); }
}

async function rejectSelected() {
  const data = dashboardState.selectedDetail;
  if (!data?.remediation) return;
  try {
    await api(`/api/incidents/${data.incident.id}/remediations/${data.remediation.id}/reject`, {
      method: 'POST', body: JSON.stringify({ note: 'Operator rejected the proposed action.' }),
    });
    showToast('Proposal rejected. No action was executed.', 'success');
    await loadIdentity().then(loadDashboard);
    await selectIncident(data.incident.id);
  } catch (error) { showToast(`Rejection failed: ${error.message}`, 'error'); }
}

async function rollbackSelected() {
  const data = dashboardState.selectedDetail;
  if (!data?.remediation) return;
  try {
    await api(`/api/incidents/${data.incident.id}/remediations/${data.remediation.id}/rollback`, { method: 'POST', body: JSON.stringify({ note: 'Operator rolled back the simulated change.' }) });
    showToast('Simulation rolled back. Previous sandbox configuration restored.', 'success');
    await loadIdentity().then(loadDashboard);
    await selectIncident(data.incident.id);
  } catch (error) { showToast(`Rollback failed: ${error.message}`, 'error'); }
}

async function runEvaluation() {
  const buttons = [$('#run-evaluation'), $('#run-evaluation-top')].filter(Boolean);
  buttons.forEach((button) => { button.disabled = true; button.textContent = 'Running…'; });
  try {
    const result = await api('/api/evaluations/run', { method: 'POST', body: JSON.stringify({ split: 'all' }) });
    const container = $('#evaluation-result');
    container.classList.add('has-results');
    const pct = (v) => (v == null ? '—' : `${(v * 100).toFixed(0)}%`);
    const splitRows = Object.entries(result.by_split || {}).map(([name, m]) => `<div class="eval-case"><b>${escapeHtml(name)}</b><span>${m.correct} / ${m.total_cases} correct · wrong diagnoses ${pct(m.wrong_diagnosis_rate)}</span></div>`).join('');
    const failures = result.cases.filter((item) => !item.passed);
    const failureRows = failures.length ? failures.map((item) => `<div class="eval-case failed"><b>${escapeHtml(item.scenario_id)}</b><span>× expected ${escapeHtml(item.expected)} → ${escapeHtml(item.predicted)}${item.abstain_reason ? ' (' + escapeHtml(item.abstain_reason) + ')' : ''}</span></div>`).join('') : '<div class="eval-case"><b>No failing cases</b><span>on these author-written sets</span></div>';
    container.innerHTML = `<div class="eval-summary"><div class="eval-score"><strong>${pct(result.accuracy)}</strong><div><b>${result.correct} / ${result.total_cases} cases · wrong-diagnosis rate ${pct(result.wrong_diagnosis_rate)} · coverage ${pct(result.coverage)}</b><small>Ruleset ${escapeHtml(result.ruleset_version)} · dataset ${escapeHtml(result.dataset_fingerprint)} · ECE ${result.expected_calibration_error ?? '—'} · run ${escapeHtml(result.run_id.slice(0, 8))}</small></div></div><span class="synthetic-note">SYNTHETIC · AUTHOR-WRITTEN</span></div><div class="eval-case-grid">${splitRows}${failureRows}</div><p class="approval-note" style="margin-top:10px">${escapeHtml(result.note)}</p>`;
    showToast(`Evaluation complete: ${result.correct}/${result.total_cases} matched expected labels.`, failures.length ? '' : 'success');
  } catch (error) { showToast(`Evaluation failed: ${error.message}`, 'error'); }
  finally { buttons.forEach((button) => { button.disabled = false; button.textContent = button.id === 'run-evaluation-top' ? '▥ Run evaluation' : 'Run benchmark ↗'; }); }
}

document.addEventListener('click', async (event) => {
  const scenario = event.target.closest('[data-scenario]');
  if (scenario) return createIncident(scenario.dataset.scenario);
  const incident = event.target.closest('[data-incident]');
  if (incident) return selectIncident(incident.dataset.incident);
  const filter = event.target.closest('[data-filter]');
  if (filter) {
    dashboardState.incidentFilter = filter.dataset.filter;
    document.querySelectorAll('[data-filter]').forEach((button) => button.classList.toggle('active', button.dataset.filter === dashboardState.incidentFilter));
    return renderIncidentList();
  }
  const action = event.target.closest('[data-action]')?.dataset.action;
  if (action === 'investigate') return investigateSelected();
  if (action === 'refresh-detail') return selectIncident(dashboardState.selectedId);
  if (action === 'approve') return approveSelected();
  if (action === 'reject') return rejectSelected();
  if (action === 'rollback') return rollbackSelected();
  if (action === 'reset-services') {
    try {
      await api('/api/demo/reset', { method: 'POST', body: '{}' });
      showToast('Demo service faults reset.', 'success');
      return loadIdentity().then(loadDashboard);
    } catch (error) { return showToast(`Could not reset services: ${error.message}`, 'error'); }
  }
});
document.addEventListener('keydown', (event) => {
  const row = event.target.closest('.incident-row');
  if (row && (event.key === 'Enter' || event.key === ' ')) { event.preventDefault(); selectIncident(row.dataset.incident); }
});
$('#refresh-button').addEventListener('click', loadDashboard);
$('#clear-selection').addEventListener('click', clearSelection);
$('#run-evaluation').addEventListener('click', runEvaluation);
$('#run-evaluation-top').addEventListener('click', runEvaluation);

$('#page-date').textContent = new Date().toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' }).toUpperCase();
loadIdentity().then(loadDashboard);
