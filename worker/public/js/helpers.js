// =============================================================================
// helpers.js — Utility functions shared across all modules
// =============================================================================

function $(id) { return document.getElementById(id); }

function escapeHtml(str) {
	return String(str)
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}

function setStatus(el, ok, text) {
	el.textContent = text || (ok ? '200 OK' : 'ERROR');
	el.className = 'status ' + (ok ? 'ok' : 'err');
}

function setPending(el) {
	el.textContent = 'scanning...';
	el.className = 'status pending';
}

function setResult(el, text) { el.textContent = text; }

function formatBytes(bytes) {
	if (!bytes || bytes === 0) return '0 B';
	const u = ['B', 'KB', 'MB', 'GB'];
	const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), u.length - 1);
	return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + u[i];
}

function formatDuration(ms) {
	if (!ms || ms < 1000) return (ms || 0) + 'ms';
	return (ms / 1000).toFixed(2) + 's';
}

function formatDate(ts) {
	const d    = new Date(ts);
	const now  = new Date();
	const diff = now - d;
	if (diff < 60000)    return 'Just now';
	if (diff < 3600000)  return Math.floor(diff / 60000)   + 'm ago';
	if (diff < 86400000) return Math.floor(diff / 3600000)  + 'h ago';
	if (diff < 604800000) return Math.floor(diff / 86400000) + 'd ago';
	return d.toISOString().split('T')[0];
}

function riskBadge(level) {
	const s   = document.createElement('span');
	const cls = 'badge badge-' + (level || 'clean').toLowerCase();
	s.className  = cls;
	s.textContent = level || 'CLEAN';
	return s;
}

function shortHash(hash) { return hash ? hash.substring(0, 8) + '...' : ''; }

const RISK_COLORS = {
	'CRITICAL': 'var(--critical)',
	'HIGH':     'var(--high)',
	'MEDIUM':   'var(--medium)',
	'LOW':      'var(--low)',
	'CLEAN':    'var(--clean)',
};
