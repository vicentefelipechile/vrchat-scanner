// =============================================================================
// router.js — History API routing and panel switching
// =============================================================================

var PANEL_PATHS = {
	'upload': '/upload',
	'history': '/history',
	'platform-stats': '/stats',
};

var PATH_TO_PANEL = {};
for (var _p in PANEL_PATHS) PATH_TO_PANEL[PANEL_PATHS[_p]] = _p;
PATH_TO_PANEL['/'] = 'upload';

var currentPanel = 'upload';

function showPanel(name) {
	currentPanel = name;
	document.querySelectorAll('.sidebar a').forEach(function (a) {
		a.classList.remove('active');
		if (a.getAttribute('data-panel') === name) a.classList.add('active');
	});
	document.querySelectorAll('.panel').forEach(function (p) { p.classList.remove('active'); });
	var t = $('panel-' + name);
	if (t) t.classList.add('active');
}

function navigate(path) {
	// Guard: block SPA navigation while an upload is in progress
	if (window.uploadInProgress) {
		if (!confirm('An upload is in progress. Leaving now will cancel it. Continue?')) return;
		window.uploadInProgress = false;
	}
	history.pushState(null, '', path);
	routePath(path);
}

function routePath(path) {
	var detailMatch = path.match(/^\/(?:detail|file)\/([0-9a-fA-F]{64})$/);
	if (detailMatch) {
		var sha256 = detailMatch[1];
		showPanel('detail');
		if (currentDetailHash !== sha256) showDetail(sha256);
		return;
	}
	var panel = PATH_TO_PANEL[path];
	if (!panel) panel = 'upload';
	showPanel(panel);
	if (panel === 'history') loadHistory();
}

// Handle browser back/forward — guard upload in progress
window.addEventListener('popstate', function () {
	if (window.uploadInProgress) {
		// Re-push current URL to cancel the back/forward action, then ask
		history.pushState(null, '', window.location.pathname);
		if (!confirm('An upload is in progress. Leaving now will cancel it. Continue?')) return;
		window.uploadInProgress = false;
	}
	routePath(window.location.pathname);
});

// Block tab close / page reload while uploading
window.addEventListener('beforeunload', function (e) {
	if (window.uploadInProgress) {
		e.preventDefault();
		e.returnValue = ''; // required for Chrome
	}
});

// Handle initial page load — deferred to DOMContentLoaded so that all
// other scripts (detail.js, history.js, etc.) are already executed and
// their globals (currentDetailHash, showDetail, loadHistory…) are defined.
window.addEventListener('DOMContentLoaded', function () {
	var path = window.location.pathname;
	if (path !== '/') {
		if (PATH_TO_PANEL[path] || /^\/(?:detail|file)\//.test(path)) {
			routePath(path);
		} else {
			history.replaceState(null, '', '/upload');
		}
	}
});

// Sidebar links use History API
document.querySelectorAll('.sidebar a').forEach(function (link) {
	link.addEventListener('click', function () {
		var panel = this.getAttribute('data-panel');
		var path = PANEL_PATHS[panel] || '/' + panel;
		navigate(path);
	});
});

// =============================================================================
// Collapsible sections
// =============================================================================

document.addEventListener('click', function (e) {
	var el = e.target.closest('.collapsible');
	if (!el) return;
	var targetId = el.getAttribute('data-target');
	var target = document.getElementById(targetId);
	if (!target) return;
	var isOpen = target.style.display !== 'none';
	target.style.display = isOpen ? 'none' : 'block';
	el.classList.toggle('open', !isOpen);
});
