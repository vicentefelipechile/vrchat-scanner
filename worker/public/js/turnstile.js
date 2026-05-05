// =============================================================================
// turnstile.js — Cloudflare Turnstile setup and token management
// =============================================================================

/** Public sitekey from Cloudflare Turnstile (public by design) */
const TURNSTILE_SITEKEY = '0x4AAAAAADGqpmoCAv2qEqDD';

/** Renders the Turnstile widget once the API script loads */
let turnstileWidgetId = null;

/**
 * Called by Turnstile's onload callback (set in <script src>).
 * Renders the managed widget. With execution:'execute' the challenge
 * does NOT auto-run — it only runs when getTurnstileToken() calls
 * turnstile.execute().
 */
function onTurnstileLoad() {
	turnstileWidgetId = turnstile.render('#turnstile-container', {
		sitekey: TURNSTILE_SITEKEY,
		execution: 'execute',
		callback: function (token) { window.turnstileToken = token; },
		'expired-callback': function () { window.turnstileToken = null; },
		'error-callback':   function () { window.turnstileToken = null; },
	});
}

/**
 * Returns a valid Turnstile token, executing a challenge if needed.
 * Resolves with the token string, or rejects on failure.
 */
function getTurnstileToken() {
	return new Promise(function (resolve, reject) {
		if (window.turnstileToken) { resolve(window.turnstileToken); return; }
		if (!turnstileWidgetId) {
			reject(new Error('Turnstile not ready'));
			return;
		}
		turnstile.execute(turnstileWidgetId, {
			callback: function (token) {
				window.turnstileToken = token;
				resolve(token);
			},
			'error-callback': function () {
				reject(new Error('Turnstile challenge failed'));
			},
		});
	});
}

/** Resets the Turnstile widget and clears the cached token */
function resetTurnstile() {
	window.turnstileToken = null;
	if (turnstileWidgetId) {
		turnstile.reset(turnstileWidgetId);
	}
}
