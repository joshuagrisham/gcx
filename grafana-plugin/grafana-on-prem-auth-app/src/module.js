// grafana-on-prem-auth-app — minimal frontend module.
//
// This file is loaded by Grafana as the plugin's `module.js` entry point.
// It's deliberately written as a single small file with no build step —
// no React, no TypeScript, no webpack. It uses `@grafana/data` and
// `@grafana/runtime` only at runtime (Grafana resolves those imports for
// us via its plugin loader).
//
// The plugin registers an AppPlugin that, when Grafana mounts the
// `/a/grafana-on-prem-auth-app/cli` page, runs the CLI handshake:
//
//   1. Reads `callback_port`, `state`, `code_challenge`,
//      `code_challenge_method`, `org_id` from the page URL.
//   2. POSTs to the plugin backend at
//        /api/plugins/grafana-on-prem-auth-app/resources/issue
//      with `{state, callback_port, org_id, device_name,
//             code_challenge, code_challenge_method}`.
//      The user's session cookie travels automatically, so the backend
//      sees Grafana's `X-Grafana-User` etc. headers.
//   3. The backend mints a per-user SA token, stores it keyed by a
//      one-time authorization code, and returns `{code, user, email, …}`.
//   4. Redirects the browser to
//        http://127.0.0.1:<port>/callback?code=…&state=…&user=…
//      The real token NEVER appears in any URL.
//   5. The gcx CLI exchanges the code for the token via a back-channel
//      POST to /resources/exchange, presenting the PKCE code_verifier.

define(['@grafana/data', '@grafana/runtime', 'react'], function (grafanaData, grafanaRuntime, React) {
  'use strict';

  function CliAuthPage() {
    var rootRef = React.useRef(null);

    React.useEffect(function () {
      runFlow(rootRef.current);
    }, []);

    return React.createElement(
      'div',
      {
        ref: rootRef,
        style: {
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          minHeight: '60vh',
          fontFamily: 'inherit',
        },
      },
      React.createElement(
        'div',
        {
          style: {
            background: 'var(--background-secondary, #181b1f)',
            border: '1px solid var(--border-medium, #2c3239)',
            padding: '32px 40px',
            borderRadius: '8px',
            maxWidth: '520px',
            width: '100%',
            color: 'inherit',
          },
        },
        React.createElement('h2', { style: { marginTop: 0 } }, 'Signing you in to gcx…'),
        React.createElement(
          'p',
          { id: 'gcx-status', style: { color: 'var(--text-secondary, #9ba0a8)' } },
          'Contacting Grafana to issue a service-account token for you.'
        ),
        React.createElement('pre', {
          id: 'gcx-detail',
          style: {
            background: 'var(--background-canvas, #0b0c0e)',
            padding: '12px',
            borderRadius: '4px',
            whiteSpace: 'pre-wrap',
            display: 'none',
            color: '#ff7a7a',
            border: '1px solid #5a2424',
          },
        }),
        React.createElement('a', {
          id: 'gcx-manual',
          style: { display: 'none', marginTop: '16px' },
          children: 'Click here to return to the CLI manually',
        })
      )
    );
  }

  function setStatus(msg) {
    var el = document.getElementById('gcx-status');
    if (el) el.textContent = msg;
  }

  function setError(msg) {
    var el = document.getElementById('gcx-detail');
    if (el) {
      el.textContent = msg;
      el.style.display = 'block';
    }
  }

  function showManual(url) {
    var el = document.getElementById('gcx-manual');
    if (el) {
      el.href = url;
      el.textContent = 'Return to the CLI manually';
      el.style.display = 'inline-block';
    }
  }

  function runFlow() {
    var params = new URLSearchParams(window.location.search);
    var callbackPort = params.get('callback_port');
    var state = params.get('state');
    var codeChallenge = params.get('code_challenge');
    var codeChallengeMethod = params.get('code_challenge_method') || 'S256';
    var orgID = params.get('org_id') || '';
    var deviceName = params.get('device_name') || '';

    if (!callbackPort || !state) {
      setStatus('Missing callback parameters.');
      setError('Expected ?callback_port=…&state=…');
      return;
    }

    if (!codeChallenge) {
      setStatus('Missing PKCE code_challenge.');
      setError('Your gcx version may be outdated. Expected ?code_challenge=…&code_challenge_method=S256');
      return;
    }

    var body = {
      state: state,
      callback_port: parseInt(callbackPort, 10),
      org_id: orgID ? parseInt(orgID, 10) : 0,
      device_name: deviceName,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
    };

    grafanaRuntime
      .getBackendSrv()
      .post('/api/plugins/grafana-on-prem-auth-app/resources/issue', body)
      .then(function (resp) {
        if (!resp || !resp.code) {
          setStatus('Plugin did not return an authorization code.');
          setError(JSON.stringify(resp || {}, null, 2));
          return;
        }
        // Redirect with the one-time code — NOT the token.
        var u = new URL('http://127.0.0.1:' + callbackPort + '/callback');
        u.searchParams.set('code', resp.code);
        u.searchParams.set('state', state);
        if (resp.user) u.searchParams.set('user', resp.user);
        if (resp.email) u.searchParams.set('email', resp.email);
        if (resp.org_id) u.searchParams.set('org_id', String(resp.org_id));
        if (resp.org_name) u.searchParams.set('org_name', resp.org_name);

        setStatus('Returning you to the CLI…');
        showManual(u.toString());
        window.location.replace(u.toString());
      })
      .catch(function (err) {
        setStatus('Sign-in failed.');
        var msg = (err && err.data && (err.data.message || err.data.error)) || (err && err.message) || String(err);
        setError(msg);

        if (callbackPort && state) {
          var u = new URL('http://127.0.0.1:' + callbackPort + '/callback');
          u.searchParams.set('error', msg);
          u.searchParams.set('state', state);
          showManual(u.toString());
        }
      });
  }

  var AppPlugin = grafanaData.AppPlugin;
  var plugin = new AppPlugin().setRootPage(CliAuthPage);

  return { plugin: plugin };
});
