# gcx-auth-app — Grafana plugin for browser-based gcx login

This plugin is the server-side counterpart to `gcx auth login`. It makes
`gcx auth login` work like `gh auth login` does for GitHub: you sign in
once in your browser through whatever auth provider your Grafana already
uses (OAuth, SAML, LDAP, basic…), and gcx receives a real Grafana service
account token bound to your identity. No per-user admin chores. No
service-account creation rights required of end users.

## How it works

1. `gcx auth login --server https://grafana.example.com` opens your browser
   to `https://grafana.example.com/a/gcx-auth-app/cli?callback_port=…&state=…`.
2. The page is served by this plugin. Grafana auth-gates it; if you're not
   already signed in, you go through your normal Grafana login first.
3. Once Grafana hands the request to the plugin, the plugin reads
   the authenticated user's identity from the `X-Grafana-User`,
   `X-Grafana-Login`, `X-Grafana-Email`, and `X-Grafana-Id` headers that
   Grafana injects.
4. The plugin's backend, acting with its own admin-level Grafana credentials
   (configured once by an admin — see "Install" below), creates or updates
   a service account named `gcx-<login>` in the user's org, mints a fresh
   API token for it, and returns it.
5. The plugin's frontend redirects the browser to
   `http://127.0.0.1:<callback_port>/callback?token=…&state=…`. gcx captures
   the token and writes it to its config.

The resulting token is an ordinary Grafana service-account token — it works
with `curl`, with the `mcp/grafana` Docker image, with anything that takes
a Grafana API token.

## Permission model

| Actor | Permissions needed |
|---|---|
| End user (signing in with `gcx auth login`) | Just **Viewer** in their org. They never create the SA themselves. |
| Admin (one-time install) | Server admin to install the plugin and generate the admin SA token. |
| The plugin's own admin SA | `serviceaccounts:write`, `serviceaccounts.permissions:write` — see [Grafana RBAC actions](https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/custom-role-actions-scopes/). |

Each end-user gets their own SA named `gcx-<login>`, so tokens can be
audited and revoked individually from the Grafana UI under **Administration
→ Users and access → Service accounts**.

## Install

### Build

The plugin has two parts:

```text
gcx-auth-app/
  pkg/      Go backend (Grafana plugin SDK)
  src/      module.js + plugin.json (frontend)
  dist/     packaged output (created by `make build`)
```

```bash
cd grafana-plugin/gcx-auth-app
make build           # builds the backend binary + assembles dist/
```

(`make build` is a thin wrapper around `mage -v build:backend` and a
copy of `src/` into `dist/`. If you prefer, run those by hand.)

### Configure Grafana

1. Copy `dist/` into your Grafana plugins directory as `gcx-auth-app/`:

   ```bash
   sudo mkdir -p /var/lib/grafana/plugins/gcx-auth-app
   sudo cp -r dist/* /var/lib/grafana/plugins/gcx-auth-app/
   ```

2. Allow the unsigned plugin in `grafana.ini`:

   ```ini
   [plugins]
   allow_loading_unsigned_plugins = gcx-auth-app
   ```

3. (Recommended) Enable the **externalServiceAccounts** feature toggle so
   Grafana provisions the plugin's own admin SA for you automatically:

   ```ini
   [feature_toggles]
   enable = externalServiceAccounts
   ```

   With the toggle enabled and the `iam.permissions` in `plugin.json`,
   Grafana creates the plugin's SA and injects its credentials into the
   plugin backend on startup — no manual token wrangling needed.

   If you can't enable that toggle, set the admin token by hand: create an
   Admin-role service account in Grafana, generate a token for it, and
   provide it to the plugin via the env var
   `GF_PLUGIN_GCX_AUTH_APP_ADMIN_TOKEN` (or via plugin settings in the UI
   once enabled).

4. Restart Grafana.

5. Sign in to Grafana as an admin, go to **Apps → gcx Auth**, and click
   **Enable**.

### Use

```bash
gcx auth login --server https://grafana.example.com
gcx auth token
```

## Files

* `src/plugin.json` — plugin manifest. Declares the app, its IAM
  permissions, and the `/cli` page route.
* `src/module.js` — minimal AMD module loaded by Grafana. Exports a
  React-free `AppPlugin` that renders the CLI auth page.
* `pkg/main.go`, `pkg/plugin.go` — Go backend. Implements the
  `POST /api/plugins/gcx-auth-app/resources/issue` resource handler that
  reads the user's identity from Grafana-injected headers and uses the
  plugin's admin SA to create/refresh a per-user service account + token.
* `Magefile.go`, `Makefile` — build glue.

## Caveats

* The plugin is currently unsigned. You must allow it via
  `allow_loading_unsigned_plugins` until it's signed by Grafana.
* If your Grafana is older than 10.3, the `externalServiceAccounts`
  toggle isn't available — fall back to the manual admin token env var.
* `gcx auth login` redirects to a `localhost` callback. If you run gcx
  inside a remote host (e.g. via SSH), you'll need to forward the callback
  port to your laptop (`ssh -L 54401:localhost:54401 …`) and pass
  `--callback-port 54401`.
