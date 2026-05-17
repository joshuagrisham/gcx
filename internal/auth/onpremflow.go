// Package auth — on-prem browser login flow.
//
// Unlike the assistant-app cloud flow (flow.go), this version is for users
// running self-hosted Grafana ("OSS"). It assumes an admin has installed
// the companion grafana-on-prem-auth-app Grafana plugin
// (see grafana-plugin/grafana-on-prem-auth-app in this repo).
//
// Flow (RFC 8252 + PKCE, per RFC 7636):
//
//  1. gcx generates a PKCE code_verifier (high-entropy random string) and
//     derives code_challenge = BASE64URL(SHA256(code_verifier)).
//  2. gcx starts a local HTTP server on 127.0.0.1:PORT.
//  3. gcx opens the user's browser to:
//     https://<grafana>/a/grafana-on-prem-auth-app/cli?callback_port=PORT&state=STATE
//     &code_challenge=CHALLENGE&code_challenge_method=S256
//     That page is auth-gated by Grafana — if the user isn't already signed
//     in, Grafana redirects them through whichever auth provider the admin
//     has configured (OAuth, LDAP, basic, etc.). gcx never sees their creds.
//  4. Once signed in, the plugin page calls its own backend resource
//     handler (POST /resources/issue) which mints a per-user Grafana SA
//     token, stores it keyed by a one-time authorization code, and returns
//     the code (NOT the token) to the frontend.
//  5. The plugin page redirects the browser to
//     http://127.0.0.1:PORT/callback?code=CODE&state=STATE
//     The real token never appears in a URL.
//  6. gcx verifies the state, then exchanges the code for the token via a
//     back-channel HTTPS POST to the plugin's /resources/exchange endpoint,
//     presenting the code_verifier. The plugin verifies
//     BASE64URL(SHA256(code_verifier)) == stored code_challenge before
//     returning the token. The code is single-use and short-lived (60 s).
//  7. gcx persists the token to its config — it's a real Grafana SA
//     token, usable by gcx itself, by the Grafana MCP image, by curl, etc.
package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed templates/oss_callback_success.html
var ossTemplateFS embed.FS

// OnPremResult is returned by OnPremFlow.Run on success.
type OnPremResult struct {
	// Token is the per-user Grafana service-account token (typically a
	// glsa_… prefixed token) that the on-prem auth plugin minted for
	// the signed-in user. Usable for all standard Grafana API calls.
	Token string

	// User and Email identify who signed in (when echoed back by the
	// plugin). Purely informational.
	User  string
	Email string

	// OrgID and OrgName identify the organisation the SA was created in.
	OrgID   int64
	OrgName string

	// TokenName is the name attached to the SA token in Grafana so users
	// can find/revoke it from the UI.
	TokenName string

	// ServiceAccountName is the name of the SA the plugin used or created
	// for this user.
	ServiceAccountName string
}

// OnPremFlowOptions configures the on-prem browser login.
type OnPremFlowOptions struct {
	// Port pins the local callback port; 0 auto-picks from a small range.
	Port int

	// BindAddress defaults to 127.0.0.1.
	BindAddress string

	// OrgID, when non-zero, is forwarded as a hint to the plugin so the
	// service account is created in that org. When zero, the plugin uses
	// the user's current Grafana org.
	OrgID int64

	// Writer receives human-facing progress messages. Defaults to os.Stderr.
	Writer io.Writer

	// OpenBrowser opens the given URL. When nil the shared openBrowser
	// helper is used; tests can override this to a no-op.
	OpenBrowser func(ctx context.Context, url string) error

	// CallbackTimeout caps how long the CLI will wait for the browser
	// callback. Defaults to 5 minutes.
	CallbackTimeout time.Duration

	// SkipTLSVerify is purely informational here — the callback server is
	// local-only; gcx itself never speaks TLS to Grafana during the flow.
	// Retained for future use.
	SkipTLSVerify bool
}

// onPremPluginID is the fixed Grafana plugin ID. Not configurable;
// the plugin is always installed under this ID.
const onPremPluginID = "grafana-on-prem-auth-app"

// OnPremFlow drives the browser handshake with grafana-on-prem-auth-app.
type OnPremFlow struct {
	endpoint string
	opts     OnPremFlowOptions
	writer   io.Writer
}

// NewOnPremFlow constructs a new flow for the given Grafana server URL.
func NewOnPremFlow(endpoint string, opts OnPremFlowOptions) *OnPremFlow {
	if opts.BindAddress == "" {
		opts.BindAddress = "127.0.0.1"
	}
	if opts.CallbackTimeout == 0 {
		opts.CallbackTimeout = 5 * time.Minute
	}
	w := opts.Writer
	if w == nil {
		w = os.Stderr
	}
	return &OnPremFlow{
		endpoint: strings.TrimSuffix(endpoint, "/"),
		opts:     opts,
		writer:   w,
	}
}

// Run executes the flow and returns the captured token.
func (f *OnPremFlow) Run(ctx context.Context) (*OnPremResult, error) {
	if f.endpoint == "" {
		return nil, errors.New("server URL is required")
	}

	listener, port, err := listenOnOnPremCallbackPort(ctx, f.opts.BindAddress, f.opts.Port)
	if err != nil {
		return nil, err
	}

	state, err := generateOnPremState()
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("generating state: %w", err)
	}

	// PKCE (RFC 7636): generate code_verifier and derive code_challenge.
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("generating PKCE verifier: %w", err)
	}
	codeChallenge := generateCodeChallenge(codeVerifier)

	codeCh := make(chan callbackResult, 1)
	errCh := make(chan error, 1)
	server := f.startCallbackServer(listener, state, codeCh, errCh)

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	authURL := f.buildAuthURL(port, state, codeChallenge)

	fmt.Fprintln(f.writer, "Opening your browser to sign in to Grafana...")
	fmt.Fprintf(f.writer, "If your browser doesn't open, visit:\n  %s\n\n", authURL)

	open := f.opts.OpenBrowser
	if open == nil {
		open = openBrowser
	}
	if err := open(ctx, authURL); err != nil {
		fmt.Fprintln(f.writer, "(Could not open browser automatically — paste the URL above instead.)")
	}

	fmt.Fprintln(f.writer, "Waiting for sign-in to complete...")

	timeoutCtx, cancel := context.WithTimeout(ctx, f.opts.CallbackTimeout)
	defer cancel()

	var cb callbackResult
	select {
	case cb = <-codeCh:
		// Got the authorization code — now exchange it.
	case err := <-errCh:
		return nil, err
	case <-timeoutCtx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("timed out after %s waiting for browser callback", f.opts.CallbackTimeout)
	}

	// Back-channel token exchange: POST code + code_verifier to the plugin.
	fmt.Fprintln(f.writer, "Exchanging authorization code for token...")
	result, err := f.exchangeCode(ctx, cb.Code, codeVerifier)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %w", err)
	}

	// Fill in metadata that the callback URL carried (the exchange
	// endpoint only returns token + SA details).
	if result.User == "" {
		result.User = cb.User
	}
	if result.Email == "" {
		result.Email = cb.Email
	}
	if result.OrgName == "" {
		result.OrgName = cb.OrgName
	}
	if result.OrgID == 0 && cb.OrgID != "" {
		var n int64
		_, _ = fmt.Sscan(cb.OrgID, &n)
		result.OrgID = n
	}

	return result, nil
}

func (f *OnPremFlow) buildAuthURL(port int, state, codeChallenge string) string {
	u := f.endpoint + "/a/" + onPremPluginID + "/cli"
	q := url.Values{}
	q.Set("callback_port", fmt.Sprintf("%d", port))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	if f.opts.OrgID > 0 {
		q.Set("org_id", fmt.Sprintf("%d", f.opts.OrgID))
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		q.Set("device_name", host)
	}
	return u + "?" + q.Encode()
}

// exchangeCode performs the back-channel PKCE token exchange (POST to
// the plugin's /resources/exchange endpoint). The request carries the
// one-time code and the PKCE code_verifier; the plugin verifies
// SHA256(verifier) == stored challenge before returning the real token.
func (f *OnPremFlow) exchangeCode(ctx context.Context, code, codeVerifier string) (*OnPremResult, error) {
	exchangeURL := f.endpoint + "/api/plugins/" + onPremPluginID + "/resources/exchange"

	body, err := json.Marshal(map[string]string{
		"code":          code,
		"code_verifier": codeVerifier,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, exchangeURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	if f.opts.SkipTLSVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // user-requested
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	const maxBody = 1 << 20 // 1 MB
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		var parsed struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &parsed) == nil && parsed.Message != "" {
			return nil, fmt.Errorf("exchange: %s", parsed.Message)
		}
		return nil, fmt.Errorf("exchange: HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var result OnPremResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("parsing exchange response: %w", err)
	}
	if result.Token == "" {
		return nil, errors.New("exchange: server returned empty token")
	}
	return &result, nil
}

// callbackResult is used internally to pass the one-time authorization
// code from the local callback handler to the main flow.
type callbackResult struct {
	Code    string
	User    string
	Email   string
	OrgID   string
	OrgName string
}

func (f *OnPremFlow) startCallbackServer(listener net.Listener, expectedState string, codeCh chan<- callbackResult, errCh chan<- error) *http.Server {
	var once sync.Once

	mux := http.NewServeMux()

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		handled := false
		once.Do(func() {
			handled = true

			q := r.URL.Query()

			if errStr := q.Get("error"); errStr != "" {
				errStr = StripControlChars(errStr)
				errCh <- fmt.Errorf("plugin reported error: %s", errStr)
				renderOSSErrorPage(w, errStr)
				return
			}

			state := q.Get("state")
			if state != expectedState {
				errCh <- errors.New("state mismatch — possible CSRF attack")
				renderOSSErrorPage(w, "Invalid state")
				return
			}

			code := q.Get("code")
			if code == "" {
				errCh <- errors.New("no authorization code returned from plugin")
				renderOSSErrorPage(w, "Missing authorization code")
				return
			}

			codeCh <- callbackResult{
				Code:    code,
				User:    q.Get("user"),
				Email:   q.Get("email"),
				OrgID:   q.Get("org_id"),
				OrgName: q.Get("org_name"),
			}
			// Show a "completing..." page; the actual result comes
			// after the back-channel exchange.
			renderOSSExchangingPage(w)
		})
		if !handled {
			http.Error(w, "Sign-in already completed in another tab", http.StatusGone)
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Anyone hitting / by accident gets a friendly note. Real browser
		// flow goes straight to /callback.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("gcx local callback listener — waiting for /callback request from Grafana.\n"))
	})

	server := &http.Server{
		Addr:              listener.Addr().String(),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case errCh <- fmt.Errorf("local callback server error: %w", err):
			default:
			}
		}
	}()

	return server
}

func listenOnOnPremCallbackPort(ctx context.Context, bindAddress string, fixedPort int) (net.Listener, int, error) {
	var lc net.ListenConfig
	if fixedPort != 0 {
		listener, err := lc.Listen(ctx, "tcp", fmt.Sprintf("%s:%d", bindAddress, fixedPort))
		if err != nil {
			return nil, 0, fmt.Errorf("local port %d unavailable: %w", fixedPort, err)
		}
		return listener, fixedPort, nil
	}
	for port := 54401; port < 54500; port++ {
		listener, err := lc.Listen(ctx, "tcp", fmt.Sprintf("%s:%d", bindAddress, port))
		if err == nil {
			return listener, port, nil
		}
	}
	return nil, 0, errors.New("no available local port in range 54401-54499")
}

func generateOnPremState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func renderOSSErrorPage(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = fmt.Fprintf(w, `<!doctype html>
<html><head><title>gcx auth — error</title>
<style>body{font-family:sans-serif;background:#111217;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.b{background:#181b1f;border:1px solid #5a2424;padding:30px 40px;border-radius:8px;max-width:480px}h2{color:#ff7a7a;margin:0 0 12px}</style>
</head><body><div class="b"><h2>Sign-in failed</h2><p>%s</p></div></body></html>`, template.HTMLEscapeString(msg))
}

func renderOSSExchangingPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, `<!doctype html>
<html><head><title>gcx auth</title>
<style>body{font-family:sans-serif;background:#111217;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.b{background:#181b1f;border:1px solid #2c3239;padding:30px 40px;border-radius:8px;max-width:480px}h2{color:#73bf69;margin:0 0 12px}</style>
</head><body><div class="b"><h2>Completing sign-in…</h2><p>gcx is exchanging your authorization code. You can close this tab.</p></div></body></html>`)
}

// ---- Token management client -----------------------------------------------

// OnPremTokenInfo describes a single SA token as returned by the plugin.
type OnPremTokenInfo struct {
	ID         int64   `json:"id"`
	Name       string  `json:"name"`
	Created    string  `json:"created,omitempty"`
	Expiration *string `json:"expiration,omitempty"`
	IsRevoked  bool    `json:"isRevoked,omitempty"`
	LastUsedAt *string `json:"lastUsedAt,omitempty"`
}

// OnPremTokenClient is a client for managing on-prem SA tokens via the plugin's
// resource endpoints. It uses the user's existing SA token for auth.
type OnPremTokenClient struct {
	Server        string
	Token         string // the user's existing SA token
	OrgID         int64
	SkipTLSVerify bool
}

// ListTokens returns all tokens for the authenticated user's SA.
func (c *OnPremTokenClient) ListTokens(ctx context.Context) ([]OnPremTokenInfo, error) {
	body, err := json.Marshal(map[string]int64{"org_id": c.OrgID})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.Server+"/api/plugins/"+onPremPluginID+"/resources/tokens", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list tokens: HTTP %d: %s", resp.StatusCode, raw)
	}
	var tokens []OnPremTokenInfo
	if err := json.Unmarshal(raw, &tokens); err != nil {
		return nil, err
	}
	return tokens, nil
}

// DeleteToken deletes a specific token by ID.
func (c *OnPremTokenClient) DeleteToken(ctx context.Context, tokenID int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		fmt.Sprintf("%s/api/plugins/%s/resources/tokens/%d?org_id=%d",
			c.Server, onPremPluginID, tokenID, c.OrgID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("delete token: HTTP %d: %s", resp.StatusCode, raw)
	}
	return nil
}

func (c *OnPremTokenClient) httpClient() *http.Client {
	client := &http.Client{Timeout: 30 * time.Second}
	if c.SkipTLSVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // user-requested
		}
	}
	return client
}
