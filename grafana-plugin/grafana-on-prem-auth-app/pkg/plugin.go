// grafana-on-prem-auth-app plugin core. Implements:
//
//   - POST /api/plugins/grafana-on-prem-auth-app/resources/issue
//     Reads the authenticated user's identity from Grafana-injected
//     headers, creates (or reuses) a per-user service account named
//     "cli:<login>" in their org, mints a fresh API token for it,
//     stores the token keyed by a one-time authorization code, and
//     returns the code (NOT the token) to the frontend.
//
//   - POST /api/plugins/grafana-on-prem-auth-app/resources/exchange
//     Receives the one-time code and PKCE code_verifier from the CLI.
//     Verifies BASE64URL(SHA256(code_verifier)) matches the stored
//     code_challenge before returning the real token. Codes are
//     single-use with a 60-second TTL.
//
//   - POST /api/plugins/grafana-on-prem-auth-app/resources/tokens
//     Lists all SA tokens for the authenticated user's "cli:<login>" SA.
//
//   - DELETE /api/plugins/grafana-on-prem-auth-app/resources/tokens/<id>
//     Deletes a specific SA token by ID.
//
//   - GET /api/plugins/grafana-on-prem-auth-app/health
//     Standard plugin health check.
//
// The plugin uses its own admin-level Grafana credentials (provided via
// either the `externalServiceAccounts` feature or the
// GF_PLUGIN_GRAFANA_ON_PREM_AUTH_APP_ADMIN_TOKEN env var) to perform
// the SA writes on behalf of users — so end users never need
// SA-management permissions.
//
// Security model (RFC 8252 + RFC 7636):
//   - The token never appears in any URL or browser history.
//   - The authorization code is single-use and expires in 60 seconds.
//   - PKCE S256 ensures only the original CLI that started the flow
//     (which holds the code_verifier) can exchange the code.
//   - State parameter prevents CSRF.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/instancemgmt"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
)

// App is the plugin's backend instance.
type App struct {
	grafanaURL string
	adminToken string
	httpClient *http.Client
	logger     log.Logger

	// pendingCodes holds one-time authorization codes. Each code maps to
	// a pendingCode that contains the real token and the PKCE challenge.
	// Codes are single-use and expire after codeTTL.
	mu           sync.Mutex
	pendingCodes map[string]*pendingCode
}

// pendingCode is an in-memory record for a single authorization code.
type pendingCode struct {
	Token         string
	CodeChallenge string // BASE64URL(SHA256(code_verifier)) stored from the /issue request
	User          string
	Email         string
	OrgID         int64
	OrgName       string
	SAName        string
	TokenName     string
	ExpiresAt     time.Time
}

const codeTTL = 60 * time.Second

// defaultTokenTTL is the default lifetime for newly minted SA tokens.
// Tokens older than this expire automatically, keeping the token list clean.
// Callers can override per-request via issueRequest.TokenTTLSeconds.
const defaultTokenTTL = 30 * 24 * time.Hour // 30 days

// NewApp is the instance-management factory called by Grafana on plugin start.
func NewApp(ctx context.Context, _ backend.AppInstanceSettings) (instancemgmt.Instance, error) {
	return newApp(ctx)
}

func newApp(_ context.Context) (*App, error) {
	grafanaURL := firstNonEmpty(
		os.Getenv("GF_PLUGIN_APP_URL"), // set by Grafana for plugin children
		os.Getenv("GF_APP_URL"),
		os.Getenv("GF_SERVER_ROOT_URL"),
		"http://localhost:3000",
	)

	// Admin SA token, in priority order:
	//   1. GF_PLUGIN_GRAFANA_ON_PREM_AUTH_APP_ADMIN_TOKEN (operator-provided)
	//   2. GF_PLUGIN_APP_CLIENT_SECRET (set by Grafana when
	//      externalServiceAccounts is enabled and our plugin.json
	//      declares iam.permissions)
	adminToken := firstNonEmpty(
		os.Getenv("GF_PLUGIN_GRAFANA_ON_PREM_AUTH_APP_ADMIN_TOKEN"),
		os.Getenv("GF_PLUGIN_APP_CLIENT_SECRET"),
	)

	return &App{
		grafanaURL:   strings.TrimSuffix(grafanaURL, "/"),
		adminToken:   adminToken,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		logger:       log.DefaultLogger,
		pendingCodes: make(map[string]*pendingCode),
	}, nil
}

// Dispose is called when the instance is unloaded.
func (a *App) Dispose() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pendingCodes = nil // help GC
}

// CheckHealth implements backend.CheckHealthHandler.
func (a *App) CheckHealth(_ context.Context, _ *backend.CheckHealthRequest) (*backend.CheckHealthResult, error) {
	if a.adminToken == "" {
		return &backend.CheckHealthResult{
			Status:  backend.HealthStatusError,
			Message: "Admin token not configured. Either enable the externalServiceAccounts feature toggle (recommended) or set GF_PLUGIN_GRAFANA_ON_PREM_AUTH_APP_ADMIN_TOKEN.",
		}, nil
	}
	return &backend.CheckHealthResult{Status: backend.HealthStatusOk, Message: "ready"}, nil
}

// CallResource implements backend.CallResourceHandler.
func (a *App) CallResource(ctx context.Context, req *backend.CallResourceRequest, sender backend.CallResourceResponseSender) error {
	switch {
	case req.Path == "issue" || req.Path == "issue/":
		return a.handleIssue(ctx, req, sender)
	case req.Path == "exchange" || req.Path == "exchange/":
		return a.handleExchange(ctx, req, sender)
	case req.Path == "tokens" || req.Path == "tokens/":
		return a.handleTokens(ctx, req, sender)
	case strings.HasPrefix(req.Path, "tokens/") && req.Method == http.MethodDelete:
		tokenID := strings.TrimPrefix(req.Path, "tokens/")
		return a.handleDeleteToken(ctx, req, sender, tokenID)
	default:
		return sender.Send(&backend.CallResourceResponse{
			Status: http.StatusNotFound,
			Body:   []byte(`{"message":"not found"}`),
		})
	}
}

// QueryData isn't used by app plugins; omitted.

// ---- issue handler ---------------------------------------------------------

type issueRequest struct {
	State               string `json:"state"`
	CallbackPort        int    `json:"callback_port"`
	OrgID               int64  `json:"org_id"`
	DeviceName          string `json:"device_name"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`

	// TokenTTLSeconds sets the token lifetime in seconds. 0 means
	// use the server-side default (defaultTokenTTL); -1 means never expire.
	TokenTTLSeconds int64 `json:"token_ttl_seconds"`
}

// issueResponse returns the one-time authorization code, NOT the token.
type issueResponse struct {
	Code    string `json:"code"`
	User    string `json:"user,omitempty"`
	Email   string `json:"email,omitempty"`
	OrgID   int64  `json:"org_id,omitempty"`
	OrgName string `json:"org_name,omitempty"`
}

func (a *App) handleIssue(ctx context.Context, req *backend.CallResourceRequest, sender backend.CallResourceResponseSender) error {
	if req.Method != http.MethodPost {
		return sendJSON(sender, http.StatusMethodNotAllowed, map[string]string{"message": "POST only"})
	}
	if a.adminToken == "" {
		return sendJSON(sender, http.StatusServiceUnavailable, map[string]string{
			"message": "plugin admin token not configured — see plugin health check",
		})
	}

	var body issueRequest
	if len(req.Body) > 0 {
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return sendJSON(sender, http.StatusBadRequest, map[string]string{"message": "invalid JSON: " + err.Error()})
		}
	}

	// PKCE: code_challenge is required.
	if body.CodeChallenge == "" {
		return sendJSON(sender, http.StatusBadRequest, map[string]string{"message": "code_challenge is required (PKCE)"})
	}
	if body.CodeChallengeMethod != "" && body.CodeChallengeMethod != "S256" {
		return sendJSON(sender, http.StatusBadRequest, map[string]string{"message": "only S256 code_challenge_method is supported"})
	}

	user := identityFromHeaders(req.Headers)
	if user.Login == "" {
		// Should never happen — Grafana refuses unauthenticated requests
		// to plugin resource endpoints — but guard just in case.
		return sendJSON(sender, http.StatusUnauthorized, map[string]string{"message": "no authenticated user"})
	}

	orgID := body.OrgID
	if orgID == 0 {
		orgID = user.OrgID
	}
	if orgID == 0 {
		orgID = 1
	}

	saName := serviceAccountName(user.Login)
	tokenName := tokenName(body.DeviceName)

	a.logger.Info("issuing CLI token", "user", user.Login, "orgID", orgID, "sa", saName, "device", body.DeviceName)

	// 1. Find or create the SA.
	sa, err := a.findOrCreateSA(ctx, orgID, saName, user)
	if err != nil {
		return sendError(sender, err)
	}

	// 2. Mint a fresh token. If caller specified a TTL, use it;
	// otherwise fall back to the server default (30 days).
	ttl := body.TokenTTLSeconds
	if ttl == 0 {
		ttl = int64(defaultTokenTTL.Seconds())
	} else if ttl < 0 {
		ttl = 0 // Grafana API: 0 = never expire
	}
	token, err := a.createToken(ctx, orgID, sa.ID, tokenName, ttl)
	if err != nil {
		return sendError(sender, err)
	}

	// 3. Look up the org name for nicer UX in the CLI summary.
	orgName, _ := a.fetchOrgName(ctx, orgID)

	// 4. Generate a one-time authorization code and store the pending
	//    exchange (token + PKCE challenge). The CLI will exchange it via
	//    /resources/exchange.
	code, err := generateAuthCode()
	if err != nil {
		return sendError(sender, fmt.Errorf("generating auth code: %w", err))
	}

	a.storePendingCode(code, &pendingCode{
		Token:         token,
		CodeChallenge: body.CodeChallenge,
		User:          user.Login,
		Email:         user.Email,
		OrgID:         orgID,
		OrgName:       orgName,
		SAName:        sa.Name,
		TokenName:     tokenName,
		ExpiresAt:     time.Now().Add(codeTTL),
	})

	return sendJSON(sender, http.StatusOK, issueResponse{
		Code:    code,
		User:    user.Login,
		Email:   user.Email,
		OrgID:   orgID,
		OrgName: orgName,
	})
}

// ---- exchange handler (PKCE) -----------------------------------------------

type exchangeRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
}

type exchangeResponse struct {
	Token     string `json:"token"`
	User      string `json:"user,omitempty"`
	Email     string `json:"email,omitempty"`
	OrgID     int64  `json:"org_id,omitempty"`
	OrgName   string `json:"org_name,omitempty"`
	SAName    string `json:"sa_name,omitempty"`
	TokenName string `json:"token_name,omitempty"`
}

func (a *App) handleExchange(_ context.Context, req *backend.CallResourceRequest, sender backend.CallResourceResponseSender) error {
	if req.Method != http.MethodPost {
		return sendJSON(sender, http.StatusMethodNotAllowed, map[string]string{"message": "POST only"})
	}

	var body exchangeRequest
	if len(req.Body) > 0 {
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return sendJSON(sender, http.StatusBadRequest, map[string]string{"message": "invalid JSON: " + err.Error()})
		}
	}

	if body.Code == "" || body.CodeVerifier == "" {
		return sendJSON(sender, http.StatusBadRequest, map[string]string{"message": "code and code_verifier are required"})
	}

	// Look up and consume the one-time code.
	pending := a.consumePendingCode(body.Code)
	if pending == nil {
		a.logger.Warn("exchange: invalid or expired code")
		return sendJSON(sender, http.StatusBadRequest, map[string]string{"message": "invalid or expired authorization code"})
	}

	// PKCE S256 verification: BASE64URL(SHA256(code_verifier)) must match
	// the code_challenge stored at issue time.
	h := sha256.Sum256([]byte(body.CodeVerifier))
	computedChallenge := base64.RawURLEncoding.EncodeToString(h[:])
	if computedChallenge != pending.CodeChallenge {
		a.logger.Warn("exchange: PKCE verification failed", "user", pending.User)
		return sendJSON(sender, http.StatusForbidden, map[string]string{"message": "PKCE verification failed — code_verifier does not match code_challenge"})
	}

	a.logger.Info("exchange: PKCE verified, returning token", "user", pending.User, "org", pending.OrgID)

	return sendJSON(sender, http.StatusOK, exchangeResponse{
		Token:     pending.Token,
		User:      pending.User,
		Email:     pending.Email,
		OrgID:     pending.OrgID,
		OrgName:   pending.OrgName,
		SAName:    pending.SAName,
		TokenName: pending.TokenName,
	})
}

// ---- token management handlers ---------------------------------------------

// saTokenInfo is returned when listing tokens for a service account.
type saTokenInfo struct {
	ID         int64   `json:"id"`
	Name       string  `json:"name"`
	Created    string  `json:"created,omitempty"`
	Expiration *string `json:"expiration,omitempty"`
	IsRevoked  bool    `json:"isRevoked,omitempty"`
	LastUsedAt *string `json:"lastUsedAt,omitempty"`
}

// handleTokens lists all tokens for the authenticated user's SA.
func (a *App) handleTokens(ctx context.Context, req *backend.CallResourceRequest, sender backend.CallResourceResponseSender) error {
	if req.Method != http.MethodPost {
		return sendJSON(sender, http.StatusMethodNotAllowed, map[string]string{"message": "POST only"})
	}
	if a.adminToken == "" {
		return sendJSON(sender, http.StatusServiceUnavailable, map[string]string{
			"message": "plugin admin token not configured",
		})
	}

	user := identityFromHeaders(req.Headers)
	if user.Login == "" {
		return sendJSON(sender, http.StatusUnauthorized, map[string]string{"message": "no authenticated user"})
	}

	var body struct {
		OrgID int64 `json:"org_id"`
	}
	if len(req.Body) > 0 {
		_ = json.Unmarshal(req.Body, &body)
	}
	orgID := body.OrgID
	if orgID == 0 {
		orgID = user.OrgID
	}
	if orgID == 0 {
		orgID = 1
	}

	saName := serviceAccountName(user.Login)
	sa, err := a.findSA(ctx, orgID, saName)
	if err != nil {
		return sendError(sender, err)
	}
	if sa == nil {
		return sendJSON(sender, http.StatusOK, []saTokenInfo{})
	}

	tokens, err := a.listTokens(ctx, orgID, sa.ID)
	if err != nil {
		return sendError(sender, err)
	}
	return sendJSON(sender, http.StatusOK, tokens)
}

// handleDeleteToken deletes a specific token by ID for the authenticated user's SA.
func (a *App) handleDeleteToken(ctx context.Context, req *backend.CallResourceRequest, sender backend.CallResourceResponseSender, tokenID string) error {
	if a.adminToken == "" {
		return sendJSON(sender, http.StatusServiceUnavailable, map[string]string{
			"message": "plugin admin token not configured",
		})
	}

	user := identityFromHeaders(req.Headers)
	if user.Login == "" {
		return sendJSON(sender, http.StatusUnauthorized, map[string]string{"message": "no authenticated user"})
	}

	var orgID int64
	if q := req.URL; q != "" {
		if u, err := url.Parse(q); err == nil {
			if v := u.Query().Get("org_id"); v != "" {
				orgID, _ = strconv.ParseInt(v, 10, 64)
			}
		}
	}
	if orgID == 0 {
		orgID = user.OrgID
	}
	if orgID == 0 {
		orgID = 1
	}

	saName := serviceAccountName(user.Login)
	sa, err := a.findSA(ctx, orgID, saName)
	if err != nil {
		return sendError(sender, err)
	}
	if sa == nil {
		return sendJSON(sender, http.StatusNotFound, map[string]string{"message": "no service account found"})
	}

	// Verify the token belongs to this SA before deleting (prevents
	// deleting tokens from other SAs).
	tid, err := strconv.ParseInt(tokenID, 10, 64)
	if err != nil {
		return sendJSON(sender, http.StatusBadRequest, map[string]string{"message": "invalid token ID"})
	}

	tokens, err := a.listTokens(ctx, orgID, sa.ID)
	if err != nil {
		return sendError(sender, err)
	}
	found := false
	for _, t := range tokens {
		if t.ID == tid {
			found = true
			break
		}
	}
	if !found {
		return sendJSON(sender, http.StatusNotFound, map[string]string{"message": "token not found for your service account"})
	}

	if err := a.deleteToken(ctx, orgID, sa.ID, tid); err != nil {
		return sendError(sender, err)
	}
	return sendJSON(sender, http.StatusOK, map[string]string{"message": "token deleted"})
}

// ---- pending code store ----------------------------------------------------

func (a *App) storePendingCode(code string, pc *pendingCode) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Garbage-collect expired codes while we're holding the lock.
	now := time.Now()
	for k, v := range a.pendingCodes {
		if now.After(v.ExpiresAt) {
			delete(a.pendingCodes, k)
		}
	}

	a.pendingCodes[code] = pc
}

// consumePendingCode atomically retrieves and deletes a code. Returns nil
// if the code doesn't exist or has expired.
func (a *App) consumePendingCode(code string) *pendingCode {
	a.mu.Lock()
	defer a.mu.Unlock()

	pc, ok := a.pendingCodes[code]
	if !ok {
		return nil
	}
	delete(a.pendingCodes, code) // single-use

	if time.Now().After(pc.ExpiresAt) {
		return nil // expired
	}
	return pc
}

func generateAuthCode() (string, error) {
	b := make([]byte, 32) // 256 bits
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ---- Grafana API client (admin SA) -----------------------------------------

type grafanaSA struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Login string `json:"login"`
}

type saSearchResponse struct {
	ServiceAccounts []grafanaSA `json:"serviceAccounts"`
	TotalCount      int         `json:"totalCount"`
}

type orgResp struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type tokenCreateResp struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

func (a *App) findOrCreateSA(ctx context.Context, orgID int64, name string, user gfUser) (*grafanaSA, error) {
	var search saSearchResponse
	q := "/api/serviceaccounts/search?query=" + name
	if err := a.gfRequest(ctx, http.MethodGet, q, orgID, nil, &search); err != nil {
		return nil, fmt.Errorf("searching service accounts: %w", err)
	}
	for i, sa := range search.ServiceAccounts {
		if sa.Name == name {
			return &search.ServiceAccounts[i], nil
		}
	}

	body := map[string]any{
		"name":       name,
		"role":       defaultRoleForUser(user),
		"isDisabled": false,
	}
	var created grafanaSA
	if err := a.gfRequest(ctx, http.MethodPost, "/api/serviceaccounts", orgID, body, &created); err != nil {
		return nil, fmt.Errorf("creating service account: %w", err)
	}
	return &created, nil
}

// findSA searches for an existing service account by exact name. Returns nil
// (not an error) if no SA with that name exists.
func (a *App) findSA(ctx context.Context, orgID int64, name string) (*grafanaSA, error) {
	var search saSearchResponse
	q := "/api/serviceaccounts/search?query=" + name
	if err := a.gfRequest(ctx, http.MethodGet, q, orgID, nil, &search); err != nil {
		return nil, fmt.Errorf("searching service accounts: %w", err)
	}
	for i, sa := range search.ServiceAccounts {
		if sa.Name == name {
			return &search.ServiceAccounts[i], nil
		}
	}
	return nil, nil //nolint:nilnil // no SA found, not an error
}

// listTokens returns all tokens for a service account.
func (a *App) listTokens(ctx context.Context, orgID, saID int64) ([]saTokenInfo, error) {
	var tokens []saTokenInfo
	if err := a.gfRequest(ctx, http.MethodGet, fmt.Sprintf("/api/serviceaccounts/%d/tokens", saID), orgID, nil, &tokens); err != nil {
		return nil, fmt.Errorf("listing tokens: %w", err)
	}
	return tokens, nil
}

// deleteToken deletes a token by ID from a service account.
func (a *App) deleteToken(ctx context.Context, orgID, saID, tokenID int64) error {
	if err := a.gfRequest(ctx, http.MethodDelete, fmt.Sprintf("/api/serviceaccounts/%d/tokens/%d", saID, tokenID), orgID, nil, nil); err != nil {
		return fmt.Errorf("deleting token: %w", err)
	}
	return nil
}

func (a *App) createToken(ctx context.Context, orgID, saID int64, name string, secondsToLive int64) (string, error) {
	body := map[string]any{
		"name":          name,
		"secondsToLive": secondsToLive,
	}
	var resp tokenCreateResp
	if err := a.gfRequest(ctx, http.MethodPost, fmt.Sprintf("/api/serviceaccounts/%d/tokens", saID), orgID, body, &resp); err != nil {
		return "", fmt.Errorf("creating token: %w", err)
	}
	if resp.Key == "" {
		return "", errors.New("Grafana returned empty token key")
	}
	return resp.Key, nil
}

func (a *App) fetchOrgName(ctx context.Context, orgID int64) (string, error) {
	var o orgResp
	if err := a.gfRequest(ctx, http.MethodGet, fmt.Sprintf("/api/orgs/%d", orgID), 0, nil, &o); err != nil {
		return "", err
	}
	return o.Name, nil
}

// gfRequest issues an authenticated request to Grafana using the plugin's
// admin SA token. orgID, when non-zero, scopes the request via the
// X-Grafana-Org-Id header.
func (a *App) gfRequest(ctx context.Context, method, path string, orgID int64, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, a.grafanaURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.adminToken)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if orgID > 0 {
		req.Header.Set("X-Grafana-Org-Id", strconv.FormatInt(orgID, 10))
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	const maxBody = 10 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeGrafanaError(method, path, resp.StatusCode, raw)
	}

	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("parsing %s response: %w", path, err)
	}
	return nil
}

func decodeGrafanaError(method, path string, status int, body []byte) error {
	var parsed struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil && parsed.Message != "" {
		return fmt.Errorf("Grafana %s %s -> %d: %s", method, path, status, parsed.Message)
	}
	preview := string(body)
	if len(preview) > 200 {
		preview = preview[:200] + "..."
	}
	return fmt.Errorf("Grafana %s %s -> %d: %s", method, path, status, preview)
}

// ---- identity & helpers ----------------------------------------------------

type gfUser struct {
	Login string
	Email string
	Name  string
	OrgID int64
	Role  string // Viewer | Editor | Admin
	IDTok string // X-Grafana-Id, when present
}

func identityFromHeaders(h map[string][]string) gfUser {
	get := func(k string) string {
		if vs, ok := h[k]; ok && len(vs) > 0 {
			return vs[0]
		}
		// Case-insensitive fallback.
		for hk, vs := range h {
			if strings.EqualFold(hk, k) && len(vs) > 0 {
				return vs[0]
			}
		}
		return ""
	}
	parseInt := func(s string) int64 {
		n, _ := strconv.ParseInt(s, 10, 64)
		return n
	}
	return gfUser{
		Login: get("X-Grafana-Login"),
		Email: get("X-Grafana-Email"),
		Name:  get("X-Grafana-Name"),
		OrgID: parseInt(get("X-Grafana-Org-Id")),
		Role:  get("X-Grafana-Role"),
		IDTok: get("X-Grafana-Id"),
	}
}

// defaultRoleForUser picks a SA role that mirrors the signed-in user's
// org role. Grafana SA tokens are role-scoped at SA creation time, so
// this gives each user a token with roughly the same effective
// permissions they have when clicking around the UI. (Note: Grafana
// still enforces RBAC on each API call.)
func defaultRoleForUser(u gfUser) string {
	switch strings.ToLower(u.Role) {
	case "admin":
		return "Admin"
	case "editor":
		return "Editor"
	default:
		return "Viewer"
	}
}

func serviceAccountName(login string) string {
	return "cli:" + sanitize(login)
}

func tokenName(device string) string {
	stamp := time.Now().UTC().Format("20060102-150405")
	if device == "" {
		return "cli-" + stamp
	}
	return "cli-" + sanitize(device) + "-" + stamp
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "user"
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func sendJSON(sender backend.CallResourceResponseSender, status int, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return sender.Send(&backend.CallResourceResponse{
		Status:  status,
		Headers: map[string][]string{"Content-Type": {"application/json"}},
		Body:    raw,
	})
}

func sendError(sender backend.CallResourceResponseSender, err error) error {
	return sendJSON(sender, http.StatusBadGateway, map[string]string{"message": err.Error()})
}
