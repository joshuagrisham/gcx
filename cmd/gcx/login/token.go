package login

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"

	configcmd "github.com/grafana/gcx/cmd/gcx/config"
	"github.com/grafana/gcx/cmd/gcx/fail"
	"github.com/grafana/gcx/internal/auth"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// tokenOpts holds inputs for `gcx login token` and its subcommands.
type tokenOpts struct {
	Config configcmd.Options
}

func (opts *tokenOpts) setup(flags *pflag.FlagSet) {
	opts.Config.BindFlags(flags)
}

func (opts *tokenOpts) Validate() error { return nil }

// tokenCommand returns the `gcx login token` Cobra command tree.
func tokenCommand() *cobra.Command {
	opts := &tokenOpts{}

	cmd := &cobra.Command{
		Use:   "token",
		Args:  cobra.NoArgs,
		Short: "Print the active Grafana token to stdout",
		Long: `Print the Grafana API token for the current (or specified) context to stdout.

Works for both Cloud OAuth and on-prem tokens. Designed to mirror
` + "`gh auth token`" + ` so the value can be piped into other tools:

  gcx login token | pbcopy
  docker run -e GRAFANA_TOKEN=$(gcx login token) ... grafana/mcp-grafana

By default the current context is used. Pass --context to target a different one.`,
		Example: `  gcx login token
  gcx login token --context prod`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}
			token, err := resolveActiveToken(cmd.Context(), opts)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), token)
			return nil
		},
	}

	opts.setup(cmd.Flags())

	cmd.AddCommand(tokenListCommand())
	cmd.AddCommand(tokenDeleteCommand())

	return cmd
}

// resolveActiveToken returns the best non-empty Grafana token for the
// chosen context. Preference order: API token > OAuth bearer.
func resolveActiveToken(ctx context.Context, opts *tokenOpts) (string, error) {
	cfg, err := opts.Config.LoadConfigTolerant(ctx)
	if err != nil {
		return "", fmt.Errorf("loading config: %w", err)
	}

	name := opts.Config.Context
	if name == "" {
		name = cfg.CurrentContext
	}
	if name == "" {
		return "", notLoggedInError()
	}

	c, ok := cfg.Contexts[name]
	if !ok || c == nil {
		return "", fmt.Errorf("context %q not found", name)
	}
	if c.Grafana == nil {
		return "", fmt.Errorf("context %q has no Grafana credentials - run `gcx login` first", name)
	}

	switch {
	case c.Grafana.APIToken != "":
		return c.Grafana.APIToken, nil
	case c.Grafana.OAuthToken != "":
		return c.Grafana.OAuthToken, nil
	default:
		return "", fmt.Errorf("no token stored for context %q - run `gcx login` first", name)
	}
}

// resolveOnPremClient builds an OnPremTokenClient from the current context.
// Returns a non-nil error if the context doesn't have an on-prem SA token.
func resolveOnPremClient(ctx context.Context, cfgOpts *configcmd.Options) (*auth.OnPremTokenClient, error) {
	cfg, err := cfgOpts.LoadConfigTolerant(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	name := cfgOpts.Context
	if name == "" {
		name = cfg.CurrentContext
	}
	if name == "" {
		return nil, notLoggedInError()
	}

	c, ok := cfg.Contexts[name]
	if !ok || c == nil {
		return nil, fmt.Errorf("context %q not found", name)
	}
	g := c.Grafana
	if g == nil || g.APIToken == "" {
		return nil, fail.DetailedError{
			Summary: "no on-prem token",
			Details: fmt.Sprintf("Context %q does not have an on-prem service-account token.", name),
			Suggestions: []string{
				"This command manages tokens issued by the on-prem auth plugin.",
				"Log in with OAuth (browser) to an on-prem Grafana first: gcx login",
			},
		}
	}

	var skipTLS bool
	if g.TLS != nil {
		skipTLS = g.TLS.Insecure
	}

	return &auth.OnPremTokenClient{
		Server:        g.Server,
		Token:         g.APIToken,
		OrgID:         g.OrgID,
		SkipTLSVerify: skipTLS,
	}, nil
}

// ---- gcx login token list --------------------------------------------------

func tokenListCommand() *cobra.Command {
	opts := &tokenOpts{}

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		Short:   "List your on-prem service-account tokens",
		Long: `List all tokens for your on-prem CLI service account (cli:<login>).

Shows token ID, name, creation date, expiry, and last-used date.
Use ` + "`gcx login token delete <ID>`" + ` to remove tokens you no longer need.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}
			client, err := resolveOnPremClient(cmd.Context(), &opts.Config)
			if err != nil {
				return err
			}
			tokens, err := client.ListTokens(cmd.Context())
			if err != nil {
				return err
			}
			if len(tokens) == 0 {
				fmt.Fprintln(cmd.ErrOrStderr(), "No tokens found.")
				return nil
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tCREATED\tEXPIRES\tLAST USED")
			for _, t := range tokens {
				expires := "never"
				if t.Expiration != nil {
					expires = *t.Expiration
				}
				lastUsed := "-"
				if t.LastUsedAt != nil && *t.LastUsedAt != "" {
					lastUsed = *t.LastUsedAt
				}
				created := truncDate(t.Created)
				expires = truncDate(expires)
				lastUsed = truncDate(lastUsed)
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", t.ID, t.Name, created, expires, lastUsed)
			}
			return w.Flush()
		},
	}

	opts.setup(cmd.Flags())
	return cmd
}

// truncDate trims an ISO timestamp to just the date portion for display.
func truncDate(s string) string {
	if i := strings.IndexByte(s, 'T'); i > 0 {
		return s[:i]
	}
	return s
}

// ---- gcx login token delete ------------------------------------------------

func tokenDeleteCommand() *cobra.Command {
	opts := &tokenOpts{}

	cmd := &cobra.Command{
		Use:     "delete <TOKEN_ID> [TOKEN_ID...]",
		Aliases: []string{"rm"},
		Args:    cobra.MinimumNArgs(1),
		Short:   "Delete on-prem service-account tokens",
		Long: `Delete one or more tokens from your on-prem CLI service account (cli:<login>).

Pass the numeric token ID(s) shown by ` + "`gcx login token list`" + `.
Only tokens belonging to your own service account can be deleted.`,
		Example: `  gcx login token delete 42
  gcx login token delete 42 57 89`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}
			client, err := resolveOnPremClient(cmd.Context(), &opts.Config)
			if err != nil {
				return err
			}

			var ids []int64
			for _, arg := range args {
				id, err := strconv.ParseInt(arg, 10, 64)
				if err != nil {
					return fmt.Errorf("invalid token ID %q: %w", arg, err)
				}
				ids = append(ids, id)
			}

			for _, id := range ids {
				if err := client.DeleteToken(cmd.Context(), id); err != nil {
					return fmt.Errorf("deleting token %d: %w", id, err)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Deleted token %d\n", id)
			}
			return nil
		},
	}

	opts.setup(cmd.Flags())
	return cmd
}

func notLoggedInError() error {
	return fail.DetailedError{
		Summary: "not logged in",
		Details: "No current gcx context is configured.",
		Suggestions: []string{
			"Run `gcx login` to sign in to a Grafana instance.",
		},
	}
}
