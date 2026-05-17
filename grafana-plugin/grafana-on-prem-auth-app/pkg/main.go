// Package main is the entry point of the grafana-on-prem-auth-app Grafana plugin.
package main

import (
	"os"

	"github.com/grafana/grafana-plugin-sdk-go/backend/app"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
)

func main() {
	if err := app.Manage("grafana-on-prem-auth-app", NewApp, app.ManageOpts{}); err != nil {
		log.DefaultLogger.Error("plugin exited", "err", err)
		os.Exit(1)
	}
}
