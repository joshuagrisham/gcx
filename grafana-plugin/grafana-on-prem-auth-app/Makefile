.PHONY: build clean backend frontend

PLUGIN_ID := grafana-on-prem-auth-app
EXECUTABLE := gpx_grafana_on_prem_auth_app
DIST := dist

build: backend frontend

backend:
	mkdir -p $(DIST)
	GOOS=linux  GOARCH=amd64 go build -o $(DIST)/$(EXECUTABLE)_linux_amd64   ./pkg
	GOOS=linux  GOARCH=arm64 go build -o $(DIST)/$(EXECUTABLE)_linux_arm64   ./pkg
	GOOS=darwin GOARCH=amd64 go build -o $(DIST)/$(EXECUTABLE)_darwin_amd64  ./pkg
	GOOS=darwin GOARCH=arm64 go build -o $(DIST)/$(EXECUTABLE)_darwin_arm64  ./pkg
	GOOS=windows GOARCH=amd64 go build -o $(DIST)/$(EXECUTABLE)_windows_amd64.exe ./pkg

frontend:
	mkdir -p $(DIST)/img
	cp src/plugin.json $(DIST)/plugin.json
	cp src/module.js   $(DIST)/module.js
	cp ../README-logo.svg $(DIST)/img/logo.svg 2>/dev/null || printf '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24"><circle cx="12" cy="12" r="10" fill="#ff8833"/></svg>\n' > $(DIST)/img/logo.svg

clean:
	rm -rf $(DIST)
