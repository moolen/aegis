package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/moolen/aegis/internal/config"
	"github.com/moolen/aegis/internal/policy"
)

func runCLI(args []string) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return runServe(args)
	}

	switch args[0] {
	case "validate":
		return runValidateCommand(args[1:])
	case "diff":
		return runDiffCommand(args[1:])
	case "dump-identities":
		return runDumpIdentitiesCommand(args[1:])
	case "simulate":
		return runSimulateCommand(args[1:])
	default:
		return runServe(args)
	}
}

func runValidateCommand(args []string) int {
	fs := newFlagSet("validate")
	configPath := fs.String("config", "aegis.example.yaml", "Path to the Aegis configuration file.")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stdout, "config valid: %s\n", *configPath)
	for _, warning := range policy.Analyze(cfg.Policies) {
		fmt.Fprintf(os.Stdout, "warning: %s\n", warning.Message)
	}

	return 0
}

func runDiffCommand(args []string) int {
	fs := newFlagSet("diff")
	currentPath := fs.String("current", "", "Path to the current configuration file.")
	nextPath := fs.String("next", "", "Path to the next configuration file.")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*currentPath) == "" || strings.TrimSpace(*nextPath) == "" {
		fmt.Fprintln(os.Stderr, "diff requires --current and --next")
		return 2
	}

	currentCfg, err := config.LoadFile(*currentPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load current config: %v\n", err)
		return 1
	}
	nextCfg, err := config.LoadFile(*nextPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load next config: %v\n", err)
		return 1
	}

	lines := diffConfigs(currentCfg, nextCfg)
	if len(lines) == 0 {
		fmt.Fprintln(os.Stdout, "no config differences")
		return 0
	}
	for _, line := range lines {
		fmt.Fprintln(os.Stdout, line)
	}
	for _, warning := range policy.Analyze(nextCfg.Policies) {
		fmt.Fprintf(os.Stdout, "warning: %s\n", warning.Message)
	}
	return 0
}

func runDumpIdentitiesCommand(args []string) int {
	fs := newFlagSet("dump-identities")
	adminURL := fs.String("admin", "http://127.0.0.1:9090", "Base URL for the Aegis admin endpoint.")
	token := fs.String("token", "", "Admin bearer token.")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*token) == "" {
		fmt.Fprintln(os.Stderr, "dump-identities requires --token")
		return 2
	}

	body, err := adminGET(*adminURL, *token, "/admin/identities", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dump identities: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stdout, prettyJSON(body))
	return 0
}

func runSimulateCommand(args []string) int {
	fs := newFlagSet("simulate")
	adminURL := fs.String("admin", "http://127.0.0.1:9090", "Base URL for the Aegis admin endpoint.")
	token := fs.String("token", "", "Admin bearer token.")
	sourceIP := fs.String("source-ip", "", "Source IP to resolve.")
	fqdn := fs.String("fqdn", "", "Destination FQDN to evaluate.")
	port := fs.Int("port", 0, "Destination port to evaluate.")
	protocol := fs.String("protocol", "http", "Protocol to simulate: http or connect.")
	method := fs.String("method", "GET", "HTTP method to simulate.")
	path := fs.String("path", "/", "HTTP path to simulate.")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*token) == "" || strings.TrimSpace(*sourceIP) == "" || strings.TrimSpace(*fqdn) == "" || *port == 0 {
		fmt.Fprintln(os.Stderr, "simulate requires --token, --source-ip, --fqdn, and --port")
		return 2
	}

	query := url.Values{
		"sourceIP": []string{*sourceIP},
		"fqdn":     []string{*fqdn},
		"port":     []string{fmt.Sprintf("%d", *port)},
		"protocol": []string{*protocol},
	}
	if strings.EqualFold(*protocol, "http") {
		query.Set("method", *method)
		query.Set("path", *path)
	}

	body, err := adminGET(*adminURL, *token, "/admin/simulate", query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "simulate: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stdout, prettyJSON(body))
	return 0
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func adminGET(baseURL string, token string, path string, query url.Values) ([]byte, error) {
	base := strings.TrimRight(baseURL, "/")
	endpoint := base + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func prettyJSON(body []byte) string {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return string(body)
	}
	formatted, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return string(body)
	}
	return string(formatted)
}

func diffConfigs(current config.Config, next config.Config) []string {
	lines := make([]string, 0)

	if config.NormalizeEnforcementMode(current.Proxy.Enforcement) != config.NormalizeEnforcementMode(next.Proxy.Enforcement) {
		lines = append(lines, fmt.Sprintf("proxy.enforcement: %s -> %s", config.NormalizeEnforcementMode(current.Proxy.Enforcement), config.NormalizeEnforcementMode(next.Proxy.Enforcement)))
	}
	if config.NormalizeUnknownIdentityPolicy(current.Proxy.UnknownIdentityPolicy) != config.NormalizeUnknownIdentityPolicy(next.Proxy.UnknownIdentityPolicy) {
		lines = append(lines, fmt.Sprintf("proxy.unknownIdentityPolicy: %s -> %s", config.NormalizeUnknownIdentityPolicy(current.Proxy.UnknownIdentityPolicy), config.NormalizeUnknownIdentityPolicy(next.Proxy.UnknownIdentityPolicy)))
	}
	if current.Admin.Enabled != next.Admin.Enabled {
		lines = append(lines, fmt.Sprintf("admin.enabled: %t -> %t", current.Admin.Enabled, next.Admin.Enabled))
	}
	if current.Admin.Listen != next.Admin.Listen {
		lines = append(lines, fmt.Sprintf("admin.listen: %s -> %s", current.Admin.Listen, next.Admin.Listen))
	}
	if (current.Admin.Token != "") != (next.Admin.Token != "") {
		lines = append(lines, fmt.Sprintf("admin.token configured: %t -> %t", current.Admin.Token != "", next.Admin.Token != ""))
	}
	if !reflect.DeepEqual(current.Proxy.CA, next.Proxy.CA) {
		lines = append(lines, "proxy.ca: changed")
	}
	if !reflect.DeepEqual(current.Discovery, next.Discovery) {
		lines = append(lines, "discovery: changed")
	}

	lines = append(lines, diffPolicySet(current.Policies, next.Policies)...)
	sort.Strings(lines)
	return lines
}

func diffPolicySet(current []config.PolicyConfig, next []config.PolicyConfig) []string {
	lines := make([]string, 0)
	currentByName := make(map[string]config.PolicyConfig, len(current))
	nextByName := make(map[string]config.PolicyConfig, len(next))
	for _, policyCfg := range current {
		currentByName[policyCfg.Name] = policyCfg
	}
	for _, policyCfg := range next {
		nextByName[policyCfg.Name] = policyCfg
	}

	names := make(map[string]struct{}, len(currentByName)+len(nextByName))
	for name := range currentByName {
		names[name] = struct{}{}
	}
	for name := range nextByName {
		names[name] = struct{}{}
	}

	orderedNames := make([]string, 0, len(names))
	for name := range names {
		orderedNames = append(orderedNames, name)
	}
	sort.Strings(orderedNames)

	for _, name := range orderedNames {
		currentCfg, currentOK := currentByName[name]
		nextCfg, nextOK := nextByName[name]
		switch {
		case !currentOK && nextOK:
			lines = append(lines, fmt.Sprintf("policy added: %s", name))
		case currentOK && !nextOK:
			lines = append(lines, fmt.Sprintf("policy removed: %s", name))
		case !reflect.DeepEqual(currentCfg, nextCfg):
			lines = append(lines, fmt.Sprintf("policy changed: %s", name))
		}
	}

	return lines
}
