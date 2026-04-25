package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
)

type fixtureConfig struct {
	Mode   string
	Listen string
	Path   string
}

func parseFixtureConfig(args []string) (fixtureConfig, error) {
	fs := flag.NewFlagSet("fixtures", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfg := fixtureConfig{}
	fs.StringVar(&cfg.Mode, "mode", "http", "http|passthrough|mitm")
	fs.StringVar(&cfg.Listen, "listen", "127.0.0.1:0", "listen address")
	fs.StringVar(&cfg.Path, "path", "/allowed", "allowed path")
	if err := fs.Parse(args); err != nil {
		return fixtureConfig{}, err
	}

	return cfg, nil
}

func newHTTPFixture(path string, successStatus int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}

		w.WriteHeader(successStatus)
	})
}

func runFixture(args []string, stdout io.Writer) error {
	cfg, err := parseFixtureConfig(args)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}

	if _, err := fmt.Fprintf(stdout, "LISTEN_ADDR=%s\n", ln.Addr().String()); err != nil {
		_ = ln.Close()
		return err
	}

	return http.Serve(ln, newHTTPFixture(cfg.Path, http.StatusNoContent))
}

func main() {
	if err := runFixture(os.Args[1:], os.Stdout); err != nil {
		log.Fatal(err)
	}
}
