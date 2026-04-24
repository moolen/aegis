package identity

import "net"

type Identity struct {
	Source   string
	Provider string
	Name     string
	Labels   map[string]string
}

type Resolver interface {
	Resolve(ip net.IP) (*Identity, error)
}
