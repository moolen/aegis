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

type Mapping struct {
	IP       string
	Provider string
	Kind     string
	Identity *Identity
}

type DumpEntry struct {
	IP        string
	Effective *Mapping
	Shadows   []Mapping
}

type Snapshotter interface {
	IdentityMappings() []Mapping
}

func Unknown() *Identity {
	return &Identity{
		Source: "unknown",
		Name:   "unknown",
		Labels: map[string]string{},
	}
}
