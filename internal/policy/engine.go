package policy

import "github.com/moolen/aegis/internal/identity"

type Decision struct {
	Allowed bool
	Policy  string
}

type Engine interface {
	Evaluate(identity *identity.Identity, fqdn string, port int) (*Decision, error)
}
