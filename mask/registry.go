package mask

import "sync"

// Registry binds physical locations to logical policies. It holds one policy
// per domain ID and rejects a binding of that domain ID with differing policy
// metadata, including a different policy version. A Registry is safe for
// concurrent use.
type Registry struct {
	mu        sync.Mutex
	domains   map[string]string
	locations map[string]*Binding
}

// Binding is an immutable location handle. Its name never enters the tweak.
type Binding struct {
	name   string
	policy *Policy
}

// Bind registers a location and checks domain consistency.
func (r *Registry) Bind(location string, p *Policy) (*Binding, error) {
	if r == nil || p == nil || p.cipher == nil || location == "" {
		return nil, ErrInvalidSpec
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.domains == nil {
		r.domains = make(map[string]string)
		r.locations = make(map[string]*Binding)
	}
	if prior, ok := r.domains[p.domainID]; ok && prior != p.fingerprint {
		return nil, ErrDivergentPolicy
	}
	if prior, ok := r.locations[location]; ok {
		if prior.policy.fingerprint != p.fingerprint ||
			prior.policy.domainID != p.domainID || prior.policy.version != p.version {
			return nil, ErrDivergentPolicy
		}
		return prior, nil
	}
	b := &Binding{name: location, policy: p}
	r.domains[p.domainID] = p.fingerprint
	r.locations[location] = b
	return b, nil
}

// Mask masks through the bound policy. The binding name never affects output.
func (b *Binding) Mask(raw string, ctx Context) (string, error) {
	if b == nil || b.policy == nil {
		return "", ErrInvalidSpec
	}
	return b.policy.Mask(raw, ctx)
}
