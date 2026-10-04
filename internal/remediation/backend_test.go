package remediation

import (
	"errors"
	"testing"
)

// TestTheHostedEndpointWarningFiresOnlyWhenItShould is the remediation exit
// gate's row "the hosted-endpoint warning fires only when it should": a
// public endpoint the operator allowed warns, and nothing else does; a public
// endpoint not allowed, or one declared under another tier, is refused.
func TestTheHostedEndpointWarningFiresOnlyWhenItShould(t *testing.T) {
	cases := []struct {
		name   string
		e      Endpoint
		warn   bool
		refuse bool
	}{
		{"local loopback", Endpoint{URL: "http://127.0.0.1:8080/v1", Model: "m", Tier: TierLocal}, false, false},
		{"local localhost", Endpoint{URL: "http://localhost:8080/v1", Model: "m", Tier: TierLocal}, false, false},
		{"local ipv6", Endpoint{URL: "http://[::1]:8080/v1", Model: "m", Tier: TierLocal}, false, false},
		{"own private http", Endpoint{URL: "http://10.0.0.5:8080/v1", Model: "m", Tier: TierOwn}, false, false},
		{"own named https", Endpoint{URL: "https://gpu.example.internal/v1", Model: "m", Tier: TierOwn}, false, false},
		{"public allowed", Endpoint{URL: "https://openrouter.ai/api/v1", Model: "m", Tier: TierPublic, AllowPublic: true}, true, false},
		{"public allowed, any host", Endpoint{URL: "https://inference.example.com/v1", Model: "m", Tier: TierPublic, AllowPublic: true}, true, false},
		{"public not allowed", Endpoint{URL: "https://openrouter.ai/api/v1", Model: "m", Tier: TierPublic}, false, true},
		{"public over http", Endpoint{URL: "http://inference.example.com/v1", Model: "m", Tier: TierPublic, AllowPublic: true}, false, true},
		{"public host declared own", Endpoint{URL: "https://api.openai.com/v1", Model: "m", Tier: TierOwn}, false, true},
		{"public subdomain declared own", Endpoint{URL: "https://eu.api.openai.com/v1", Model: "m", Tier: TierOwn}, false, true},
		{"public host declared local", Endpoint{URL: "https://api.groq.com/v1", Model: "m", Tier: TierLocal}, false, true},
		{"local not loopback", Endpoint{URL: "http://10.0.0.5:8080/v1", Model: "m", Tier: TierLocal}, false, true},
		{"own public ip over http", Endpoint{URL: "http://8.8.8.8:8080/v1", Model: "m", Tier: TierOwn}, false, true},
		{"no model", Endpoint{URL: "http://127.0.0.1:8080/v1", Tier: TierLocal}, false, true},
		{"no tier", Endpoint{URL: "http://127.0.0.1:8080/v1", Model: "m"}, false, true},
		{"credentials in url", Endpoint{URL: "http://u:p@127.0.0.1:8080/v1", Model: "m", Tier: TierLocal}, false, true},
		{"not http", Endpoint{URL: "file:///tmp/x", Model: "m", Tier: TierLocal}, false, true},
	}
	for _, c := range cases {
		w, err := c.e.Check()
		if c.refuse != (err != nil) {
			t.Errorf("%s: refused %v (%v), want %v", c.name, err != nil, err, c.refuse)
		}
		if err != nil && !errors.Is(err, ErrEndpoint) {
			t.Errorf("%s: %v is not ErrEndpoint", c.name, err)
		}
		if got := len(w) > 0; got != c.warn {
			t.Errorf("%s: warned %v, want %v", c.name, got, c.warn)
		}
		if c.warn && w[0] != PublicEndpointWarning {
			t.Errorf("%s: warning %q", c.name, w[0])
		}
	}
}
