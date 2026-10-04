package remediation

// The model backend (plan node backend): any OpenAI-compatible chat endpoint,
// chosen by configuration, never hard-coded, with a trust tier the operator
// declares. A public hosted endpoint is off unless the operator allows it, and
// when allowed it is the one configuration that warns.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Tier is who runs the model endpoint.
type Tier string

// The three tiers.
const (
	// TierLocal is a server on this machine. Its host must be loopback.
	TierLocal Tier = "local"
	// TierOwn is the operator's own remote box (the hardware tiers put the
	// coder there). No warning: it is the operator's machine, not a third
	// party's.
	TierOwn Tier = "own"
	// TierPublic is a hosted service run by someone else. Target source,
	// findings and prompts leave the operator's control. Off by default.
	TierPublic Tier = "public"
)

// Endpoint is one configured model endpoint.
type Endpoint struct {
	// URL is the OpenAI-compatible base, e.g. http://127.0.0.1:8080/v1; the
	// client posts to URL + "/chat/completions".
	URL string
	// Model is the model name sent with every request. There is no default.
	Model string
	Tier  Tier
	// AllowPublic must be true for TierPublic to be accepted at all.
	AllowPublic bool
	// APIKeyFile, when set, holds a bearer token for the endpoint. It is read
	// by the parent and handed to the generation process on its stdin, never
	// through the environment.
	APIKeyFile string
}

// publicModelHosts are hosted inference services. Naming one under the local
// or own tier is a misdeclaration, refused rather than warned about: a warning
// that depended on the operator declaring the tier honestly would fire exactly
// when it is least needed.
var publicModelHosts = []string{
	"api.openai.com", "api.anthropic.com", "openrouter.ai", "api.together.xyz",
	"api.groq.com", "api.deepseek.com", "generativelanguage.googleapis.com",
	"api.mistral.ai", "api.fireworks.ai", "router.huggingface.co",
	"api-inference.huggingface.co", "api.cohere.com", "api.perplexity.ai",
	"inference.cerebras.ai", "api.cerebras.ai", "api.x.ai",
}

// ErrEndpoint reports an endpoint configuration Anvil refuses.
var ErrEndpoint = errors.New("remediation: model endpoint refused")

// PublicEndpointWarning is the warning a public endpoint produces. It is loud
// on purpose and it is the only warning Check returns.
const PublicEndpointWarning = "WARNING: THE MODEL ENDPOINT IS A PUBLIC HOSTED SERVICE. " +
	"Target source code, findings and every prompt leave this machine for a third party " +
	"that Anvil cannot audit. Anvil exists to make this unnecessary; use a self-hosted " +
	"endpoint unless you have decided otherwise for this repository."

// Check validates e and returns the warnings it earns. A warning is returned
// if and only if e is a public endpoint the operator allowed.
func (e Endpoint) Check() (warnings []string, err error) {
	u, err := url.Parse(e.URL)
	if err != nil {
		return nil, fmt.Errorf("%w: url %q: %v", ErrEndpoint, e.URL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: url %q must be http or https", ErrEndpoint, e.URL)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: url %q may not carry credentials, a query or a fragment", ErrEndpoint, e.URL)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return nil, fmt.Errorf("%w: url %q names no host", ErrEndpoint, e.URL)
	}
	if strings.TrimSpace(e.Model) == "" {
		return nil, fmt.Errorf("%w: no model is named; Anvil has no default model", ErrEndpoint)
	}
	public := isPublicModelHost(host)
	switch e.Tier {
	case TierLocal:
		if !isLoopback(host) {
			return nil, fmt.Errorf("%w: tier local needs a loopback host, not %q", ErrEndpoint, host)
		}
	case TierOwn:
		if public {
			return nil, fmt.Errorf("%w: %q is a public hosted service, so it cannot be declared tier own", ErrEndpoint, host)
		}
		if u.Scheme == "http" && !isLoopback(host) && !isPrivate(host) {
			return nil, fmt.Errorf("%w: tier own over plain http needs a private address; use https for %q", ErrEndpoint, host)
		}
	case TierPublic:
		if !e.AllowPublic {
			return nil, fmt.Errorf("%w: a public hosted endpoint is off by default; set allowPublic to use %q", ErrEndpoint, host)
		}
		if u.Scheme != "https" {
			return nil, fmt.Errorf("%w: a public endpoint must use https", ErrEndpoint)
		}
		return []string{PublicEndpointWarning}, nil
	default:
		return nil, fmt.Errorf("%w: tier %q is not local, own or public", ErrEndpoint, e.Tier)
	}
	return nil, nil
}

func isPublicModelHost(host string) bool {
	for _, h := range publicModelHosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isPrivate(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

// Message is one chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// maxReplyBytes caps what the client reads from the endpoint.
const maxReplyBytes = 4 << 20

// chat is one call to the endpoint. It runs inside the generation process
// (isolate.go), never in the controller.
func chat(ctx context.Context, e Endpoint, apiKey string, msgs []Message, maxTokens int) (string, error) {
	body, err := json.Marshal(map[string]any{
		"model": e.Model, "messages": msgs, "temperature": 0, "max_tokens": maxTokens, "stream": false,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(e.URL, "/")+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	// No proxy, ever: the only socket is the one to the endpoint.
	client := &http.Client{
		Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 30 * time.Second}).DialContext},
		Timeout:   30 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("remediation: the model endpoint redirected; refused")
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("remediation: model endpoint: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes+1))
	if err != nil {
		return "", err
	}
	if len(raw) > maxReplyBytes {
		return "", errors.New("remediation: the model reply is over 4 MiB; refused")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("remediation: model endpoint answered %d", resp.StatusCode)
	}
	var out struct {
		Choices []struct {
			Message Message `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("remediation: model reply is not a chat completion: %w", err)
	}
	if len(out.Choices) == 0 {
		return "", errors.New("remediation: model reply has no choices")
	}
	return out.Choices[0].Message.Content, nil
}
