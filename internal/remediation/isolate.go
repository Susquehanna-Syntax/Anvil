package remediation

// Generation runs in its own process (plan node generate): no credential in
// its environment, only its three standard streams passed on by the parent
// (a descriptor the parent itself inherited without close-on-exec could still
// reach it), and no socket except the one to the model endpoint. A prompt injection hidden in a finding reaches a process
// that holds nothing worth stealing and can reach nothing but the model.
//
// The child's environment is an ALLOWLIST of one variable, set by the parent.
// The child refuses to run if it sees anything else, and before it answers it
// lists every socket it holds, read from /proc, so the parent can refuse a
// reply from a process that talked to anything but the endpoint.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// GenerationEnv is the generation process's whole environment.
const GenerationEnv = "ANVIL_GENERATION_PROCESS=1"

// Generator proposes text for a prompt. The controller only ever holds one
// through IsolatedGenerator in production; tests substitute canned replies.
type Generator interface {
	Generate(ctx context.Context, msgs []Message, maxTokens int) (string, error)
	// Model names the model, for the triage table and the trailers.
	Model() string
}

// generationRequest is what the parent writes to the child's stdin.
type generationRequest struct {
	Endpoint  Endpoint  `json:"endpoint"`
	APIKey    string    `json:"apiKey,omitempty"`
	Messages  []Message `json:"messages"`
	MaxTokens int       `json:"maxTokens"`
}

// generationReply is what the child writes to its stdout.
type generationReply struct {
	Content string   `json:"content,omitempty"`
	Error   string   `json:"error,omitempty"`
	Environ []string `json:"environ"` // the names the child saw
	Peers   []string `json:"peers"`   // remote address of every socket held at the end, or "unix:<inode>"/"unknown:<inode>"
}

// IsolatedGenerator runs each generation in a fresh child process.
type IsolatedGenerator struct {
	// Exe and Args start the child; in production, the anvil binary with
	// "generate-isolated".
	Exe      string
	Args     []string
	Endpoint Endpoint
}

// Model names the configured model.
func (g IsolatedGenerator) Model() string { return g.Endpoint.Model }

// ErrIsolation means the generation process broke its isolation contract.
var ErrIsolation = errors.New("remediation: the generation process broke its isolation")

// Generate runs one chat call in a child process and checks the child's own
// account of its environment and sockets before trusting the reply.
func (g IsolatedGenerator) Generate(ctx context.Context, msgs []Message, maxTokens int) (string, error) {
	if _, err := g.Endpoint.Check(); err != nil {
		return "", err
	}
	var key string
	if g.Endpoint.APIKeyFile != "" {
		raw, err := os.ReadFile(g.Endpoint.APIKeyFile)
		if err != nil {
			return "", fmt.Errorf("remediation: reading the endpoint's key file: %w", err)
		}
		key = strings.TrimSpace(string(raw))
	}
	out, err := runGeneration(ctx, g.Exe, g.Args, generationRequest{Endpoint: g.Endpoint, APIKey: key, Messages: msgs, MaxTokens: maxTokens})
	if err != nil {
		return "", err
	}
	var rep generationReply
	if err := json.Unmarshal(out, &rep); err != nil {
		return "", fmt.Errorf("remediation: generation process reply: %w", err)
	}
	if err := checkIsolation(rep, g.Endpoint); err != nil {
		return "", err
	}
	if rep.Error != "" {
		return "", errors.New(rep.Error)
	}
	return rep.Content, nil
}

// runGeneration starts the child with an environment of one marker, no
// inherited descriptor beyond its three standard streams, and the request on
// its stdin, and returns what it wrote.
func runGeneration(ctx context.Context, exe string, args []string, req generationRequest) ([]byte, error) {
	in, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Env = []string{GenerationEnv}
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(in)
	var out, errOut bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &out, n: maxReplyBytes * 2}
	cmd.Stderr = &limitedWriter{w: &errOut, n: 64 << 10}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("remediation: generation process: %v: %s", err, strings.TrimSpace(errOut.String()))
	}
	return out.Bytes(), nil
}

// checkIsolation refuses a reply whose process saw an environment other than
// the allowlist or held a socket to anything but the endpoint.
func checkIsolation(rep generationReply, e Endpoint) error {
	want := strings.SplitN(GenerationEnv, "=", 2)[0]
	if len(rep.Environ) != 1 || rep.Environ[0] != want {
		return fmt.Errorf("%w: its environment held %v, want only %s", ErrIsolation, rep.Environ, want)
	}
	allowed, err := endpointAddrs(e)
	if err != nil {
		return err
	}
	for _, p := range rep.Peers {
		if !allowed[p] {
			return fmt.Errorf("%w: it held a socket to %s; only the model endpoint %v is allowed", ErrIsolation, p, keys(allowed))
		}
	}
	return nil
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// endpointAddrs resolves the endpoint to the host:port strings a socket to it
// would show.
func endpointAddrs(e Endpoint) (map[string]bool, error) {
	u, err := url.Parse(e.URL)
	if err != nil {
		return nil, err
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	host := u.Hostname()
	var ips []string
	if ip := net.ParseIP(host); ip != nil {
		ips = []string{ip.String()}
	} else {
		addrs, err := net.LookupHost(host)
		if err != nil {
			return nil, fmt.Errorf("remediation: resolving the endpoint: %w", err)
		}
		ips = addrs
	}
	out := map[string]bool{}
	for _, ip := range ips {
		out[net.JoinHostPort(net.ParseIP(ip).String(), port)] = true
	}
	return out, nil
}

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > l.n {
		return 0, errors.New("remediation: generation process output over its limit")
	}
	l.n -= len(p)
	return l.w.Write(p)
}

// ServeGeneration is the child's whole program: `anvil generate-isolated`.
// It returns the process exit status.
func ServeGeneration(ctx context.Context, stdin io.Reader, stdout io.Writer) int {
	rep := generationReply{Environ: environNames()}
	emit := func() int {
		rep.Peers = socketPeers(&rep)
		if err := json.NewEncoder(stdout).Encode(rep); err != nil {
			return 5
		}
		return 0
	}
	if len(os.Environ()) != 1 || os.Environ()[0] != GenerationEnv {
		rep.Error = "the generation process refuses to run with any environment but its own marker"
		return emit()
	}
	var req generationRequest
	if err := json.NewDecoder(io.LimitReader(stdin, 64<<20)).Decode(&req); err != nil {
		rep.Error = "reading the request: " + err.Error()
		return emit()
	}
	if _, err := req.Endpoint.Check(); err != nil {
		rep.Error = err.Error()
		return emit()
	}
	content, err := chat(ctx, req.Endpoint, req.APIKey, req.Messages, req.MaxTokens)
	if err != nil {
		rep.Error = err.Error()
	}
	rep.Content = content
	return emit()
}

func environNames() []string {
	names := []string{}
	for _, kv := range os.Environ() {
		names = append(names, strings.SplitN(kv, "=", 2)[0])
	}
	sort.Strings(names)
	return names
}

// socketPeers lists the remote end of every socket this process holds, by
// matching /proc/self/fd's socket inodes against /proc/self/net. A socket it
// cannot place is reported as unknown, which the parent refuses.
func socketPeers(rep *generationReply) []string {
	inodes := map[string]bool{}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		rep.Error = "cannot list /proc/self/fd, so the process cannot show it held no stray socket"
		return []string{"unknown:proc"}
	}
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
		if err == nil && strings.HasPrefix(target, "socket:[") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	peers := []string{}
	placed := map[string]bool{}
	for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f, err := os.Open("/proc/self/net/" + table)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Scan() // header
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 10 || !inodes[fields[9]] {
				continue
			}
			placed[fields[9]] = true
			if addr, ok := procAddr(fields[2]); ok {
				peers = append(peers, addr)
			} else {
				peers = append(peers, "unknown:"+fields[9])
			}
		}
		_ = f.Close()
	}
	for ino := range inodes {
		if !placed[ino] {
			peers = append(peers, "socket:"+ino)
		}
	}
	sort.Strings(peers)
	return peers
}

// procAddr decodes /proc/net/tcp's "0100007F:1F90" (IPv4) or its 32-hex IPv6
// form; each 32-bit word is little-endian.
func procAddr(s string) (string, bool) {
	hp := strings.SplitN(s, ":", 2)
	if len(hp) != 2 {
		return "", false
	}
	raw, err := hex.DecodeString(hp[0])
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", false
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 {
		ip[i], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	port, err := strconv.ParseUint(hp[1], 16, 16)
	if err != nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return net.JoinHostPort(ip.String(), strconv.FormatUint(port, 10)), true
}
