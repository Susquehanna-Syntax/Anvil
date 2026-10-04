package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// fakeModel is an OpenAI-compatible endpoint that records what reached it.
func fakeModel(t *testing.T, reply string) (*httptest.Server, *[]map[string]any, *[]string) {
	t.Helper()
	var bodies []map[string]any
	var auths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		bodies = append(bodies, body)
		auths = append(auths, r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": reply}}}})
	}))
	t.Cleanup(srv.Close)
	return srv, &bodies, &auths
}

// TestGenerationHasNoCredentialsOrStraySockets is the remediation exit gate's
// row "generation has no credentials or stray sockets": the generation process
// is a real child process; the parent's environment holds credentials and the
// child sees none of them, only its marker; the only socket it holds when it
// answers is the one to the model endpoint; and the endpoint's key reaches the
// endpoint without passing through any environment.
func TestGenerationHasNoCredentialsOrStraySockets(t *testing.T) {
	for k, v := range map[string]string{"GITHUB_TOKEN": "ghp_parent", "AWS_SECRET_ACCESS_KEY": "aws", "ANVIL_PUSH_TOKEN": "push", "HTTPS_PROXY": "http://127.0.0.1:9"} {
		t.Setenv(k, v)
	}
	srv, bodies, auths := fakeModel(t, "FILE: a.c\n<<<<<<< SEARCH\nx\n=======\ny\n>>>>>>> REPLACE\n")
	keyFile := t.TempDir() + "/key"
	if err := os.WriteFile(keyFile, []byte("endpoint-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	g := IsolatedGenerator{Exe: exe, Endpoint: Endpoint{URL: srv.URL + "/v1", Model: "coder", Tier: TierLocal, APIKeyFile: keyFile}}
	reply, err := g.Generate(context.Background(), []Message{{Role: "user", Content: "fix it"}}, 64)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reply, "<<<<<<< SEARCH") {
		t.Fatalf("reply %q", reply)
	}
	if len(*bodies) != 1 || (*bodies)[0]["model"] != "coder" || (*bodies)[0]["temperature"] != float64(0) {
		t.Fatalf("the endpoint saw %v", *bodies)
	}
	if (*auths)[0] != "Bearer endpoint-key" {
		t.Fatalf("the endpoint's key did not arrive: %q", (*auths)[0])
	}

	// Run the child by hand to read its own account of itself.
	rep := runChild(t, exe, generationRequest{Endpoint: g.Endpoint, Messages: []Message{{Role: "user", Content: "x"}}, MaxTokens: 8}, []string{GenerationEnv})
	if rep.Error != "" || len(rep.Environ) != 1 || rep.Environ[0] != "ANVIL_GENERATION_PROCESS" {
		t.Fatalf("the child reported %+v", rep)
	}
	allowed, _ := endpointAddrs(g.Endpoint)
	if len(rep.Peers) == 0 {
		t.Log("the child closed its connection before answering; it held no socket at all")
	}
	for _, p := range rep.Peers {
		if !allowed[p] {
			t.Fatalf("the child held a socket to %s", p)
		}
	}

	// The child refuses to run with anything else in its environment.
	leaky := runChild(t, exe, generationRequest{Endpoint: g.Endpoint}, []string{GenerationEnv, "GITHUB_TOKEN=x"})
	if leaky.Error == "" || len(*bodies) != 2 {
		t.Fatalf("a child with a credential in its environment ran: %+v (endpoint calls %d)", leaky, len(*bodies))
	}
}

func runChild(t *testing.T, exe string, req generationRequest, env []string) generationReply {
	t.Helper()
	// The child decides what to be from its environment alone; one with more
	// than the marker runs as the test binary, so the leaky case is checked
	// through ServeGeneration's own refusal, in process.
	if len(env) != 1 {
		var out strings.Builder
		in, _ := json.Marshal(req)
		saved := os.Environ()
		os.Clearenv()
		for _, kv := range env {
			k, v, _ := strings.Cut(kv, "=")
			_ = os.Setenv(k, v)
		}
		ServeGeneration(context.Background(), strings.NewReader(string(in)), &out)
		os.Clearenv()
		for _, kv := range saved {
			k, v, _ := strings.Cut(kv, "=")
			_ = os.Setenv(k, v)
		}
		var rep generationReply
		if err := json.Unmarshal([]byte(out.String()), &rep); err != nil {
			t.Fatal(err)
		}
		return rep
	}
	raw, err := runGeneration(context.Background(), exe, nil, req)
	if err != nil {
		t.Fatal(err)
	}
	var rep generationReply
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

// TestCheckIsolationRefusesALeak: the parent's check refuses a reply from a
// process that saw another variable or held a socket to anything but the
// endpoint. These are the negative controls for the end-to-end test above.
func TestCheckIsolationRefusesALeak(t *testing.T) {
	e := Endpoint{URL: "http://127.0.0.1:8080/v1", Model: "m", Tier: TierLocal}
	ok := generationReply{Environ: []string{"ANVIL_GENERATION_PROCESS"}, Peers: []string{"127.0.0.1:8080"}}
	if err := checkIsolation(ok, e); err != nil {
		t.Fatal(err)
	}
	bad := []generationReply{
		{Environ: []string{"ANVIL_GENERATION_PROCESS", "GITHUB_TOKEN"}},
		{Environ: []string{}},
		{Environ: []string{"ANVIL_GENERATION_PROCESS"}, Peers: []string{"127.0.0.1:8080", "140.82.112.3:443"}},
		{Environ: []string{"ANVIL_GENERATION_PROCESS"}, Peers: []string{"socket:12345"}},
		{Environ: []string{"ANVIL_GENERATION_PROCESS"}, Peers: []string{"unknown:proc"}},
		{Environ: []string{"ANVIL_GENERATION_PROCESS"}, Peers: []string{"127.0.0.1:8081"}},
	}
	for _, b := range bad {
		if err := checkIsolation(b, e); !errors.Is(err, ErrIsolation) {
			t.Errorf("%+v was accepted: %v", b, err)
		}
	}
	if a, ok := procAddr("0100007F:1F90"); !ok || a != "127.0.0.1:8080" {
		t.Fatalf("procAddr: %q", a)
	}
	if a, ok := procAddr("00000000000000000000000001000000:01BB"); !ok || a != "[::1]:443" {
		t.Fatalf("procAddr v6: %q", a)
	}
}
