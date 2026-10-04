package remediation

import (
	"context"
	"database/sql"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/store"

	_ "modernc.org/sqlite" // cgo-free driver, the spine's Go control-plane decision
)

// TestMain lets the test binary stand in for `anvil generate-isolated`: the
// generation process is started with exactly GenerationEnv, so that variable
// alone decides which program this binary is.
func TestMain(m *testing.M) {
	// The marker anywhere in the environment makes this binary the child, so a
	// mutation that leaks the parent's environment reaches ServeGeneration's own
	// refusal instead of re-running the test suite.
	if os.Getenv("ANVIL_GENERATION_PROCESS") == "1" {
		os.Exit(ServeGeneration(context.Background(), os.Stdin, os.Stdout))
	}
	// The sandbox test runs this binary inside the sandbox to try the file
	// system: exit 0 only if the secret cannot be read and the outside path
	// cannot be written.
	if secret := os.Getenv("ANVIL_TEST_READ"); secret != "" {
		_, rerr := os.ReadFile(secret)
		werr := os.WriteFile(os.Getenv("ANVIL_TEST_WRITE"), []byte("x"), 0o644)
		if rerr == nil || werr == nil {
			os.Exit(4)
		}
		os.Exit(0)
	}
	// The sandbox test runs this binary inside the sandbox to try the network.
	if addr := os.Getenv("ANVIL_TEST_DIAL"); addr != "" {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			os.Exit(3)
		}
		_ = c.Close()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func newStore(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "anvil.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// fakeGen answers prompts from a function, records every prompt, and names a
// model.
type fakeGen struct {
	mu      sync.Mutex
	answer  func(msgs []Message) (string, error)
	prompts [][]Message
}

func (g *fakeGen) Generate(_ context.Context, msgs []Message, _ int) (string, error) {
	g.mu.Lock()
	g.prompts = append(g.prompts, msgs)
	g.mu.Unlock()
	return g.answer(msgs)
}

func (g *fakeGen) Model() string { return "fake-coder" }

func isTriage(msgs []Message) bool { return len(msgs) > 0 && msgs[0].Content == TriageSystem }

func userText(msgs []Message) string {
	var b strings.Builder
	for _, m := range msgs {
		if m.Role == "user" {
			b.WriteString(m.Content)
		}
	}
	return b.String()
}
