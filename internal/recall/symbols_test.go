package recall

import (
	"strings"
	"testing"
)

func TestPythonSymbol(t *testing.T) {
	src := strings.Split(`import os

class Config:
    """A docstring
def not_a_def():
    """

    def from_env(
        self, prefix="X",
    ) -> bool:
        value = os.environ[prefix]
        if value:
            return eval(value)

    def other(self):
        pass

def top():
    return [
        1,
    ]
x = 1`, "\n")
	for line, want := range map[int]string{
		1:  "",                // module level
		11: "Config.from_env", // the body under a split signature
		13: "Config.from_env", // nested deeper
		10: "Config.from_env", // the signature's closing line belongs to the def
		16: "Config.other",
		21: "top", // inside a bracket continuation
		22: "",
		5:  "Config", // inside a docstring, not a def
	} {
		if got := pythonSymbol(src, line); got != want {
			t.Errorf("line %d (%q): %q, want %q", line, src[line-1], got, want)
		}
	}
}

func TestGoSymbol(t *testing.T) {
	src := []byte(`package p

type T[K any] struct{}

func (t *T[K]) Method() {
	f := func() {
		_ = 1
	}
	f()
}

func Plain() {}

var x = 1
`)
	for line, want := range map[int]string{7: "T.Method", 12: "Plain", 14: "", 1: ""} {
		if got := goSymbol(src, line); got != want {
			t.Errorf("line %d: %q, want %q", line, got, want)
		}
	}
	if got := goSymbol([]byte("not go"), 1); got != "" {
		t.Errorf("an unparseable file gave %q", got)
	}
}
