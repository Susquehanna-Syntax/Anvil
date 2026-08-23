package containment

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
	"github.com/Susquehanna-Syntax/Anvil/internal/dast/target"
)

// ---------------------------------------------------------------------------
// What this file can and cannot prove
// ---------------------------------------------------------------------------
//
// This suite runs on the Windows development host, where Linux network
// namespaces and nftables DO NOT EXIST. It therefore proves the DECISION LOGIC
// -- ruleset construction, rule ordering, the deny-set relation with the
// authorization kernel's gate 10, and every branch of the canary-report
// evaluation -- and it proves that the platform path REFUSES rather than
// passing. It does NOT prove that nftables installs the ruleset, that a Linux
// kernel drops the packet, or that a real canary in a real namespace reports
// what this suite's fake canaries report.
//
// That gap is written down, not implied: internal/SKIPPED-CONTROLS.md entry U1
// names it and names exactly what would settle it.
//
// There is NO t.Skip in this file. Every test asserts something on every
// platform; the platform-dependent ones assert the platform-appropriate
// behaviour rather than vanishing.

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const (
	fixtureNetnsName  = "anvil-dast-fixture"
	fixtureInode      = uint64(4026532567)
	fixtureHostInode  = uint64(4026531840)
	fixtureCanaryPath = "/usr/lib/anvil/anvil-dast"
)

func fixtureNetns(t *testing.T) Netns {
	t.Helper()
	ns, err := NewNetns(fixtureNetnsName, fixtureInode, fixtureHostInode)
	if err != nil {
		t.Fatalf("NewNetns on the fixture must succeed: %v", err)
	}
	return ns
}

func fixturePlan(t *testing.T, scope *target.Scope, intra ...netip.Prefix) Plan {
	t.Helper()
	return Plan{
		Netns:               fixtureNetns(t),
		Manifest:            &target.Manifest{SchemaVersion: 1, Scope: scope},
		IntraTargetNetworks: intra,
	}
}

// recordedCall is one Commander invocation, kept so tests can assert on the
// argv BY IDENTITY rather than by "it contained the word nft somewhere".
type recordedCall struct {
	argv  []string
	stdin []byte
}

// fakeCommander is a scripted Commander. Every test that needs an exec goes
// through it; the production execCommander is never run by this suite.
type fakeCommander struct {
	calls []recordedCall
	// respond is consulted with the argv and returns the stdout and error.
	respond func(argv []string) ([]byte, error)
}

func (f *fakeCommander) Run(_ context.Context, argv []string, stdin []byte) ([]byte, error) {
	f.calls = append(f.calls, recordedCall{argv: append([]string(nil), argv...), stdin: stdin})
	if f.respond == nil {
		return nil, nil
	}
	return f.respond(argv)
}

// canaryStdout renders a report the way the real canary would write it. The
// JSON is written out by hand rather than by encoding the struct, so that the
// wire field NAMES are pinned here too: a renamed json tag would silently keep
// round-tripping if both halves went through the same encoder.
func canaryStdout(inode uint64, attempts ...Attempt) []byte {
	parts := make([]string, 0, len(attempts))
	for _, a := range attempts {
		parts = append(parts, fmt.Sprintf(
			`{"target":%q,"outcome":%q,"detail":%q,"failure":%q,"elapsed_ms":%d}`,
			a.Target, string(a.Outcome), a.Detail, string(a.Failure), a.ElapsedMillis))
	}
	return []byte(fmt.Sprintf(`{"netns_inode":%d,"attempts":[%s]}`+"\n",
		inode, strings.Join(parts, ",")))
}

// blockedAttempt is a legitimately blocked attempt: a no-route answer, which
// the local kernel gives affirmatively and immediately, so it carries no
// timing burden. See minSilentTimeoutEvidence for the case that does.
func blockedAttempt(tgt string) Attempt {
	return Attempt{
		Target:        tgt,
		Outcome:       AttemptOutcomeBlocked,
		Detail:        "no route",
		Failure:       DialFailureNoRoute,
		ElapsedMillis: 1,
	}
}

// timedOutAttempt is the OTHER legitimately blocked attempt: a plain nftables
// `drop` answers nothing, so the dialer's own timer fires and the attempt must
// show it waited out the declared bound.
func timedOutAttempt(tgt string) Attempt {
	return Attempt{
		Target:        tgt,
		Outcome:       AttemptOutcomeBlocked,
		Detail:        "no reply of any kind",
		Failure:       DialFailureSilentTimeout,
		ElapsedMillis: DefaultCanaryDialTimeout.Milliseconds(),
	}
}

func blockedReport() []byte {
	probes := MetadataProbes()
	return canaryStdout(fixtureInode,
		blockedAttempt(probes[0].String()),
		blockedAttempt(probes[1].String()),
	)
}

func mustErrIs(t *testing.T, err error, want error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected a refusal, got nil", what)
	}
	if !errors.Is(err, want) {
		t.Fatalf("%s: error %v does not wrap the expected sentinel", what, err)
	}
	if !errors.Is(err, ErrContainment) {
		t.Fatalf("%s: error %v does not wrap ErrContainment", what, err)
	}
}

// ---------------------------------------------------------------------------
// The platform refusal
// ---------------------------------------------------------------------------

// TestSystemCommanderRefusesOffLinux is the Windows-path guard, and it is the
// reason this package has no t.Skip. On a non-Linux host it asserts a REFUSAL;
// on Linux it asserts a Commander comes back. Either way it asserts.
func TestSystemCommanderRefusesOffLinux(t *testing.T) {
	c, err := SystemCommander()
	if runtime.GOOS == "linux" {
		if err != nil {
			t.Fatalf("on linux SystemCommander must return a Commander, got %v", err)
		}
		if c == nil {
			t.Fatal("on linux SystemCommander returned a nil Commander and a nil error")
		}
		return
	}
	if err == nil {
		t.Fatalf("on %s SystemCommander returned a Commander. A containment layer that reports "+
			"success on a platform with no network namespaces is the silent-clean failure this "+
			"package exists to prevent", runtime.GOOS)
	}
	if c != nil {
		t.Fatalf("on %s SystemCommander returned both an error and a non-nil Commander; a caller "+
			"that only checked the Commander would proceed", runtime.GOOS)
	}
	mustErrIs(t, err, ErrUnsupportedPlatform, "SystemCommander off linux")
	if !strings.Contains(err.Error(), runtime.GOOS) {
		t.Fatalf("the refusal must name the platform it refused on; got %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// The namespace handle
// ---------------------------------------------------------------------------

func TestZeroNetnsIsNeverConstructed(t *testing.T) {
	var zero Netns
	if zero.Constructed() {
		t.Fatal("the zero Netns reports Constructed(); a Go zero value must never mean permitted")
	}
	if zero.Name() != "" || zero.Inode() != 0 || zero.HostInode() != 0 {
		t.Fatalf("the zero Netns is not zero: %+v", zero)
	}
	// And every entry point must refuse it.
	if err := EvaluateCanaryReport(zero, MetadataProbes(), CanaryReport{}); err == nil {
		t.Fatal("EvaluateCanaryReport accepted a zero Netns")
	}
	if err := AssertContainment(context.Background(), &fakeCommander{}, zero, fixtureCanaryPath); err == nil {
		t.Fatal("AssertContainment accepted a zero Netns")
	}
	if _, err := BuildRuleset(Plan{Manifest: &target.Manifest{}}); err == nil {
		t.Fatal("BuildRuleset accepted a zero Netns")
	}
}

func TestNewNetnsRefusals(t *testing.T) {
	cases := []struct {
		name              string
		nsName            string
		inode, hostInode  uint64
		wantErrorContains string
	}{
		{"empty name", "", 5, 6, "is empty"},
		{"path separator", "a/b", 5, 6, "contains"},
		{"backslash", `a\b`, 5, 6, "contains"},
		{"space", "a b", 5, 6, "contains"},
		{"leading dash", "-rf", 5, 6, "starts with '-'"},
		{"newline", "a\nb", 5, 6, "contains"},
		{"nul", "a\x00b", 5, 6, "contains"},
		{"dotdot", "..", 5, 6, "contains"},
		{"too long", strings.Repeat("a", 65), 5, 6, "the limit is 64"},
		{"zero inode", "ok", 0, 6, "inode 0"},
		{"zero host inode", "ok", 5, 0, "inode is 0"},
		{"inode equals host inode", "ok", 7, 7, "HOST network namespace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ns, err := NewNetns(tc.nsName, tc.inode, tc.hostInode)
			if err == nil {
				t.Fatalf("NewNetns(%q, %d, %d) was accepted", tc.nsName, tc.inode, tc.hostInode)
			}
			if ns.Constructed() {
				t.Fatal("NewNetns returned a constructed Netns alongside an error")
			}
			mustErrIs(t, err, ErrInvalidPlan, "NewNetns")
			if !strings.Contains(err.Error(), tc.wantErrorContains) {
				t.Fatalf("refusal %q does not mention %q", err.Error(), tc.wantErrorContains)
			}
		})
	}
}

// TestNetnsNameIsAnAllowlistNotADenylist pins the DIRECTION of the check. A
// denylist of shell metacharacters loses to the first encoding nobody thought
// of; this asserts that a character simply not on the allowlist is refused,
// using one that no denylist would have bothered to list.
func TestNetnsNameIsAnAllowlistNotADenylist(t *testing.T) {
	for _, s := range []string{"anvil.dast", "anvil+dast", "anvil:dast", "anvil%20dast", "ánvil"} {
		if _, err := NewNetns(s, 5, 6); err == nil {
			t.Fatalf("NewNetns accepted %q; the name check must be an allowlist", s)
		}
	}
	for _, s := range []string{"a", "anvil-dast-0", "anvil_dast_0", strings.Repeat("a", 64)} {
		if _, err := NewNetns(s, 5, 6); err != nil {
			t.Fatalf("NewNetns refused the legitimate name %q: %v", s, err)
		}
	}
}

// ---------------------------------------------------------------------------
// The ruleset
// ---------------------------------------------------------------------------

// wantGoldenScript is the whole nft input for the fixture plan below. It is a
// GOLDEN rather than a set of substring assertions because the thing being
// pinned is the complete text an operator would read out of `nft list
// ruleset`, and a substring test cannot see a rule that was added.
const wantGoldenScript = `# Generated by internal/dast/containment. Do not edit by hand.
add table inet anvil_dast
delete table inet anvil_dast
table inet anvil_dast {
	set anvil_deny4 {
		type ipv4_addr
		flags interval
		elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4 }
	}
	set anvil_deny6 {
		type ipv6_addr
		flags interval
		elements = { ::/128, ::1/128, ::ffff:0.0.0.0/96, 64:ff9b::/96, 64:ff9b:1::/48, 2002::/16, fc00::/7, fe80::/10, ff00::/8 }
	}
	chain egress {
		type filter hook output priority filter; policy drop;
		ip daddr 169.254.169.254 drop
		ip6 daddr fd00:ec2::254 drop
		ip daddr 169.254.0.0/16 drop
		ip6 daddr fe80::/10 drop
		oifname "lo" ip daddr 127.0.0.0/8 accept
		oifname "lo" ip6 daddr ::1/128 accept
		ct state established,related accept
		ip daddr 172.18.0.0/16 accept
		ip daddr @anvil_deny4 drop
		ip6 daddr @anvil_deny6 drop
		ip daddr 203.0.113.7/32 accept
		drop
	}
	chain egress_forward {
		type filter hook forward priority filter; policy drop;
		ip daddr 169.254.169.254 drop
		ip6 daddr fd00:ec2::254 drop
		ip daddr 169.254.0.0/16 drop
		ip6 daddr fe80::/10 drop
		oifname "lo" ip daddr 127.0.0.0/8 accept
		oifname "lo" ip6 daddr ::1/128 accept
		ct state established,related accept
		ip daddr 172.18.0.0/16 accept
		ip daddr @anvil_deny4 drop
		ip6 daddr @anvil_deny6 drop
		ip daddr 203.0.113.7/32 accept
		drop
	}
}
`

func TestBuildRulesetGolden(t *testing.T) {
	p := fixturePlan(t,
		&target.Scope{AdditionalEgressAllow: []string{"203.0.113.7", "staging.example.com"}},
		netip.MustParsePrefix("172.18.0.0/16"),
	)
	rs, err := BuildRuleset(p)
	if err != nil {
		t.Fatalf("BuildRuleset: %v", err)
	}
	if rs.Script != wantGoldenScript {
		t.Fatalf("the generated ruleset drifted.\n--- want ---\n%s\n--- got ---\n%s", wantGoldenScript, rs.Script)
	}
	if len(rs.UnexpressedAllowEntries) != 1 || rs.UnexpressedAllowEntries[0] != "staging.example.com" {
		t.Fatalf("the hostname allow entry must be reported as unexpressed, got %v", rs.UnexpressedAllowEntries)
	}
	if strings.Contains(rs.Script, "staging.example.com") {
		t.Fatal("a hostname reached the nft script. nft would resolve it once at load time and pin " +
			"whatever it got, which is a TOCTOU hole")
	}
}

// TestTheRulesetHooksForwardAndNotOnlyOutput is MEDIUM 7, and it is a test
// about which PACKETS the ruleset can see rather than about what it says.
//
// nftables' `output` hook sees packets from a socket in the namespace. The
// target is not that: it is a Compose project on a bridge INSIDE the namespace,
// so its egress is RECEIVED on the bridge and FORWARDED, which is a different
// hook. provision.go's NetworkMode assertion requires exactly that arrangement.
// So an output-only ruleset constrained the canary and left the target's own
// traffic unfiltered -- while the golden test, the ordering test and the canary
// all reported the sandbox closed.
//
// Only the canary's own dials go out via `output`, which is why no existing
// test could see this: the canary is the one process in the namespace whose
// traffic the ruleset was constraining.
func TestTheRulesetHooksForwardAndNotOnlyOutput(t *testing.T) {
	rs, err := BuildRuleset(fixturePlan(t,
		&target.Scope{AdditionalEgressAllow: []string{"203.0.113.7"}},
		netip.MustParsePrefix("172.18.0.0/16"),
	))
	if err != nil {
		t.Fatalf("BuildRuleset: %v", err)
	}
	for _, want := range []string{
		"type filter hook output priority filter; policy drop;",
		"type filter hook forward priority filter; policy drop;",
	} {
		if !strings.Contains(rs.Script, want) {
			t.Fatalf("the ruleset does not install %q.\nA Compose project's egress is FORWARDED "+
				"across the bridge in this namespace; a ruleset hooked only at output sees the "+
				"canary and nothing else.\n%s", want, rs.Script)
		}
	}
	if !strings.Contains(rs.Script, "chain "+ForwardChainName+" {") {
		t.Fatalf("the forward chain %q is missing from the script:\n%s", ForwardChainName, rs.Script)
	}
}

// TestEveryHookedChainCarriesTheIdenticalRuleList: two chains built from two
// rule lists is two rulesets that can drift, and the one that drifts is the one
// nobody reads. This parses the emitted script back rather than trusting
// renderScript's loop, so a hand-edit that gave one chain a shorter list is
// caught.
func TestEveryHookedChainCarriesTheIdenticalRuleList(t *testing.T) {
	rs, err := BuildRuleset(fixturePlan(t,
		&target.Scope{AdditionalEgressAllow: []string{"203.0.113.7"}},
		netip.MustParsePrefix("172.18.0.0/16"),
	))
	if err != nil {
		t.Fatalf("BuildRuleset: %v", err)
	}
	chains := parseChains(t, rs.Script)
	hooked := hookedChains()
	if len(chains) != len(hooked) {
		t.Fatalf("the script declares %d chains and hookedChains names %d: %v",
			len(chains), len(hooked), chains)
	}
	for _, hc := range hooked {
		body, ok := chains[hc.Chain]
		if !ok {
			t.Fatalf("chain %q is named by hookedChains and absent from the script", hc.Chain)
		}
		if body.hook != hc.Hook {
			t.Fatalf("chain %q is hooked at %q, want %q", hc.Chain, body.hook, hc.Hook)
		}
		if body.policy != "drop" {
			t.Fatalf("chain %q has policy %q; every hooked chain must be default-deny",
				hc.Chain, body.policy)
		}
		if len(body.rules) != len(rs.Rules) {
			t.Fatalf("chain %q carries %d rules and Ruleset.Rules has %d:\n%v\n%v",
				hc.Chain, len(body.rules), len(rs.Rules), body.rules, rs.Rules)
		}
		for i := range rs.Rules {
			if body.rules[i] != rs.Rules[i] {
				t.Fatalf("chain %q rule %d is %q, want %q. The chains have drifted, and order "+
					"is the control", hc.Chain, i, body.rules[i], rs.Rules[i])
			}
		}
	}
}

type parsedChain struct {
	hook   string
	policy string
	rules  []string
}

// parseChains reads the emitted nft script back into chain name -> body. It is
// deliberately a separate reader from renderScript's writer: a test that asked
// the writer what it wrote would agree with itself.
func parseChains(t *testing.T, script string) map[string]parsedChain {
	t.Helper()
	out := map[string]parsedChain{}
	var cur string
	var body parsedChain
	for _, raw := range strings.Split(script, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "chain ") && strings.HasSuffix(line, "{"):
			cur = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "chain "), "{"))
			body = parsedChain{}
		case cur != "" && strings.HasPrefix(line, "type filter hook "):
			fields := strings.Fields(line)
			// type filter hook <hook> priority filter; policy <policy>;
			if len(fields) < 7 {
				t.Fatalf("chain %q has an unreadable hook line %q", cur, line)
			}
			body.hook = fields[3]
			body.policy = strings.TrimSuffix(fields[len(fields)-1], ";")
		case cur != "" && line == "}":
			out[cur] = body
			cur = ""
		case cur != "" && line != "":
			body.rules = append(body.rules, line)
		}
	}
	return out
}

// TestTheChainIsDefaultDeny pins the two statements that make it default-deny:
// the chain policy and the terminal drop.
func TestTheChainIsDefaultDeny(t *testing.T) {
	rs, err := BuildRuleset(fixturePlan(t, nil))
	if err != nil {
		t.Fatalf("BuildRuleset: %v", err)
	}
	if !strings.Contains(rs.Script, "policy drop;") {
		t.Fatal("the egress chain does not carry `policy drop`")
	}
	if len(rs.Rules) == 0 || rs.Rules[len(rs.Rules)-1] != "drop" {
		t.Fatalf("the last rule must be an explicit drop, got %v", rs.Rules)
	}
	if strings.Contains(rs.Script, "policy accept") {
		t.Fatal("the script contains `policy accept`")
	}
}

// indexOf returns the position of the first rule containing sub, or -1.
func indexOf(rules []string, sub string) int {
	for i, r := range rules {
		if strings.Contains(r, sub) {
			return i
		}
	}
	return -1
}

// TestMetadataDropsPrecedeEveryAcceptRule is an ORDER test, and order is the
// control. nftables evaluates a chain top to bottom, so a suite that only
// asserted "the drop rule is present" and "the accept rule is present" would
// pass on a ruleset that had them the wrong way round -- which is a ruleset
// where the accept wins and the metadata endpoint is reachable.
func TestMetadataDropsPrecedeEveryAcceptRule(t *testing.T) {
	p := fixturePlan(t,
		&target.Scope{AdditionalEgressAllow: []string{"203.0.113.7"}},
		netip.MustParsePrefix("172.18.0.0/16"),
	)
	rs, err := BuildRuleset(p)
	if err != nil {
		t.Fatalf("BuildRuleset: %v", err)
	}
	lastMetadataDrop := -1
	for _, probe := range MetadataProbes() {
		i := indexOf(rs.Rules, probe.Addr.String()+" drop")
		if i < 0 {
			t.Fatalf("no unconditional drop rule for %s in %v", probe.Addr, rs.Rules)
		}
		if lastMetadataDrop < i {
			lastMetadataDrop = i
		}
		// Unconditional: no interface, no conntrack state qualifier.
		if strings.Contains(rs.Rules[i], "oifname") || strings.Contains(rs.Rules[i], "ct state") {
			t.Fatalf("the metadata drop for %s is qualified (%q); a qualifier is a condition under "+
				"which the metadata endpoint is NOT dropped", probe.Addr, rs.Rules[i])
		}
	}
	firstAccept := indexOf(rs.Rules, "accept")
	if firstAccept < 0 {
		t.Fatal("this fixture is supposed to contain accept rules; it does not, so the ordering " +
			"assertion below would be vacuous")
	}
	if lastMetadataDrop >= firstAccept {
		t.Fatalf("an accept rule at index %d precedes or ties the metadata drop at index %d; "+
			"nftables would take the accept.\nrules: %v", firstAccept, lastMetadataDrop, rs.Rules)
	}
}

// TestLoopbackAcceptIsScopedToInterfaceAndPrefix stops the loopback carve-out
// from becoming a bare `oifname "lo" accept`, which would accept a packet to
// any destination that happened to be routed at lo.
func TestLoopbackAcceptIsScopedToInterfaceAndPrefix(t *testing.T) {
	rs, err := BuildRuleset(fixturePlan(t, nil))
	if err != nil {
		t.Fatalf("BuildRuleset: %v", err)
	}
	for _, r := range rs.Rules {
		if !strings.Contains(r, `oifname "lo"`) {
			continue
		}
		if !strings.Contains(r, "127.0.0.0/8") && !strings.Contains(r, "::1/128") {
			t.Fatalf("loopback rule %q accepts without pinning the destination prefix", r)
		}
	}
	if indexOf(rs.Rules, `oifname "lo" ip daddr 127.0.0.0/8 accept`) < 0 {
		t.Fatal("the IPv4 loopback accept is missing; target.checkHealthURL requires health.url to " +
			"address loopback or the Compose service name, and Docker's embedded DNS is at 127.0.0.11")
	}
	if indexOf(rs.Rules, `oifname "lo" ip6 daddr ::1/128 accept`) < 0 {
		t.Fatal("the IPv6 loopback accept is missing")
	}
}

// TestIntraTargetNetworkRefusals bounds the one deliberate hole in the deny
// set.
func TestIntraTargetNetworkRefusals(t *testing.T) {
	cases := []struct {
		name     string
		prefixes []netip.Prefix
		want     string
	}{
		{"unmasked", []netip.Prefix{netip.MustParsePrefix("172.18.1.5/16")}, "host bits set"},
		{"v4 too wide", []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, "wider than /8"},
		{"v4 slash 7", []netip.Prefix{netip.MustParsePrefix("0.0.0.0/7")}, "wider than /8"},
		{"v6 too wide", []netip.Prefix{netip.MustParsePrefix("::/0")}, "wider than /32"},
		{"v6 ula slash 7", []netip.Prefix{netip.MustParsePrefix("fc00::/7")}, "wider than /32"},
		{"covers v4 metadata", []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}, "169.254.169.254"},
		{"covers v4 metadata exactly", []netip.Prefix{netip.MustParsePrefix("169.254.169.254/32")}, "169.254.169.254"},
		{"covers v6 metadata", []netip.Prefix{netip.MustParsePrefix("fd00:ec2::/64")}, "fd00:ec2::254"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildRuleset(fixturePlan(t, nil, tc.prefixes...))
			if err == nil {
				t.Fatalf("BuildRuleset accepted intra-target network %v", tc.prefixes)
			}
			mustErrIs(t, err, ErrInvalidPlan, "BuildRuleset")
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not mention %q", err.Error(), tc.want)
			}
		})
	}

	t.Run("too many", func(t *testing.T) {
		var many []netip.Prefix
		for i := 0; i <= maxIntraTargetPrefixes; i++ {
			many = append(many, netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/16", i)))
		}
		if _, err := BuildRuleset(fixturePlan(t, nil, many...)); err == nil {
			t.Fatalf("BuildRuleset accepted %d intra-target networks", len(many))
		}
	})

	t.Run("a legitimate compose bridge is accepted", func(t *testing.T) {
		rs, err := BuildRuleset(fixturePlan(t, nil, netip.MustParsePrefix("172.18.0.0/16")))
		if err != nil {
			t.Fatalf("BuildRuleset refused a legitimate Compose bridge: %v", err)
		}
		if indexOf(rs.Rules, "ip daddr 172.18.0.0/16 accept") < 0 {
			t.Fatalf("the Compose bridge accept is missing from %v", rs.Rules)
		}
	})
}

// TestScopeEntryCoveringMetadataIsRefused pins the plan's rule that a scope
// entry grants nothing the containment layer forbids. The metadata drop sits
// above these accepts and would win anyway; refusing at build time means the
// operator hears about it instead of it quietly doing nothing.
// THE 4-IN-6 ROWS ARE THE POINT OF THIS TABLE'S SECOND HALF. The six original
// rows all spelled the metadata address the way a person would, and
// BuildRuleset ACCEPTED "::ffff:169.254.169.254/128" and emitted an accept rule
// for it -- because the refusal is netip.Prefix.Contains, and an IPv6 prefix
// does not contain an IPv4 address however identical the two destinations are.
// The doc on splitAllowEntries claimed the refusal and this table asserted it,
// and both were defeated by a spelling neither of them contained.
//
// It is the same lesson gate 8 already encodes in the authorization kernel:
// authz.Canonicalize unwraps an IPv4-mapped literal precisely so that
// "[::ffff:169.254.169.254]" and "169.254.169.254" cannot compare differently
// against gate 10's ranges. This is that rule at the network layer, and it
// reuses the same operation (netip Unmap) rather than a second one that could
// disagree with it.
func TestScopeEntryCoveringMetadataIsRefused(t *testing.T) {
	for _, entry := range []string{
		"169.254.169.254",
		"169.254.0.0/16",
		"0.0.0.0/0",
		"fd00:ec2::254",
		"fd00:ec2::/32",
		"::/0",
		// The IPv4-mapped spellings of the same three IPv4 rows.
		"::ffff:169.254.169.254",
		"::ffff:169.254.169.254/128",
		"::ffff:169.254.0.0/112",
		"::ffff:0.0.0.0/96",
	} {
		t.Run(entry, func(t *testing.T) {
			p := fixturePlan(t, &target.Scope{AdditionalEgressAllow: []string{entry}})
			_, err := BuildRuleset(p)
			if err == nil {
				t.Fatalf("BuildRuleset accepted scope entry %q", entry)
			}
			mustErrIs(t, err, ErrInvalidPlan, "BuildRuleset")
		})
	}
}

// TestAnIPv4MappedAllowEntryIsEmittedAsIPv4 is the other half of the fix: an
// entry that is LEGITIMATE in its mapped spelling must not be emitted as an
// `ip6` rule naming a mapped address, because the target's traffic to that
// destination is an ordinary IPv4 packet and an ip6 rule would never match it.
// The entry would silently do nothing under a default-drop policy -- the safe
// direction, but a silent one.
func TestAnIPv4MappedAllowEntryIsEmittedAsIPv4(t *testing.T) {
	for _, tc := range []struct{ entry, want string }{
		{"::ffff:203.0.113.7", "ip daddr 203.0.113.7/32 accept"},
		{"::ffff:203.0.113.7/128", "ip daddr 203.0.113.7/32 accept"},
		{"::ffff:203.0.113.0/120", "ip daddr 203.0.113.0/24 accept"},
	} {
		t.Run(tc.entry, func(t *testing.T) {
			rs, err := BuildRuleset(fixturePlan(t, &target.Scope{AdditionalEgressAllow: []string{tc.entry}}))
			if err != nil {
				t.Fatalf("BuildRuleset refused a legitimate mapped entry: %v", err)
			}
			if indexOf(rs.Rules, tc.want) < 0 {
				t.Fatalf("want rule %q, got %v", tc.want, rs.Rules)
			}
			if indexOf(rs.Rules, "::ffff:") >= 0 {
				t.Fatalf("a mapped address reached the ruleset: %v. An `ip6 daddr ::ffff:...` "+
					"rule never matches an IPv4 packet, so the entry would silently do nothing", rs.Rules)
			}
		})
	}
}

// TestAnIntraTargetNetworkCannotHideBehindTheMappedSpelling: the same
// canonicalization on the OTHER operator-supplied input. "::ffff:169.254.0.0/112"
// is a /16 of IPv4 link-local space wearing a /112 of IPv6, and it would have
// passed both the width bound (112 >= 32) and the metadata check.
func TestAnIntraTargetNetworkCannotHideBehindTheMappedSpelling(t *testing.T) {
	for _, tc := range []struct{ name, cidr, want string }{
		{"metadata in mapped clothing", "::ffff:169.254.0.0/112", "metadata address"},
		{"the whole of IPv4 as a /96", "::ffff:0.0.0.0/96", "wider than /8"},
		{"a legitimate bridge, mapped", "::ffff:172.18.0.0/112", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rs, err := BuildRuleset(fixturePlan(t, nil, netip.MustParsePrefix(tc.cidr)))
			if tc.want == "" {
				if err != nil {
					t.Fatalf("BuildRuleset refused a legitimate mapped bridge: %v", err)
				}
				if indexOf(rs.Rules, "ip daddr 172.18.0.0/16 accept") < 0 {
					t.Fatalf("the mapped bridge was not emitted as IPv4: %v", rs.Rules)
				}
				return
			}
			if err == nil {
				t.Fatalf("BuildRuleset accepted intra-target network %q", tc.cidr)
			}
			mustErrIs(t, err, ErrInvalidPlan, "BuildRuleset")
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

func TestScopeEntryWithHostBitsIsRefused(t *testing.T) {
	p := fixturePlan(t, &target.Scope{AdditionalEgressAllow: []string{"203.0.113.7/24"}})
	if _, err := BuildRuleset(p); err == nil {
		t.Fatal("BuildRuleset accepted an unmasked scope prefix; what it allows is ambiguous")
	}
}

// ---------------------------------------------------------------------------
// The relation with gate 10
// ---------------------------------------------------------------------------

// TestDenySetIsNeverWeakerThanGateTenAtSixteenBitGranularity is the RELATION
// pin, not a value pin.
//
// The authorization kernel's gate 10 owns the reserved-range denylist at the
// HTTP layer; this package owns it at the network layer. Both lists were
// written from the same source, and the failure that matters is DRIFT: a range
// added to gate 10 and not here leaves a hole in the sandbox that the HTTP
// layer would refuse but the network would carry.
//
// So instead of comparing two hand-written tables -- which would just be the
// same drift with extra steps -- this sweeps addresses and asserts the
// implication
//
//	authz.AddressIsReserved(a) => DeniedByRuleset(a)
//
// The name states the granularity because the claim has to be exactly as
// strong as the evidence: the sweep visits two addresses per IPv4 /16 and one
// per /24 inside the three /8s that hold gate 10's narrow ranges, so it catches
// any IPv4 range of /16 or wider anywhere, and any /24 or wider in those three
// /8s. A future gate-10 range narrower than that, outside those /8s, would not
// be caught by this test -- it would be caught by the explicit-literal test
// below only if someone added the literal.
func TestDenySetIsNeverWeakerThanGateTenAtSixteenBitGranularity(t *testing.T) {
	checked, reserved := 0, 0
	check := func(a netip.Addr) {
		checked++
		why, isReserved := authz.AddressIsReserved(a)
		if !isReserved {
			return
		}
		reserved++
		if !DeniedByRuleset(a) {
			t.Fatalf("gate 10 calls %s reserved (%s) but the containment deny set does not drop "+
				"it. The two layers have drifted and the sandbox has a hole the HTTP layer would "+
				"have refused", a, why)
		}
		if !GateTenAgreesWith(a) {
			t.Fatalf("GateTenAgreesWith(%s) is false while DeniedByRuleset is true; the two "+
				"helpers disagree", a)
		}
	}

	// Two per IPv4 /16: the first and last usable-looking host in it.
	for hi := 0; hi < 256; hi++ {
		for lo := 0; lo < 256; lo++ {
			check(netip.AddrFrom4([4]byte{byte(hi), byte(lo), 0, 1}))
			check(netip.AddrFrom4([4]byte{byte(hi), byte(lo), 255, 254}))
		}
	}
	// One per /24 inside the /8s holding gate 10's narrow ranges: 192.0.0.0/24
	// (RFC 6890), 198.18.0.0/15 (RFC 2544), 100.64.0.0/10 (RFC 6598).
	for _, first := range []byte{100, 192, 198} {
		for b := 0; b < 256; b++ {
			for c := 0; c < 256; c++ {
				check(netip.AddrFrom4([4]byte{first, byte(b), byte(c), 1}))
			}
		}
	}
	// IPv6 at /16 granularity, plus the interesting narrow ones by hand.
	for hi := 0; hi < 256; hi++ {
		for lo := 0; lo < 256; lo++ {
			var a [16]byte
			a[0], a[1] = byte(hi), byte(lo)
			a[15] = 1
			check(netip.AddrFrom16(a))
		}
	}
	for _, s := range []string{
		"::", "::1", "64:ff9b::1.2.3.4", "64:ff9b:1::1", "2002:c000:204::1",
		"fc00::1", "fd00::1", "fd00:ec2::254", "fe80::1", "ff02::1",
	} {
		check(netip.MustParseAddr(s))
	}

	// THE GENERATOR'S OWN BLIND SPOT, AND WHY IT IS FIXED HERE.
	//
	// Every address above comes from AddrFrom4 / AddrFrom16 / ParseAddr on a
	// zone-free literal, so not one of them can carry an IPv6 ZONE -- and
	// netip.Prefix.Contains returns false for ANY zoned address, because
	// prefixes cannot carry zones. So DeniedByRuleset walked the whole deny
	// set and answered "not denied" for fe80::1%eth0, ::1%lo and
	// fd00:ec2::254%eth0, and this relation test could not construct the
	// input that broke the relation it exists to pin.
	//
	// A relation test whose generator cannot reach the failing input is a
	// test that will keep passing through the bug.
	zoned := 0
	for _, s := range []string{
		"fe80::1", "::1", "fd00:ec2::254", "ff02::1", "64:ff9b::1.2.3.4",
		"2002:c000:204::1", "fc00::1", "::",
	} {
		for _, zone := range []string{"eth0", "lo", "1", "%"} {
			zoned++
			check(netip.MustParseAddr(s).WithZone(zone))
		}
	}
	// And the IPv4-mapped spelling, on both the reserved and the routable
	// side, so the unmap is shown to be neither absent nor over-eager.
	for _, s := range []string{
		"::ffff:169.254.169.254", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
		"::ffff:192.168.1.1", "::ffff:0.0.0.0", "::ffff:255.255.255.255",
	} {
		check(netip.MustParseAddr(s))
	}
	if zoned == 0 {
		t.Fatal("the zoned sweep visited nothing")
	}

	if checked < 100000 {
		t.Fatalf("the sweep only visited %d addresses; it is not covering what its name claims", checked)
	}
	if reserved == 0 {
		t.Fatalf("the sweep visited %d addresses and found NONE reserved. The implication it "+
			"asserts is vacuously true and this test is proving nothing", checked)
	}
	t.Logf("swept %d addresses; %d were reserved by gate 10 and every one is dropped by the "+
		"containment ruleset", checked, reserved)
}

// TestEveryPlanNamedRangeIsInTheDenySet pins the literals plan/50-dast.md D.11
// enumerates by name, so that a refactor of the sweep above cannot quietly
// drop them.
func TestEveryPlanNamedRangeIsInTheDenySet(t *testing.T) {
	// plan/50-dast.md D.11, verbatim: 169.254.0.0/16, fd00:ec2::254, and the
	// OWASP SSRF block list 127.0.0.0/8, 0.0.0.0/8, ::1/128, 10.0.0.0/8,
	// 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, ff00::/8.
	for _, s := range []string{
		"169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8", "10.0.0.0/8",
		"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4",
		"::1/128", "ff00::/8",
	} {
		pfx := netip.MustParsePrefix(s)
		if !DeniedByRuleset(pfx.Addr()) {
			t.Fatalf("plan/50-dast.md D.11 names %s and the deny set does not cover it", s)
		}
	}
	for _, s := range []string{"169.254.169.254", "fd00:ec2::254"} {
		if !DeniedByRuleset(netip.MustParseAddr(s)) {
			t.Fatalf("plan/50-dast.md D.11 names %s and the deny set does not cover it", s)
		}
	}
}

func TestDeniedByRulesetTreatsAnInvalidAddressAsDenied(t *testing.T) {
	var zero netip.Addr
	if !DeniedByRuleset(zero) {
		t.Fatal("the zero netip.Addr is not denied. A Go zero value must never mean permitted")
	}
	if !GateTenAgreesWith(zero) {
		t.Fatal("GateTenAgreesWith is false for the zero address")
	}
}

func TestDeniedByRulesetSeesThroughIPv4MappedIPv6(t *testing.T) {
	// "::ffff:169.254.169.254" and "169.254.169.254" are the same destination.
	// A deny set that compared the v6 form against the v6 prefixes only would
	// let the mapped spelling through.
	mapped := netip.MustParseAddr("::ffff:169.254.169.254")
	if !DeniedByRuleset(mapped) {
		t.Fatal("the IPv4-mapped spelling of the metadata address is not denied")
	}
	if DeniedByRuleset(netip.MustParseAddr("::ffff:203.0.113.7")) {
		t.Fatal("the IPv4-mapped spelling of a routable address is denied; the unmap is too eager")
	}
}

// TestDeniedByRulesetSeesThroughAZone is HIGH 3.
//
// netip.Prefix.Contains returns FALSE for any address carrying an IPv6 zone --
// prefixes strip zones, so netip refuses the comparison rather than answering
// it. DeniedByRuleset walked the entire deny set for "fe80::1%eth0", matched
// nothing, and reported NOT DENIED. Gate 10 called the same address reserved,
// so the two layers disagreed in the fail-open direction, and the relation test
// could not see it because its generator produces no zoned addresses.
//
// Stripping the zone is what the ruleset itself does: nftables has no zone
// concept, a zone never appears on the wire, and the packet the kernel matches
// carries only the address bytes. So the zone-free form IS what the ruleset
// sees.
func TestDeniedByRulesetSeesThroughAZone(t *testing.T) {
	for _, s := range []string{
		"fe80::1", "::1", "fd00:ec2::254", "ff02::1", "fc00::1",
		"64:ff9b::1.2.3.4", "2002:c000:204::1", "::",
	} {
		plain := netip.MustParseAddr(s)
		if !DeniedByRuleset(plain) {
			t.Fatalf("fixture problem: %s is not in the deny set at all", s)
		}
		for _, zone := range []string{"eth0", "lo", "1"} {
			z := plain.WithZone(zone)
			if !DeniedByRuleset(z) {
				t.Fatalf("DeniedByRuleset(%s) is false while DeniedByRuleset(%s) is true. A zone "+
					"is a local scope identifier that never reaches the wire; the ruleset would "+
					"drop this packet and the predicate that models the ruleset says it would not", z, plain)
			}
			if !GateTenAgreesWith(z) {
				t.Fatalf("GateTenAgreesWith(%s) is false", z)
			}
		}
	}
	// The unmap must not become over-eager under a zone either: a routable
	// address is still routable with a zone on it.
	for _, s := range []string{"2001:db8::1", "2606:4700::1111"} {
		z := netip.MustParseAddr(s).WithZone("eth0")
		if DeniedByRuleset(z) {
			t.Fatalf("DeniedByRuleset(%s) is true for a routable address; stripping the zone "+
				"must not change which range the address is in", z)
		}
	}
}

// TestGateTenHasAZoneBlindSpotThisPackageCanonicalizesAround pins a MEASURED
// property of a package this packet does not write.
//
// authz.AddressIsReserved walks netip prefixes and then falls back to the Go
// runtime's classification. The prefix walk misses every zoned address (see
// above); the runtime fallback covers loopback, private, link-local, multicast
// and unspecified but NOT the NAT64, 6to4 and unspecified-with-zone cases. So
// gate 10 itself reports reserved=false for three spellings it reports
// reserved=true for without the zone.
//
// That is a finding in internal/dast/authz, which is outside this packet's
// write scope. It is REPORTED to the orchestrator, and it is pinned here so
// the report can be checked rather than believed -- and so that if authz is
// fixed, this test fails and the report gets retired instead of rotting.
//
// GateTenAgreesWith canonicalizes before asking, so the containment layer is
// unaffected either way; the assertions below prove that too.
func TestGateTenHasAZoneBlindSpotThisPackageCanonicalizesAround(t *testing.T) {
	blind := []string{"64:ff9b::1.2.3.4", "2002:c000:204::1", "::"}
	for _, s := range blind {
		plain := netip.MustParseAddr(s)
		if _, reserved := authz.AddressIsReserved(plain); !reserved {
			t.Fatalf("fixture problem: gate 10 does not consider %s reserved", s)
		}
		z := plain.WithZone("eth0")
		if _, reserved := authz.AddressIsReserved(z); reserved {
			t.Fatalf("authz.AddressIsReserved(%s) now reports reserved. The blind spot this "+
				"package canonicalizes around has been fixed upstream -- retire the note on "+
				"GateTenAgreesWith and the entry in the orchestrator report, then delete this "+
				"test", z)
		}
		// The containment layer is unaffected, in BOTH directions.
		if !DeniedByRuleset(z) {
			t.Fatalf("DeniedByRuleset(%s) is false", z)
		}
		if !GateTenAgreesWith(z) {
			t.Fatalf("GateTenAgreesWith(%s) is false; it must canonicalize before asking gate 10", z)
		}
	}
	// The addresses where the runtime fallback DOES cover the zone, so the
	// blind spot above is shown to be specific rather than universal.
	for _, s := range []string{"fe80::1", "::1", "fd00:ec2::254", "ff02::1"} {
		z := netip.MustParseAddr(s).WithZone("eth0")
		if _, reserved := authz.AddressIsReserved(z); !reserved {
			t.Fatalf("authz.AddressIsReserved(%s) reports not-reserved; the blind spot is wider "+
				"than this test records and the note on GateTenAgreesWith understates it", z)
		}
	}
}

func TestGateTenAgreesWithIsTrueForRoutableAddresses(t *testing.T) {
	for _, s := range []string{"203.0.113.7", "8.8.8.8", "2001:db8::1"} {
		a := netip.MustParseAddr(s)
		if _, reserved := authz.AddressIsReserved(a); reserved {
			t.Fatalf("fixture problem: gate 10 considers %s reserved", s)
		}
		if !GateTenAgreesWith(a) {
			t.Fatalf("GateTenAgreesWith(%s) is false for an address gate 10 permits", s)
		}
	}
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

func TestSetupNetnsRunsNftInsideTheNamespaceWithTheScriptOnStdin(t *testing.T) {
	p := fixturePlan(t, nil, netip.MustParsePrefix("172.18.0.0/16"))
	rs, err := BuildRuleset(p)
	if err != nil {
		t.Fatalf("BuildRuleset: %v", err)
	}
	f := &fakeCommander{}
	if err := SetupNetns(context.Background(), f, p); err != nil {
		t.Fatalf("SetupNetns: %v", err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("expected exactly one command, got %d: %+v", len(f.calls), f.calls)
	}
	want := []string{"ip", "netns", "exec", fixtureNetnsName, "nft", "-f", "-"}
	got := f.calls[0].argv
	if len(got) != len(want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
	if string(f.calls[0].stdin) != rs.Script {
		t.Fatalf("the script was not delivered on stdin.\ngot:  %q\nwant: %q", f.calls[0].stdin, rs.Script)
	}
}

func TestSetupNetnsPropagatesANftFailure(t *testing.T) {
	f := &fakeCommander{respond: func([]string) ([]byte, error) {
		return nil, errors.New("nft: Error: Could not process rule: Operation not permitted")
	}}
	err := SetupNetns(context.Background(), f, fixturePlan(t, nil))
	if err == nil {
		t.Fatal("SetupNetns returned nil after nft failed")
	}
	if !errors.Is(err, ErrContainment) {
		t.Fatalf("error %v does not wrap ErrContainment", err)
	}
}

func TestSetupNetnsRefusesANilCommander(t *testing.T) {
	if err := SetupNetns(context.Background(), nil, fixturePlan(t, nil)); err == nil {
		t.Fatal("SetupNetns with a nil Commander returned nil")
	}
}

func TestReadNetnsInodeStatsTheFileDirectlyAndNotThroughIpNetnsExec(t *testing.T) {
	f := &fakeCommander{respond: func([]string) ([]byte, error) { return []byte("4026532567\n"), nil }}
	got, err := ReadNetnsInode(context.Background(), f, fixtureNetnsName)
	if err != nil {
		t.Fatalf("ReadNetnsInode: %v", err)
	}
	if got != fixtureInode {
		t.Fatalf("inode = %d, want %d", got, fixtureInode)
	}
	argv := f.calls[0].argv
	// THE POINT OF THIS TEST. If this read went through `ip netns exec`, then
	// an `ip netns exec` that silently failed to switch namespaces would
	// produce the same wrong inode here AND in the canary, and the positive
	// control would compare a wrong value against itself and agree.
	if argv[0] == "ip" {
		t.Fatalf("ReadNetnsInode went through %v. A positive control that shares a failure mode "+
			"with the thing it controls is not a control", argv)
	}
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, NetnsRunDir+"/"+fixtureNetnsName) {
		t.Fatalf("ReadNetnsInode did not stat the namespace file: %v", argv)
	}
}

func TestReadNetnsInodeRefusesJunk(t *testing.T) {
	for _, out := range []string{"", "\n", "not-a-number", "0", "-1", "18446744073709551616"} {
		t.Run(fmt.Sprintf("%q", out), func(t *testing.T) {
			f := &fakeCommander{respond: func([]string) ([]byte, error) { return []byte(out), nil }}
			if _, err := ReadNetnsInode(context.Background(), f, fixtureNetnsName); err == nil {
				t.Fatalf("ReadNetnsInode accepted stat output %q", out)
			}
		})
	}
}

func TestReadHostNetnsInodeParsesTheReadlinkForm(t *testing.T) {
	f := &fakeCommander{respond: func([]string) ([]byte, error) { return []byte("net:[4026531840]\n"), nil }}
	got, err := ReadHostNetnsInode(context.Background(), f)
	if err != nil {
		t.Fatalf("ReadHostNetnsInode: %v", err)
	}
	if got != fixtureHostInode {
		t.Fatalf("inode = %d, want %d", got, fixtureHostInode)
	}
	for _, bad := range []string{"", "4026531840", "net:[]", "net:[abc]", "net:[0]", "mnt:[4026531840]", "net:[1]x"} {
		f := &fakeCommander{respond: func([]string) ([]byte, error) { return []byte(bad), nil }}
		if _, err := ReadHostNetnsInode(context.Background(), f); err == nil {
			t.Fatalf("ReadHostNetnsInode accepted readlink output %q", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// The assertion probe -- the gate
// ---------------------------------------------------------------------------

func TestEvaluateCanaryReportAcceptsAFullyBlockedReport(t *testing.T) {
	ns := fixtureNetns(t)
	probes := MetadataProbes()
	rep := CanaryReport{
		NetnsInode: fixtureInode,
		Attempts: []Attempt{
			blockedAttempt(probes[0].String()),
			blockedAttempt(probes[1].String()),
		},
	}
	if err := EvaluateCanaryReport(ns, probes, rep); err != nil {
		t.Fatalf("a fully blocked report from the right namespace was refused: %v", err)
	}
	// And the order of the attempts must not matter -- matching is by
	// identity, not by position.
	rep.Attempts[0], rep.Attempts[1] = rep.Attempts[1], rep.Attempts[0]
	if err := EvaluateCanaryReport(ns, probes, rep); err != nil {
		t.Fatalf("the same report with the attempts reordered was refused: %v", err)
	}

	// The other blocked shape: a silent timeout that waited out its budget.
	// It has to be here as well as in the refusal table, or the timing rule
	// below would be passing because it refuses every silent timeout.
	timed := CanaryReport{
		NetnsInode: fixtureInode,
		Attempts: []Attempt{
			timedOutAttempt(probes[0].String()),
			timedOutAttempt(probes[1].String()),
		},
	}
	if err := EvaluateCanaryReport(ns, probes, timed); err != nil {
		t.Fatalf("a silent-timeout report that waited out the declared %s was refused: %v",
			DefaultCanaryDialTimeout, err)
	}
	// And a policy reject, which is affirmative and instantaneous.
	rejected := CanaryReport{
		NetnsInode: fixtureInode,
		Attempts: []Attempt{
			{Target: probes[0].String(), Outcome: AttemptOutcomeBlocked, Failure: DialFailurePolicyRejected, ElapsedMillis: 0},
			{Target: probes[1].String(), Outcome: AttemptOutcomeBlocked, Failure: DialFailurePolicyRejected, ElapsedMillis: 0},
		},
	}
	if err := EvaluateCanaryReport(ns, probes, rejected); err != nil {
		t.Fatalf("an instantaneous EPERM reject was refused; the timing floor must apply to a "+
			"silent timeout only, because an affirmative kernel answer is correctly immediate: %v", err)
	}
}

// TestASilentTimeoutMustHaveWaitedOutItsBudget is MEDIUM 6, and it is the
// assertion the package's safety argument rested on and did not make.
//
// Classifying DialFailureSilentTimeout as BLOCKED is sound only because a
// REACHABLE metadata endpoint is link-local and answers in well under a
// millisecond, so an attempt that waited the full DefaultCanaryDialTimeout and
// heard nothing has genuinely heard nothing. Nothing enforced or observed that
// timeout: a ConnectProbe with a 50ms dialer -- a plausible choice for a probe
// that expects to be blocked -- would have reported "silent timeout" for every
// probe, every probe would have been read as "blocked", and the whole
// containment gate would have been a green function that could not fail.
func TestASilentTimeoutMustHaveWaitedOutItsBudget(t *testing.T) {
	ns := fixtureNetns(t)
	probes := MetadataProbes()
	v4, v6 := probes[0].String(), probes[1].String()

	// THE CRITIC'S SCENARIO, EXACTLY: a probe built with a 50ms dialer.
	fast := func(tgt string) Attempt {
		a := timedOutAttempt(tgt)
		a.ElapsedMillis = 50
		return a
	}
	err := EvaluateCanaryReport(ns, probes, CanaryReport{
		NetnsInode: fixtureInode,
		Attempts:   []Attempt{fast(v4), fast(v6)},
	})
	if err == nil {
		t.Fatal("a report whose every silent timeout gave up after 50ms was accepted. The 2s " +
			"bound is the entire reason a silent timeout counts as blocked; unenforced, this " +
			"assertion cannot fail")
	}
	mustErrIs(t, err, ErrNotContained, "50ms silent timeout")
	if !strings.Contains(err.Error(), "silent timeout after 50 ms") {
		t.Fatalf("the refusal does not name the timing it refused on: %v", err)
	}

	// The boundary, both sides of it, so the floor is pinned and not merely
	// present.
	floor := minSilentTimeoutEvidence().Milliseconds()
	atFloor := timedOutAttempt(v4)
	atFloor.ElapsedMillis = floor
	justUnder := timedOutAttempt(v4)
	justUnder.ElapsedMillis = floor - 1

	if err := EvaluateCanaryReport(ns, probes, CanaryReport{
		NetnsInode: fixtureInode,
		Attempts:   []Attempt{atFloor, timedOutAttempt(v6)},
	}); err != nil {
		t.Fatalf("an attempt exactly at the %d ms floor was refused: %v", floor, err)
	}
	if err := EvaluateCanaryReport(ns, probes, CanaryReport{
		NetnsInode: fixtureInode,
		Attempts:   []Attempt{justUnder, timedOutAttempt(v6)},
	}); err == nil {
		t.Fatalf("an attempt one millisecond under the %d ms floor was accepted", floor)
	}

	// The floor must be a real bound, not a formality that admits anything.
	if floor <= 0 {
		t.Fatalf("minSilentTimeoutEvidence is %d ms; a non-positive floor admits every probe "+
			"and this whole test is a no-op", floor)
	}
	if floor >= DefaultCanaryDialTimeout.Milliseconds()+1 {
		t.Fatalf("minSilentTimeoutEvidence (%d ms) is above the declared bound (%d ms); no "+
			"honest probe could ever satisfy it", floor, DefaultCanaryDialTimeout.Milliseconds())
	}
	t.Logf("silent-timeout evidence floor: %d ms against a declared %s bound (tolerance %s)",
		floor, DefaultCanaryDialTimeout, canaryTimingTolerance)
}

// TestTheReportsTwoHalvesMustAgree is RULE 7. The canary reports both the raw
// DialFailure and the AttemptOutcome derived from it; this side re-derives the
// outcome and refuses a disagreement, so a canary that classified a TCP reset
// as "blocked" cannot have its verdict taken at face value.
func TestTheReportsTwoHalvesMustAgree(t *testing.T) {
	ns := fixtureNetns(t)
	probes := MetadataProbes()
	v4, v6 := probes[0].String(), probes[1].String()

	cases := []struct {
		name string
		bad  Attempt
		want string
	}{
		{
			name: "a reset dressed up as blocked",
			bad:  Attempt{Target: v4, Outcome: AttemptOutcomeBlocked, Failure: DialFailureReset, ElapsedMillis: 1},
			want: `reports outcome "blocked" for failure reason "reset"`,
		},
		{
			name: "blocked with no reason at all",
			bad:  Attempt{Target: v4, Outcome: AttemptOutcomeBlocked, ElapsedMillis: 1},
			want: `for failure reason ""`,
		},
		{
			name: "blocked for a reason this build does not know",
			bad:  Attempt{Target: v4, Outcome: AttemptOutcomeBlocked, Failure: DialFailure("firewalled"), ElapsedMillis: 1},
			want: `failure reason "firewalled"`,
		},
		{
			name: "a cancelled attempt called blocked",
			bad:  Attempt{Target: v4, Outcome: AttemptOutcomeBlocked, Failure: DialFailureCancelled, ElapsedMillis: 1},
			want: `failure reason "cancelled"`,
		},
		{
			name: "an elapsed time that is not a measurement",
			bad:  Attempt{Target: v4, Outcome: AttemptOutcomeBlocked, Failure: DialFailureNoRoute, ElapsedMillis: -1},
			want: "negative duration is not a measurement",
		},
		{
			name: "an elapsed time far outside the declared bound",
			bad:  Attempt{Target: v4, Outcome: AttemptOutcomeBlocked, Failure: DialFailureNoRoute, ElapsedMillis: maxCanaryAttemptMillis + 1},
			want: "did not honour anything like it",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := EvaluateCanaryReport(ns, probes, CanaryReport{
				NetnsInode: fixtureInode,
				Attempts:   []Attempt{tc.bad, blockedAttempt(v6)},
			})
			if err == nil {
				t.Fatalf("EvaluateCanaryReport accepted %+v", tc.bad)
			}
			mustErrIs(t, err, ErrNotContained, "EvaluateCanaryReport")
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

// TestReachableIsDecidedBeforeTheEvidenceChecks pins the ORDER inside
// EvaluateCanaryReport. A reachable attempt carries no DialFailure by
// construction, so an agreement check running first would refuse it as a schema
// problem -- still an abort, but with the wrong message. The one message in
// this package that has to be readable is the one saying cloud metadata is
// reachable.
func TestReachableIsDecidedBeforeTheEvidenceChecks(t *testing.T) {
	ns := fixtureNetns(t)
	probes := MetadataProbes()
	v4, v6 := probes[0].String(), probes[1].String()
	err := EvaluateCanaryReport(ns, probes, CanaryReport{
		NetnsInode: fixtureInode,
		Attempts: []Attempt{
			// No Failure, no ElapsedMillis: exactly what RunCanary emits on a
			// completed handshake.
			{Target: v4, Outcome: AttemptOutcomeReachable, Detail: "the TCP handshake completed"},
			blockedAttempt(v6),
		},
	})
	if err == nil {
		t.Fatal("a reachable metadata endpoint was accepted")
	}
	if !strings.Contains(err.Error(), "THE SANDBOX CAN REACH") {
		t.Fatalf("the abort for a reachable endpoint was reported as something else: %v", err)
	}
	if strings.Contains(err.Error(), "two halves disagree") {
		t.Fatalf("the schema check ran ahead of the reachability check and buried it: %v", err)
	}
}

// sleepingProbe is a ConnectProbe that takes a measurable amount of time and
// holds no socket. It exists so the timing field can be shown to be a
// MEASUREMENT taken around the call rather than a number the probe supplied.
type sleepingProbe struct {
	sleep   time.Duration
	failure DialFailure
}

func (p sleepingProbe) Attempt(_ context.Context, _, _ string) (bool, DialFailure, string) {
	if p.sleep > 0 {
		time.Sleep(p.sleep)
	}
	return false, p.failure, "stub"
}

// TestRunCanaryTimesEveryAttempt: the elapsed figure has to come from a
// measurement around the ConnectProbe call, not from the probe's own claim.
func TestRunCanaryTimesEveryAttempt(t *testing.T) {
	const sleep = 40 * time.Millisecond
	rep := RunCanary(context.Background(), sleepingProbe{sleep: sleep, failure: DialFailureNoRoute},
		fixtureInode, MetadataProbes())
	if len(rep.Attempts) != 2 {
		t.Fatalf("RunCanary produced %d attempts, want 2", len(rep.Attempts))
	}
	for _, a := range rep.Attempts {
		if a.ElapsedMillis < sleep.Milliseconds() {
			t.Fatalf("attempt against %s reports %d ms for a probe that slept %s; the timing is "+
				"not being measured around the call", a.Target, a.ElapsedMillis, sleep)
		}
		if a.Failure != DialFailureNoRoute {
			t.Fatalf("attempt against %s lost the raw failure reason (%q)", a.Target, string(a.Failure))
		}
	}
	// A probe that answers instantly must not be reported as having waited.
	// Without this, the assertion above would pass on an implementation that
	// simply wrote the declared timeout into the field.
	fast := RunCanary(context.Background(), sleepingProbe{failure: DialFailureNoRoute},
		fixtureInode, MetadataProbes())
	for _, a := range fast.Attempts {
		if a.ElapsedMillis >= sleep.Milliseconds() {
			t.Fatalf("an instantaneous probe was reported as %d ms elapsed; the field is not a "+
				"measurement", a.ElapsedMillis)
		}
	}
	// The round trip: what RunCanary produced must survive the wire and be
	// accepted, or the two halves of the protocol have drifted.
	parsed, err := ParseCanaryReport(canaryStdout(rep.NetnsInode, rep.Attempts...))
	if err != nil {
		t.Fatalf("a report RunCanary produced does not parse: %v", err)
	}
	if err := EvaluateCanaryReport(fixtureNetns(t), MetadataProbes(), parsed); err != nil {
		t.Fatalf("a report RunCanary produced from a no-route probe was refused: %v", err)
	}

	// AND THE END-TO-END FORM OF THE CRITIC'S SCENARIO: a real ConnectProbe
	// whose dialer gives up early, driven through RunCanary rather than
	// through a hand-built Attempt. 40ms against a 2s declared bound.
	quick := RunCanary(context.Background(), sleepingProbe{sleep: sleep, failure: DialFailureSilentTimeout},
		fixtureInode, MetadataProbes())
	if err := EvaluateCanaryReport(fixtureNetns(t), MetadataProbes(), quick); err == nil {
		t.Fatalf("a ConnectProbe that reported a silent timeout after ~%s was accepted as "+
			"evidence of containment; the declared bound is %s", sleep, DefaultCanaryDialTimeout)
	}
}

// TestEvaluateCanaryReportRefusals is the heart of the packet: every way a
// report can fail to establish containment, and the assertion that each one
// ABORTS rather than warning.
func TestEvaluateCanaryReportRefusals(t *testing.T) {
	ns := fixtureNetns(t)
	probes := MetadataProbes()
	v4, v6 := probes[0].String(), probes[1].String()
	blocked := blockedAttempt

	cases := []struct {
		name string
		want string
		rep  CanaryReport
	}{
		{
			name: "v4 metadata is reachable",
			want: "THE SANDBOX CAN REACH " + v4,
			rep: CanaryReport{NetnsInode: fixtureInode, Attempts: []Attempt{
				{Target: v4, Outcome: AttemptOutcomeReachable, Detail: "handshake completed"},
				blocked(v6),
			}},
		},
		{
			name: "v6 metadata is reachable",
			want: "THE SANDBOX CAN REACH " + v6,
			rep: CanaryReport{NetnsInode: fixtureInode, Attempts: []Attempt{
				blocked(v4),
				{Target: v6, Outcome: AttemptOutcomeReachable, Detail: "handshake completed"},
			}},
		},
		{
			name: "the v6 probe was never attempted",
			want: "no attempt against " + v6,
			rep:  CanaryReport{NetnsInode: fixtureInode, Attempts: []Attempt{blocked(v4)}},
		},
		{
			name: "no attempts at all",
			want: "no attempt against",
			rep:  CanaryReport{NetnsInode: fixtureInode},
		},
		{
			name: "a duplicate attempt makes the answer ambiguous",
			want: "2 attempts against",
			rep: CanaryReport{NetnsInode: fixtureInode, Attempts: []Attempt{
				blocked(v4), blocked(v4), blocked(v6),
			}},
		},
		{
			name: "the outcome field is absent",
			want: "carries no outcome",
			rep: CanaryReport{NetnsInode: fixtureInode, Attempts: []Attempt{
				{Target: v4}, blocked(v6),
			}},
		},
		{
			name: "the outcome is indeterminate",
			want: "Unknown is not contained",
			rep: CanaryReport{NetnsInode: fixtureInode, Attempts: []Attempt{
				{Target: v4, Outcome: AttemptOutcomeIndeterminate, Detail: "connection refused"},
				blocked(v6),
			}},
		},
		{
			name: "the outcome is a value this build does not know",
			want: "does not recognise",
			rep: CanaryReport{NetnsInode: fixtureInode, Attempts: []Attempt{
				{Target: v4, Outcome: AttemptOutcome("fine")}, blocked(v6),
			}},
		},
		{
			name: "the canary reported no namespace inode",
			want: "inode 0",
			rep:  CanaryReport{Attempts: []Attempt{blocked(v4), blocked(v6)}},
		},
		{
			name: "the canary ran in the HOST namespace",
			want: "did not switch namespaces",
			rep:  CanaryReport{NetnsInode: fixtureHostInode, Attempts: []Attempt{blocked(v4), blocked(v6)}},
		},
		{
			name: "the canary ran in some other namespace",
			want: "ran somewhere else",
			rep:  CanaryReport{NetnsInode: 999999, Attempts: []Attempt{blocked(v4), blocked(v6)}},
		},
		{
			name: "an attempt nobody asked for",
			want: "not requested",
			rep: CanaryReport{NetnsInode: fixtureInode, Attempts: []Attempt{
				blocked(v4), blocked(v6), blocked("203.0.113.7:80"),
			}},
		},
		{
			name: "a target string that is close but not equal",
			want: "no attempt against " + v4,
			rep: CanaryReport{NetnsInode: fixtureInode, Attempts: []Attempt{
				blocked("169.254.169.254:8080"), blocked(v6),
			}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := EvaluateCanaryReport(ns, probes, tc.rep)
			if err == nil {
				t.Fatalf("EvaluateCanaryReport accepted %+v", tc.rep)
			}
			mustErrIs(t, err, ErrNotContained, "EvaluateCanaryReport")
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

// TestEvaluateCanaryReportRefusesAnEmptyProbeList is the "a check that checks
// nothing always passes" guard, applied to this function's own inputs.
func TestEvaluateCanaryReportRefusesAnEmptyProbeList(t *testing.T) {
	ns := fixtureNetns(t)
	err := EvaluateCanaryReport(ns, nil, CanaryReport{NetnsInode: fixtureInode})
	if err == nil {
		t.Fatal("EvaluateCanaryReport with no probes returned nil. An assertion over an empty set " +
			"is vacuously true and would report every sandbox as contained")
	}
	mustErrIs(t, err, ErrNotContained, "EvaluateCanaryReport with no probes")
}

func TestParseCanaryReportIsStrict(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"whitespace", "   "},
		{"not json", "ok\n"},
		{"truncated", `{"netns_inode":4026532567,"attempts":[`},
		{"unknown field", `{"netns_inode":1,"attempts":[],"contained":true}`},
		{"two values", `{"netns_inode":1,"attempts":[]}{"netns_inode":2,"attempts":[]}`},
		{"array", `[]`},
		{"nft banner then json", "nft: warning\n" + `{"netns_inode":1,"attempts":[]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseCanaryReport([]byte(tc.raw)); err == nil {
				t.Fatalf("ParseCanaryReport accepted %q", tc.raw)
			}
		})
	}
	t.Run("oversized", func(t *testing.T) {
		raw := `{"netns_inode":1,"attempts":[],"pad":"` + strings.Repeat("a", maxCanaryReportBytes) + `"}`
		if _, err := ParseCanaryReport([]byte(raw)); err == nil {
			t.Fatal("ParseCanaryReport accepted an oversized report")
		}
	})
	t.Run("the real canary's output round-trips", func(t *testing.T) {
		rep, err := ParseCanaryReport(blockedReport())
		if err != nil {
			t.Fatalf("ParseCanaryReport rejected a well-formed report: %v", err)
		}
		if rep.NetnsInode != fixtureInode || len(rep.Attempts) != 2 {
			t.Fatalf("round trip lost data: %+v", rep)
		}
	})
}

func TestAssertContainmentPassesOnAFullyBlockedReport(t *testing.T) {
	f := &fakeCommander{respond: func([]string) ([]byte, error) { return blockedReport(), nil }}
	if err := AssertContainment(context.Background(), f, fixtureNetns(t), fixtureCanaryPath); err != nil {
		t.Fatalf("AssertContainment refused a fully blocked report: %v", err)
	}
	want := []string{"ip", "netns", "exec", fixtureNetnsName, fixtureCanaryPath, CanarySubcommand}
	got := f.calls[0].argv
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("canary argv = %v, want %v", got, want)
	}
}

func TestAssertContainmentRefusesWhenTheCanaryWillNotRun(t *testing.T) {
	cases := []struct {
		name string
		out  []byte
		err  error
	}{
		{"exec failed", nil, errors.New("exec: \"ip\": executable file not found in $PATH")},
		{"non-zero exit", []byte("Cannot open network namespace"), errors.New("exit status 1")},
		{"no output, no error", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeCommander{respond: func([]string) ([]byte, error) { return tc.out, tc.err }}
			err := AssertContainment(context.Background(), f, fixtureNetns(t), fixtureCanaryPath)
			if err == nil {
				t.Fatal("AssertContainment returned nil when the canary did not produce a report. " +
					"A canary that did not run is not evidence of containment")
			}
			mustErrIs(t, err, ErrNotContained, "AssertContainment")
		})
	}
}

func TestAssertContainmentRefusesANilCommanderAndAnEmptyCanaryPath(t *testing.T) {
	ns := fixtureNetns(t)
	if err := AssertContainment(context.Background(), nil, ns, fixtureCanaryPath); err == nil {
		t.Fatal("AssertContainment with a nil Commander returned nil")
	}
	f := &fakeCommander{respond: func([]string) ([]byte, error) { return blockedReport(), nil }}
	if err := AssertContainment(context.Background(), f, ns, ""); err == nil {
		t.Fatal("AssertContainment with an empty canary path returned nil")
	}
	if len(f.calls) != 0 {
		t.Fatalf("AssertContainment ran %d commands with an empty canary path", len(f.calls))
	}
}

// TestABrokenRulesetFixtureIsCaughtOnEveryOneOfTwentyRuns is the SECOND HALF of
// plan/50-dast.md D.11's stop condition, and only the second half.
//
// The stop condition, verbatim, is TWO clauses joined by a semicolon:
//
//	"Default-deny ruleset installs correctly on a real target fixture; the
//	 deliberately-broken fixture is caught by the assertion probe every time in
//	 a 20-run flake check."
//
// This test is the clause after the semicolon, and it is met. THE CLAUSE
// BEFORE IT IS NOT MET AND CANNOT BE MET ON THIS HOST: there is no real target
// fixture, no kernel, no nftables, and nothing here installs a ruleset
// anywhere. internal/SKIPPED-CONTROLS.md entry U1 is the standing record of
// that half, and a privileged Linux CI lane is what would settle it.
//
// The distinction is not pedantry. An exit criterion recorded as met when half
// of it is unexecuted is how a gap ships.
//
// The fixture is a namespace whose nftables ruleset is EMPTY -- the exact
// research-19 risk #5 shape, where the policy object exists, nothing enforces
// it, and no error is raised anywhere. In that namespace the canary's connects
// succeed, so it reports `reachable`, and the probe must abort. Twenty runs,
// twenty aborts, no exceptions.
func TestABrokenRulesetFixtureIsCaughtOnEveryOneOfTwentyRuns(t *testing.T) {
	probes := MetadataProbes()
	// The broken-fixture canary: nothing is blocked, because nothing is
	// filtering.
	brokenOutput := canaryStdout(fixtureInode,
		Attempt{Target: probes[0].String(), Outcome: AttemptOutcomeReachable, Detail: "the TCP handshake completed"},
		Attempt{Target: probes[1].String(), Outcome: AttemptOutcomeReachable, Detail: "the TCP handshake completed"},
	)
	ns := fixtureNetns(t)
	const runs = 20
	for i := 0; i < runs; i++ {
		f := &fakeCommander{respond: func([]string) ([]byte, error) { return brokenOutput, nil }}
		err := AssertContainment(context.Background(), f, ns, fixtureCanaryPath)
		if err == nil {
			t.Fatalf("run %d of %d: AssertContainment accepted a namespace with an empty ruleset, "+
				"where the canary reached cloud metadata", i+1, runs)
		}
		mustErrIs(t, err, ErrNotContained, fmt.Sprintf("run %d", i+1))
		if !strings.Contains(err.Error(), "THE SANDBOX CAN REACH") {
			t.Fatalf("run %d: the abort does not say what happened: %v", i+1, err)
		}
	}

	// The other half of the fixture: the same 20 runs against a namespace
	// whose ruleset IS installed must pass every time, so that the test above
	// is not passing because AssertContainment refuses everything.
	for i := 0; i < runs; i++ {
		f := &fakeCommander{respond: func([]string) ([]byte, error) { return blockedReport(), nil }}
		if err := AssertContainment(context.Background(), f, ns, fixtureCanaryPath); err != nil {
			t.Fatalf("run %d of %d: AssertContainment refused a correctly contained namespace: %v",
				i+1, runs, err)
		}
	}
}

// TestAssertContainmentHasNoUnconditionalSuccessPath is a source-level guard,
// and it is here because the property it pins cannot be reached by calling the
// function: "there is no branch that returns success without consulting the
// canary" is a statement about the BODY.
//
// The property: AssertContainment contains ZERO `return nil` statements. Every
// exit is either a refusal or the verdict of EvaluateCanaryReport. A future
// edit that added a fast path, a cache, a "fast scan mode" bypass or a
// platform shortcut would have to add a `return nil` to do it, and this fails.
func TestAssertContainmentHasNoUnconditionalSuccessPath(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "netns.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing netns.go: %v", err)
	}
	var fn *ast.FuncDecl
	for _, d := range file.Decls {
		if f, ok := d.(*ast.FuncDecl); ok && f.Recv == nil && f.Name.Name == "AssertContainment" {
			fn = f
			break
		}
	}
	if fn == nil {
		t.Fatal("AssertContainment was not found in netns.go; this guard has lost its subject")
	}
	bare := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return true
		}
		if id, ok := ret.Results[0].(*ast.Ident); ok && id.Name == "nil" {
			bare++
			t.Errorf("AssertContainment has a `return nil` at %s. Every success must be the "+
				"verdict of EvaluateCanaryReport, never a branch that decided on its own",
				fset.Position(ret.Pos()))
		}
		return true
	})
	if bare == 0 {
		t.Log("AssertContainment has no unconditional success path")
	}
}

// ---------------------------------------------------------------------------
// The canary side
// ---------------------------------------------------------------------------

// stubProbe answers per address so RunCanary can be exercised without a
// network -- and, more to the point, without this test file constructing a
// socket, which gate 3 refuses inside internal/dast just as firmly for a test
// as for production code.
type stubProbe struct {
	// connected names the addresses whose handshake completes.
	connected map[string]bool
	// failure names the reason reported for the rest.
	failure map[string]DialFailure
}

func (p stubProbe) Attempt(_ context.Context, _, address string) (bool, DialFailure, string) {
	if p.connected[address] {
		return true, DialFailureUnset, ""
	}
	return false, p.failure[address], "stub"
}

func TestRunCanaryClassifiesEachProbeIndependently(t *testing.T) {
	probes := MetadataProbes()
	d := stubProbe{
		// v4 answers -> reachable. v6 is dropped silently -> blocked.
		connected: map[string]bool{probes[0].String(): true},
		failure:   map[string]DialFailure{probes[1].String(): DialFailureSilentTimeout},
	}
	rep := RunCanary(context.Background(), d, fixtureInode, probes)
	if rep.NetnsInode != fixtureInode {
		t.Fatalf("the canary lost its inode: %+v", rep)
	}
	if len(rep.Attempts) != len(probes) {
		t.Fatalf("expected %d attempts, got %+v", len(probes), rep.Attempts)
	}
	if rep.Attempts[0].Outcome != AttemptOutcomeReachable {
		t.Fatalf("a completed handshake was not reported as reachable: %+v", rep.Attempts[0])
	}
	if rep.Attempts[1].Outcome != AttemptOutcomeBlocked {
		t.Fatalf("a silent timeout was not reported as blocked: %+v", rep.Attempts[1])
	}
	// And the whole report must abort, because one probe got through.
	if err := EvaluateCanaryReport(fixtureNetns(t), probes, rep); err == nil {
		t.Fatal("a report with one reachable probe was accepted")
	}
}

func TestRunCanaryUsesTheRightAddressFamilyPerProbe(t *testing.T) {
	var seen []string
	d := recordingProbe{onAttempt: func(network, address string) { seen = append(seen, network+" "+address) }}
	RunCanary(context.Background(), d, fixtureInode, MetadataProbes())
	want := []string{"tcp4 169.254.169.254:80", "tcp6 [fd00:ec2::254]:80"}
	if len(seen) != len(want) {
		t.Fatalf("dials = %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			// "tcp" would let the stack choose a family, and a probe that
			// silently fell back would report blocked for a family it never
			// tried.
			t.Fatalf("dial %d = %q, want %q", i, seen[i], want[i])
		}
	}
}

type recordingProbe struct{ onAttempt func(network, address string) }

func (p recordingProbe) Attempt(_ context.Context, network, address string) (bool, DialFailure, string) {
	p.onAttempt(network, address)
	return false, DialFailureSilentTimeout, ""
}

// TestClassifyDialFailureTable pins the MAPPING from a named failure reason to
// a verdict. What it does not prove -- stated so the claim matches the
// evidence -- is that a Linux kernel delivers the errno a ConnectProbe would
// turn into each of these names. That mapping lives with the implementation,
// which holds the socket; nothing on a Windows host can prove it. See
// internal/SKIPPED-CONTROLS.md U1.
func TestClassifyDialFailureTable(t *testing.T) {
	cases := []struct {
		f    DialFailure
		want AttemptOutcome
	}{
		{DialFailurePolicyRejected, AttemptOutcomeBlocked},
		{DialFailureNoRoute, AttemptOutcomeBlocked},
		{DialFailureSilentTimeout, AttemptOutcomeBlocked},
		{DialFailureReset, AttemptOutcomeIndeterminate},
		{DialFailureCancelled, AttemptOutcomeIndeterminate},
		{DialFailureUnclassified, AttemptOutcomeIndeterminate},
		{DialFailureUnset, AttemptOutcomeIndeterminate},
		{DialFailure("blocked"), AttemptOutcomeIndeterminate},
		{DialFailure("ok"), AttemptOutcomeIndeterminate},
		{DialFailure("reachable"), AttemptOutcomeIndeterminate},
	}
	for _, tc := range cases {
		t.Run(string(tc.f), func(t *testing.T) {
			got, detail := ClassifyDialFailure(tc.f)
			if got != tc.want {
				t.Fatalf("ClassifyDialFailure(%q) = %q, want %q (detail: %s)", tc.f, got, tc.want, detail)
			}
			if !got.Valid() {
				t.Fatalf("ClassifyDialFailure returned %q, which is not a valid outcome", got)
			}
			if detail == "" {
				t.Fatal("ClassifyDialFailure returned an empty detail; the abort message would say nothing")
			}
			// Nothing this function returns may be AttemptOutcomeReachable:
			// it is only ever called when the handshake did NOT complete.
			if got == AttemptOutcomeReachable {
				t.Fatalf("ClassifyDialFailure(%q) reported reachable for a failed connect", tc.f)
			}
		})
	}
}

// TestNoUnrecognisedFailureReasonIsEverBlocked is the fail-closed direction of
// the table above, asserted over a set the table does not enumerate. A
// classifier whose default was "blocked" would turn every future reason -- and
// every typo -- into containment.
func TestNoUnrecognisedFailureReasonIsEverBlocked(t *testing.T) {
	known := map[DialFailure]bool{
		DialFailurePolicyRejected: true,
		DialFailureNoRoute:        true,
		DialFailureSilentTimeout:  true,
	}
	for _, s := range []string{
		"", "blocked", "BLOCKED", "no_route ", " no_route", "policy-rejected",
		"silent_timeout\n", "drop", "dropped", "filtered", "unreachable", "denied",
	} {
		f := DialFailure(s)
		if known[f] {
			t.Fatalf("fixture problem: %q is a recognised reason and does not belong here", s)
		}
		if got, _ := ClassifyDialFailure(f); got == AttemptOutcomeBlocked {
			t.Fatalf("ClassifyDialFailure(%q) = blocked. An unrecognised reason must never be "+
				"read as containment", s)
		}
	}
}

// TestAResetIsNotContainment is called out separately because it is the one
// classification a reasonable person would get wrong. A TCP RST means the
// packet REACHED something that answered.
func TestAResetIsNotContainment(t *testing.T) {
	got, detail := ClassifyDialFailure(DialFailureReset)
	if got == AttemptOutcomeBlocked {
		t.Fatal("a TCP reset was classified as blocked. A RST is a reply: something received the " +
			"packet, which is evidence of delivery, not of containment")
	}
	if !strings.Contains(detail, "delivery") {
		t.Fatalf("the reset detail does not explain itself: %q", detail)
	}
	// And it must abort the whole run, not merely be a non-blocked value.
	probes := MetadataProbes()
	rep := RunCanary(context.Background(), stubProbe{
		failure: map[string]DialFailure{
			probes[0].String(): DialFailureReset,
			probes[1].String(): DialFailureNoRoute,
		},
	}, fixtureInode, probes)
	if err := EvaluateCanaryReport(fixtureNetns(t), probes, rep); err == nil {
		t.Fatal("a run in which the metadata endpoint answered with a RST was accepted")
	}
}

// TestACancelledAttemptIsNotContainment: the caller's clock running out is not
// a network verdict, and a run cut short must not read as a clean one.
func TestACancelledAttemptIsNotContainment(t *testing.T) {
	if got, _ := ClassifyDialFailure(DialFailureCancelled); got == AttemptOutcomeBlocked {
		t.Fatal("a cancelled attempt was classified as blocked")
	}
}

// TestAConnectedProbeIsReachableEvenIfItAlsoReportsAFailure pins the
// fail-closed direction of RunCanary's own branch: a probe that says both
// things is confused, and the confused reading that ABORTS is the safe one.
func TestAConnectedProbeIsReachableEvenIfItAlsoReportsAFailure(t *testing.T) {
	probes := MetadataProbes()
	rep := RunCanary(context.Background(), contradictoryProbe{}, fixtureInode, probes)
	for _, a := range rep.Attempts {
		if a.Outcome != AttemptOutcomeReachable {
			t.Fatalf("a probe that connected AND reported no_route was classified %q; the reading "+
				"that aborts is the safe one", a.Outcome)
		}
	}
	if err := EvaluateCanaryReport(fixtureNetns(t), probes, rep); err == nil {
		t.Fatal("a contradictory report was accepted")
	}
}

type contradictoryProbe struct{}

func (contradictoryProbe) Attempt(_ context.Context, _, _ string) (bool, DialFailure, string) {
	return true, DialFailureNoRoute, "both at once"
}

// TestCanaryMainRefusesWithoutAProbe: a binary built without a ConnectProbe
// must say so, not emit an empty report that the host side would diagnose as
// a missing probe.
func TestCanaryMainRefusesWithoutAProbe(t *testing.T) {
	var out strings.Builder
	code := CanaryMain(context.Background(), &out, nil)
	if code == 0 {
		t.Fatal("CanaryMain with a nil ConnectProbe exited 0")
	}
	if out.Len() != 0 {
		t.Fatalf("CanaryMain with a nil ConnectProbe wrote a report: %q", out.String())
	}
}

func TestAttemptOutcomeZeroValueIsNotValid(t *testing.T) {
	var zero AttemptOutcome
	if zero != AttemptOutcomeUnset {
		t.Fatalf("the zero AttemptOutcome is %q, not AttemptOutcomeUnset", zero)
	}
	if zero.Valid() {
		t.Fatal("the zero AttemptOutcome reports Valid(); a Go zero value must never mean permitted")
	}
	if AttemptOutcomeUnset == AttemptOutcomeBlocked {
		t.Fatal("the unset outcome collides with the blocked outcome")
	}
}

// ---------------------------------------------------------------------------
// Probe list integrity
// ---------------------------------------------------------------------------

func TestMetadataProbesAreTheTwoThePlanNamesAndCannotBeMutatedByACaller(t *testing.T) {
	got := MetadataProbes()
	want := []string{"169.254.169.254:80", "[fd00:ec2::254]:80"}
	if len(got) != len(want) {
		t.Fatalf("MetadataProbes returned %d probes: %v", len(got), got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("probe %d = %q, want %q", i, got[i].String(), want[i])
		}
		if !DeniedByRuleset(got[i].Addr) {
			t.Fatalf("probe %d (%s) is not in the deny set; the probe checks for something the "+
				"ruleset does not block", i, got[i].Addr)
		}
		if _, reserved := authz.AddressIsReserved(got[i].Addr); !reserved {
			t.Fatalf("probe %d (%s) is not reserved per gate 10", i, got[i].Addr)
		}
	}
	// A caller mutating the returned slice must not affect the next call.
	got[0] = Probe{Addr: netip.MustParseAddr("203.0.113.7"), Port: 80}
	got = got[:1]
	again := MetadataProbes()
	if len(again) != len(want) || again[0].String() != want[0] {
		t.Fatalf("MetadataProbes was mutated by a caller: %v", again)
	}
}

func TestTimeoutIsBoundedAndNonZero(t *testing.T) {
	if DefaultCanaryDialTimeout <= 0 {
		t.Fatal("DefaultCanaryDialTimeout is not positive; a zero dial timeout means no timeout")
	}
	if DefaultCanaryDialTimeout > 30*time.Second {
		t.Fatalf("DefaultCanaryDialTimeout is %v; the probe runs on every scan and this is a "+
			"per-address cost", DefaultCanaryDialTimeout)
	}
}

// TestThisFileSkipsNothing. provision_test.go carries the same guard over
// itself; neither reads the other's source, so this file needs its own or the
// property is unchecked here.
//
// It matters more than usual in this package. Everything in D.11 is a control
// that cannot run on the development host, which is exactly the condition
// under which a skip is reached for -- and a skipped containment assertion
// lets the package print `ok` while proving nothing about the sandbox. The gap
// goes in internal/SKIPPED-CONTROLS.md (entry U1) instead, where it is read
// rather than passed over.
func TestThisFileSkipsNothing(t *testing.T) {
	src, err := parser.ParseFile(token.NewFileSet(), "netns_test.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing netns_test.go: %v", err)
	}
	// The needle is assembled at runtime. Written as a literal it would appear
	// in this file and the test would fail against itself, which is how a
	// self-referential guard gets deleted instead of fixed.
	tok := "t." + "Skip"
	ast.Inspect(src, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != "t" {
			return true
		}
		if strings.HasPrefix(sel.Sel.Name, tok[2:]) {
			t.Errorf("netns_test.go calls t.%s. If a control genuinely cannot run here, it "+
				"belongs in internal/SKIPPED-CONTROLS.md with what would settle it -- not "+
				"behind a green tick", sel.Sel.Name)
		}
		return true
	})
}

// TestThisPackageConstructsNoSocket is the local statement of gate 3.
//
// It is a source-level guard because that is where the property lives: a
// package cannot open a socket without importing something that can, so the
// check is over the import set, exactly as
// internal/dast/authz/egress_chokepoint_test.go argues. Gate 3 already scans
// the whole repository and would catch a regression here -- this test exists
// so the failure lands in THIS package's own suite, naming this package's own
// design rule, rather than only in a distant one.
func TestThisPackageConstructsNoSocket(t *testing.T) {
	// syscall is absent entirely rather than narrowed to gate 3's inert
	// symbols: this package has no use for an errno, because the errno table
	// belongs with the ConnectProbe implementation.
	banned := map[string]string{
		"net":                  "a dialer, listener and resolver",
		"net/http":             "an HTTP client",
		"syscall":              "raw sockets, and this package needs no errno",
		"golang.org/x/net":     "networking",
		"crypto/tls":           "a TLS client over a connection",
		"net/rpc":              "an RPC client",
		"net/smtp":             "an SMTP client",
		"os/user":              "not networking, but not needed either",
		"golang.org/x/net/prx": "networking",
	}
	fset := token.NewFileSet()
	for _, name := range []string{"netns.go", "netns_test.go"} {
		file, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if why, bad := banned[path]; bad {
				t.Errorf("%s imports %q (%s). Gate 3 refuses socket construction inside "+
					"internal/dast outside the kernel, with no allowlist; the canary's connect "+
					"is a ConnectProbe handed in from the binary for exactly this reason",
					name, path, why)
			}
			// The catch-all, so a networking package nobody listed above is
			// still caught: anything under net/ except the two value-only
			// packages gate 3 itself calls inert.
			if strings.HasPrefix(path, "net/") && path != "net/netip" && path != "net/url" {
				t.Errorf("%s imports %q, which is under net/ and is not one of the two "+
					"value-only packages gate 3 treats as inert", name, path)
			}
		}
	}
}
