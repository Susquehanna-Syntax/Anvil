// Package containment holds the DAST half's network containment: a dedicated
// Linux network namespace whose egress is default-deny under nftables, and an
// assertion probe that re-proves the containment ON EVERY RUN.
//
// # The design spike the plan asked for
//
// plan/50-dast.md's Open Questions (the D.11 entry) leaves the assertion
// probe's mechanism to this worker and names the two candidates. Both were
// considered; the reasoning is recorded here because the next reader will ask,
// and because the two options prove DIFFERENT THINGS and the difference is the
// whole decision.
//
// Option A -- a HOST-SIDE probe against the namespace. The host reads the
// installed ruleset back (`nft -j list ruleset` inside the netns), or dials the
// metadata address across the veth from the host side, and concludes.
//
//	What it actually proves: that the ruleset Anvil installed is the ruleset
//	nft reports, and/or that the HOST cannot reach the metadata endpoint by a
//	route through the veth. Neither is the claim the gate needs. Reading the
//	ruleset back is marking your own homework in your own handwriting: it
//	cannot see a second nft table at an earlier hook that accepts, a route
//	added to the namespace after setup, a second interface, a container the
//	runtime placed in the HOST netns instead (`--network=host`, a runtime bug,
//	an operator override), or an IPv6 path the ruleset's address family did
//	not cover. Every one of those leaves the ruleset text unchanged and the
//	sandbox open.
//	Latency: an `nft list` is one exec and a parse. A host-side dial pays a
//	full dial timeout on the blocked path, because DROP is silent.
//
// Option B -- a CANARY PROCESS INSIDE the namespace. A process is launched in
// the target's netns and attempts a real TCP connect to the metadata endpoints.
//
//	What it actually proves: that a process holding the same network view as
//	the target cannot complete a connection to the metadata endpoint. That is
//	the claim, stated in the terms the attacker would use.
//	Latency: identical order of magnitude to option A's dial, and the
//	asymmetry is favourable -- the DANGEROUS outcome (reachable) returns fast,
//	because a link-local metadata endpoint answers in well under a
//	millisecond, while the SAFE outcome (blocked) is the one that may pay the
//	timeout. So the timeout can be short without trading away sensitivity: a
//	short timeout can only ever turn a slow "blocked" into a "blocked", never
//	a "reachable" into a "blocked". The concrete figure on the target runtime
//	is NOT MEASURED -- see the platform note below; this host cannot run it.
//
// DECISION: option B, the canary. Not because it is faster -- the two are
// comparable -- but because option A proves a property of the CONFIGURATION and
// option B proves a property of the REACHABILITY, and a namespace that was
// configured correctly and is now misconfigured looks identical from outside.
//
// # The canary's own failure mode, and the positive control that closes it
//
// A canary that reports "blocked" because it never ran, ran in the wrong
// namespace, or ran in an empty namespace where NOTHING is reachable is the
// silent-clean failure in its purest form -- and it is the specific one
// research 19 risk #5 names ("no controller, no effect, no error"). So the
// canary reports the inode of its OWN network namespace
// (`/proc/self/ns/net`) alongside its dial results, and EvaluateCanaryReport
// refuses unless BOTH hold:
//
//   - the canary's inode equals the inode of the netns file the host stat'd
//     directly (so the canary ran in the namespace we configured), AND
//   - the canary's inode DIFFERS from the host's own netns inode (so
//     `ip netns exec` genuinely switched namespaces rather than silently
//     running the canary on the host).
//
// The second check is the one that is not vacuous. Without it, a setup path
// that reads the inode through the same `ip netns exec` it later fails to apply
// would agree with itself and report contained.
//
// # This host cannot prove any of it
//
// The development host for this packet is WINDOWS. Linux network namespaces
// and nftables do not exist here, so nothing in this file that touches the
// kernel can be executed, and no test in this package claims otherwise. The
// package is therefore split so that the honest part is testable everywhere:
//
//   - The ruleset is BUILT by a pure function (BuildRuleset) and pinned by
//     golden and ordering tests that run on every platform.
//   - The report evaluation is a pure function (EvaluateCanaryReport) and is
//     tested against reachable / missing / wrong-namespace / malformed reports
//     on every platform.
//   - The only part that needs Linux is the EXEC, and it is behind the
//     Commander interface.
//
// SystemCommander REFUSES on any non-Linux GOOS -- it does not return a
// no-op that would let AssertContainment return nil. There is no t.Skip in
// this package. See internal/SKIPPED-CONTROLS.md entry U1 for what remains
// unexecuted and exactly what would settle it.
//
// # Why this package holds no socket
//
// It cannot. The authorization kernel's gate 3 refuses any socket construction
// inside `internal/dast` outside the kernel package, with no allowlist. The
// canary's connect is therefore a ConnectProbe -- a capability handed in from
// the binary, returning a VERDICT and never a connection. See the ConnectProbe
// declaration for the full reasoning; the short version is that the gate was
// right, the first draft of this file was wrong, and the seam moved rather
// than the gate.
package containment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
	"github.com/Susquehanna-Syntax/Anvil/internal/dast/target"
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// ErrContainment is the root sentinel. Every refusal in this package wraps it,
// so a caller can errors.Is against one value instead of string-matching.
var ErrContainment = errors.New("dast network containment")

var (
	// ErrUnsupportedPlatform is returned by SystemCommander and by anything
	// that would have to touch a Linux kernel facility, on a host that has
	// none. It is an ERROR, never a quiet success: a containment layer that
	// reports "fine" on a platform where it did nothing is the exact failure
	// this package exists to make impossible.
	ErrUnsupportedPlatform = fmt.Errorf("%w: refused", ErrContainment)

	// ErrNotContained is the ABORT. AssertContainment returns it -- wrapped
	// with the detail -- whenever the sandbox is reachable, or whenever
	// reachability could not be established either way. Both directions abort;
	// see EvaluateCanaryReport.
	ErrNotContained = fmt.Errorf("%w: refused", ErrContainment)

	// ErrInvalidPlan is a refusal at ruleset-build time: the plan handed in
	// would have punched a hole in the containment, or is not usable.
	ErrInvalidPlan = fmt.Errorf("%w: refused", ErrContainment)
)

func notContainedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrNotContained, fmt.Sprintf(format, args...))
}

func invalidPlanf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidPlan, fmt.Sprintf(format, args...))
}

// ---------------------------------------------------------------------------
// The namespace handle
// ---------------------------------------------------------------------------

// TableName is the single nftables table this package owns. It is a fixed
// name, not derived from operator input, because the setup script DELETES the
// table before recreating it and a name that could be steered is a name that
// could delete somebody else's ruleset.
const TableName = "anvil_dast"

// ChainName is the egress chain inside TableName, hooked at `output`.
const ChainName = "egress"

// ForwardChainName is the egress chain hooked at `forward`, and it carries
// EXACTLY the same rules as ChainName.
//
// IT IS NOT REDUNDANT WITH ChainName. THE OUTPUT HOOK CANNOT SEE THE TRAFFIC
// THIS PACKAGE EXISTS TO STOP.
//
// nftables' `output` hook sees packets whose SOURCE SOCKET is in the namespace
// -- a process running directly in it. That is the canary, launched by `ip
// netns exec`, and it is not the target. The target is a Compose project: its
// containers sit in their own namespaces on a bridge INSIDE this namespace, so
// a packet a container sends is received on the bridge and ROUTED ONWARD, which
// is the `forward` hook and not `output`. provision.go's own NetworkMode
// assertion requires exactly that arrangement -- the authorized service must be
// on a network of this Compose project, which is a bridge, which forwards.
//
// So an output-only ruleset constrained the canary and nothing else, while
// every test in this package -- the golden script, the ordering test, the
// canary's own blocked verdict -- reported it closed. That is the shape of
// failure this package was written to make impossible, occurring in the
// package's own ruleset.
//
// WHAT THIS STILL DOES NOT PROVE: the canary runs under `ip netns exec`, so it
// holds a socket IN the namespace and its own dials traverse `output`, not
// `forward`. It therefore exercises the chain the TARGET DOES NOT USE. Recorded
// in internal/SKIPPED-CONTROLS.md as U1a, with what would settle it.
//
// WHY THERE IS NO `input` CHAIN, stated rather than left as an omission. The
// property asserted here is what the target can REACH. `input` is inbound: the
// probe engine lives outside the namespace and must reach the target, and the
// health probe (provision.go step 14) must reach the declared health URL. A
// default-drop input chain would refuse both, turning every scan into
// unreachable_at_scan_time. Inbound reachability is not the SSRF-to-metadata
// path and adding a hook that breaks the scan buys nothing against it.
const ForwardChainName = "egress_forward"

// hookedChains is every chain the generated script installs, with the nftables
// hook each is attached to, IN EMISSION ORDER. It is one list so that a chain
// added here is automatically carried through renderScript and through
// TestEveryHookedChainCarriesTheIdenticalRuleList, rather than being a second
// place that has to be remembered.
func hookedChains() []struct{ Chain, Hook string } {
	return []struct{ Chain, Hook string }{
		{ChainName, "output"},
		{ForwardChainName, "forward"},
	}
}

// NetnsRunDir is where iproute2 keeps named network namespaces. It is where
// ReadNetnsInode stats, and it is a constant rather than a parameter for the
// same reason TableName is.
const NetnsRunDir = "/run/netns"

// Netns identifies ONE target's network namespace, together with the two
// inodes the positive control needs.
//
// FAIL CLOSED: the zero value is not constructed. Constructed() reports false
// for it, every function here refuses an unconstructed Netns, and there is no
// path that turns a zero value into a usable one except NewNetns, which
// validates.
type Netns struct {
	name      string
	inode     uint64
	hostInode uint64
}

// NewNetns validates and builds a Netns.
//
// The three checks are not paperwork:
//
//   - name must be a plain identifier. It is interpolated into an `ip netns
//     exec` argv and into a path under NetnsRunDir; anything with a separator,
//     a space or a shell metacharacter is refused rather than escaped.
//   - neither inode may be zero. Zero is the value an unread or failed stat
//     leaves behind, and a zero inode compared against a zero inode would
//     "agree" and pass the positive control.
//   - inode must DIFFER from hostInode. If they are equal, the name resolves to
//     the host's own network namespace and there is no containment boundary at
//     all -- a canary launched into it would be on the host and would report
//     whatever the host can reach.
func NewNetns(name string, inode, hostInode uint64) (Netns, error) {
	if err := checkNetnsName(name); err != nil {
		return Netns{}, err
	}
	if inode == 0 {
		return Netns{}, invalidPlanf("netns %q has inode 0; 0 is what a failed stat leaves behind, "+
			"and a zero inode would compare equal to another zero inode and pass the positive control", name)
	}
	if hostInode == 0 {
		return Netns{}, invalidPlanf("the host network namespace inode is 0; the positive control " +
			"cannot tell whether the canary switched namespaces without it")
	}
	if inode == hostInode {
		return Netns{}, invalidPlanf("netns %q has inode %d, which is the HOST network namespace's "+
			"inode; there is no containment boundary and a canary launched into it would report "+
			"what the host can reach", name, inode)
	}
	return Netns{name: name, inode: inode, hostInode: hostInode}, nil
}

// checkNetnsName is an allowlist: 1-64 bytes of [A-Za-z0-9_-], not starting
// with '-'. A denylist of dangerous characters loses to the first encoding
// nobody thought of, and this string reaches both an argv and a path.
func checkNetnsName(name string) error {
	if name == "" {
		return invalidPlanf("the network namespace name is empty")
	}
	if len(name) > 64 {
		return invalidPlanf("the network namespace name is %d bytes; the limit is 64", len(name))
	}
	if name[0] == '-' {
		return invalidPlanf("the network namespace name %q starts with '-', which an argv would "+
			"read as an option", name)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
		if !ok {
			return invalidPlanf("the network namespace name %q contains %q at byte %d; only "+
				"[A-Za-z0-9_-] is permitted", name, string(c), i)
		}
	}
	return nil
}

// Name returns the namespace name, or "" for the zero value.
func (n Netns) Name() string { return n.name }

// Inode returns the namespace's inode, or 0 for the zero value.
func (n Netns) Inode() uint64 { return n.inode }

// HostInode returns the host namespace's inode, or 0 for the zero value.
func (n Netns) HostInode() uint64 { return n.hostInode }

// Constructed reports whether this Netns came out of NewNetns. The zero value
// reports false, and every entry point in this package refuses it.
func (n Netns) Constructed() bool {
	return n.name != "" && n.inode != 0 && n.hostInode != 0 && n.inode != n.hostInode
}

// Path is the iproute2 path for the named namespace.
func (n Netns) Path() string { return NetnsRunDir + "/" + n.name }

// ---------------------------------------------------------------------------
// The Commander boundary
// ---------------------------------------------------------------------------

// Commander runs one external command to completion and returns its stdout.
//
// It exists for exactly two reasons. The first is the licence boundary spine
// S8 and plan/50-dast.md's Pinned Versions section require: nftables is
// GPL-2.0 and is INVOKED AS A SUBPROCESS, NEVER LINKED. The second is that it
// is the only part of this package that needs a Linux kernel, so putting it
// behind an interface is what lets the decision logic be tested on a host that
// has none.
//
// stdin is passed as bytes rather than a Reader because every use here writes a
// complete, already-built script and a streaming stdin would make the command
// non-deterministic for no gain.
type Commander interface {
	Run(ctx context.Context, argv []string, stdin []byte) ([]byte, error)
}

// SystemCommander returns a Commander backed by os/exec, or
// ErrUnsupportedPlatform.
//
// THIS IS THE WINDOWS REFUSAL, and it is deliberately here rather than deeper
// in. A version of this function that returned a Commander whose Run was a
// no-op would make SetupNetns and AssertContainment both return nil on
// Windows, which reads as "the sandbox is contained". That is the single worst
// lie this codebase could tell, because it is the claim that authorizes Anvil
// to fire probes at all.
func SystemCommander() (Commander, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("%w: network containment needs Linux network namespaces and "+
			"nftables; this process is running on %s/%s, where neither exists. Anvil will not "+
			"report a sandbox as contained on a platform where it cannot check",
			ErrUnsupportedPlatform, runtime.GOOS, runtime.GOARCH)
	}
	return execCommander{}, nil
}

type execCommander struct{}

// MaxCommandOutputBytes caps what a subprocess may return. `nft` and `stat`
// answer in bytes; a process that answers in megabytes is malfunctioning and
// the cap turns that into a refusal instead of a memory problem.
const MaxCommandOutputBytes = 1 << 20

func (execCommander) Run(ctx context.Context, argv []string, stdin []byte) ([]byte, error) {
	if len(argv) == 0 {
		return nil, invalidPlanf("empty argv")
	}
	// NO SHELL. The binary is resolved on PATH and the arguments are passed as
	// an argv slice, so nothing in them is ever interpreted.
	bin, err := exec.LookPath(argv[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %q is not on PATH: %v", ErrContainment, argv[0], err)
	}
	cmd := exec.CommandContext(ctx, bin, argv[1:]...)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	runErr := cmd.Run()
	if out.Len() > MaxCommandOutputBytes {
		return nil, fmt.Errorf("%w: %q returned %d bytes of stdout; the cap is %d",
			ErrContainment, strings.Join(argv, " "), out.Len(), MaxCommandOutputBytes)
	}
	if runErr != nil {
		return out.Bytes(), fmt.Errorf("%w: %q failed: %v: %s",
			ErrContainment, strings.Join(argv, " "), runErr, strings.TrimSpace(errBuf.String()))
	}
	return out.Bytes(), nil
}

// ---------------------------------------------------------------------------
// The probe targets
// ---------------------------------------------------------------------------

// The cloud metadata endpoints, as untyped string CONSTANTS.
//
// These are the two plan/50-dast.md names for D.11. They are consts rather
// than vars for the reason gate 10's denylist is: a var is assignable from
// anywhere in the package, and "the probe list was empty at the moment
// AssertContainment ran" is a state that must not be reachable. MetadataProbes
// builds a fresh slice on every call so no caller can retain and mutate it.
const (
	metadataIPv4 = "169.254.169.254" // AWS/GCP/Azure/OpenStack IMDS. Hands out credentials.
	metadataIPv6 = "fd00:ec2::254"   // AWS IMDS over IPv6.

	// Port 80 and not 443: IMDS answers on 80, and the question is whether a
	// TCP connection completes, not whether TLS negotiates.
	metadataPort = 80
)

// Probe is one address:port the canary must fail to reach.
type Probe struct {
	Addr netip.Addr
	Port uint16
}

// String is the canary's wire identity for this probe and the key
// EvaluateCanaryReport matches on. It is netip.AddrPort's canonical form, so
// "169.254.169.254:80" and "[fd00:ec2::254]:80".
func (p Probe) String() string { return netip.AddrPortFrom(p.Addr, p.Port).String() }

// MetadataProbes returns the metadata endpoints, freshly built.
//
// MustParseAddr panics on a malformed constant. That is correct: a malformed
// compiled-in constant is a build defect, the panic fires in every test binary
// that links this package, and there is no correct way to continue with a
// probe list that did not assemble -- the alternative is an empty list, and an
// empty list is a probe that always passes.
func MetadataProbes() []Probe {
	return []Probe{
		{Addr: netip.MustParseAddr(metadataIPv4), Port: metadataPort},
		{Addr: netip.MustParseAddr(metadataIPv6), Port: metadataPort},
	}
}

// ---------------------------------------------------------------------------
// The deny set
// ---------------------------------------------------------------------------

// The default-deny egress denylist, as untyped string CONSTANTS.
//
// This is plan/50-dast.md D.11's list: 169.254.0.0/16, the fd00:ec2::254
// metadata address, and the full OWASP SSRF block list. It is a superset of
// what the plan enumerates, because it is checked against gate 10's
// reserved-range denylist by TestDenySetIsNeverWeakerThanGateTen -- the
// relation, not the values, is what is pinned, so a range added to gate 10
// later fails this package's tests rather than silently leaving a hole here.
//
// A denylist normally loses, and this project says so. It is used here for the
// same stated reason gate 10 uses one (see authz's constant block): the
// complement of "reserved" is "every routable address on the internet" and it
// cannot be enumerated. What makes it survivable is that it is NOT the only
// control -- the chain's policy is `drop`, so an address in no list at all is
// refused by default, and these explicit rules exist to make sure no LATER
// allow rule can reopen them.
const (
	denyIPv4ThisNetwork = "0.0.0.0/8"      // RFC 1122; reaches loopback on most stacks.
	denyIPv4Private10   = "10.0.0.0/8"     // RFC 1918.
	denyIPv4CGNAT       = "100.64.0.0/10"  // RFC 6598.
	denyIPv4Loopback    = "127.0.0.0/8"    // RFC 1122.
	denyIPv4LinkLocal   = "169.254.0.0/16" // RFC 3927, and 169.254.169.254.
	denyIPv4Private172  = "172.16.0.0/12"  // RFC 1918.
	denyIPv4Protocol    = "192.0.0.0/24"   // RFC 6890, incl. 192.0.0.170.
	denyIPv4Private192  = "192.168.0.0/16" // RFC 1918.
	denyIPv4Benchmark   = "198.18.0.0/15"  // RFC 2544.
	denyIPv4Multicast   = "224.0.0.0/4"    // RFC 5771.
	denyIPv4Future      = "240.0.0.0/4"    // RFC 1112, incl. 255.255.255.255.
	denyIPv6Unspecified = "::/128"         // RFC 4291.
	denyIPv6Loopback    = "::1/128"        // RFC 4291.
	denyIPv6V4Mapped    = "::ffff:0:0/96"  // RFC 4291 2.5.5.2; see below.
	denyIPv6NAT64       = "64:ff9b::/96"   // RFC 6052; an IPv4 range in disguise.
	denyIPv6NAT64Local  = "64:ff9b:1::/48" // RFC 8215; likewise.
	denyIPv6SixToFour   = "2002::/16"      // RFC 3056; likewise.
	denyIPv6ULA         = "fc00::/7"       // RFC 4193, and fd00:ec2::254 lives here.
	denyIPv6LinkLocal   = "fe80::/10"      // RFC 4291.
	denyIPv6Multicast   = "ff00::/8"       // RFC 4291.
)

// WHY ::ffff:0:0/96 IS IN THE EMITTED SET AND NOT ONLY IN THE PREDICATE.
//
// DeniedByRuleset canonicalizes an IPv4-mapped address to its dotted quad
// before matching, so the PREDICATE has always answered "denied" for
// "::ffff:169.254.169.254". The emitted nftables ruleset did not: its
// anvil_deny6 set held no mapped range, so `ip6 daddr @anvil_deny6 drop` would
// not have matched that destination on the wire.
//
// A predicate that is stricter than the ruleset it claims to model is a check
// that cannot see the damage: every test in this package asks DeniedByRuleset
// and would have reported the sandbox closed while the kernel left it open.
// The two are reconciled in the STRICTER direction -- the whole mapped range is
// dropped outright, so the model and the wire now say the same thing. Nothing
// legitimate is lost: a v4-mapped destination in an actual IPv6 packet is not
// a destination any target needs.

// canonicalAddr is the ONE canonicalization every address comparison in this
// package goes through, and it exists because netip's own comparisons are
// spelling-sensitive in two directions that both fail OPEN:
//
//  1. IPv4-MAPPED IPv6. netip.Prefix.Contains compares families, so
//     "169.254.0.0/16" does not contain "::ffff:169.254.169.254" and
//     "::ffff:169.254.169.254/128" does not contain "169.254.169.254". The
//     authorization kernel already encodes this lesson in gate 8
//     (authz.Canonicalize unwraps an IPv4-mapped literal precisely so that
//     "[::ffff:169.254.169.254]" and "169.254.169.254" cannot compare
//     differently against gate 10's ranges) and this is the same rule at the
//     network layer. It is Unmap, exactly as authz.AddressIsReserved and
//     authz.scopeEnumeratesAddress spell it, so the two layers cannot disagree
//     about what an address IS before they disagree about whether it is denied.
//
//  2. ZONED IPv6. netip.Prefix.Contains returns FALSE for any address carrying
//     a zone, unconditionally -- prefixes cannot carry zones, so netip refuses
//     the comparison rather than answering it. "fe80::1%eth0", "::1%lo" and
//     "fd00:ec2::254%eth0" therefore walked the entire deny set and came out
//     the far side reported as NOT DENIED. Measured, not reasoned: see
//     TestDeniedByRulesetSeesThroughAZone.
//     Stripping the zone is correct rather than merely convenient, because
//     nftables has no zone concept at all: a zone is a local scope identifier
//     for a link-local address, it never appears on the wire, and the packet
//     the kernel matches against the ruleset carries only the 16 address bytes.
//     So the zone-free form IS what the ruleset sees, and stripping it makes
//     the predicate model the ruleset instead of contradicting it.
//
// FAIL CLOSED: an invalid address canonicalizes to an invalid address, and
// every caller treats invalid as denied.
func canonicalAddr(addr netip.Addr) netip.Addr {
	return addr.WithZone("").Unmap()
}

// DenyPrefixesV4 returns the IPv4 half of the deny set, freshly parsed.
func DenyPrefixesV4() []netip.Prefix {
	return mustPrefixes(
		denyIPv4ThisNetwork, denyIPv4Private10, denyIPv4CGNAT, denyIPv4Loopback,
		denyIPv4LinkLocal, denyIPv4Private172, denyIPv4Protocol, denyIPv4Private192,
		denyIPv4Benchmark, denyIPv4Multicast, denyIPv4Future,
	)
}

// DenyPrefixesV6 returns the IPv6 half of the deny set, freshly parsed.
func DenyPrefixesV6() []netip.Prefix {
	return mustPrefixes(
		denyIPv6Unspecified, denyIPv6Loopback, denyIPv6V4Mapped, denyIPv6NAT64,
		denyIPv6NAT64Local, denyIPv6SixToFour, denyIPv6ULA, denyIPv6LinkLocal,
		denyIPv6Multicast,
	)
}

func mustPrefixes(raw ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(raw))
	for _, r := range raw {
		out = append(out, netip.MustParsePrefix(r))
	}
	return out
}

// canonicalPrefix is canonicalAddr for a PREFIX, and it is what every
// operator-supplied CIDR goes through before anything is decided about it.
//
// The IPv4-mapped spelling defeats a prefix comparison exactly as it defeats an
// address comparison, and it did: BuildRuleset ACCEPTED
// "::ffff:169.254.169.254/128" as a scope allow entry and emitted an accept
// rule for it, because netip.Prefix.Contains compares families and that prefix
// does not contain the dotted-quad metadata address. The six-row table that was
// supposed to assert the refusal held six spellings, none of them this one.
//
// So an IPv4-mapped prefix is UNWRAPPED to the dotted-quad prefix it names --
// "::ffff:169.254.169.254/128" becomes "169.254.169.254/32", and
// "::ffff:0.0.0.0/96" becomes "0.0.0.0/0", which is then refused for covering
// the metadata address, which is the correct answer for a rule that would let
// every IPv4 destination through.
//
// A mapped prefix with fewer than 96 bits is REFUSED rather than unwrapped: it
// straddles the boundary of the mapped range and names IPv6 space outside it,
// so there is no dotted quad it is equivalent to. In practice such a prefix
// cannot reach here masked -- netip masks "::ffff:0:0/95" to "::fffe:0:0/95",
// whose address is no longer IPv4-mapped, and every caller requires a masked
// prefix -- but the refusal is written rather than reasoned about, because the
// alternative is a silently wrong bits-96 subtraction if a caller ever stops
// requiring masked input.
//
// netip.PrefixFrom drops any zone on the address it is given (verified), so a
// prefix cannot carry one and there is no zone case here.
func canonicalPrefix(p netip.Prefix) (netip.Prefix, error) {
	if !p.IsValid() {
		return netip.Prefix{}, fmt.Errorf("not a valid prefix")
	}
	if !p.Addr().Is4In6() {
		return p, nil
	}
	const mappedPrefixBits = 96
	if p.Bits() < mappedPrefixBits {
		return netip.Prefix{}, fmt.Errorf("%q is an IPv4-mapped prefix shorter than /%d, so it "+
			"also names IPv6 space outside ::ffff:0:0/%d and there is no IPv4 prefix it is "+
			"equivalent to; write the IPv4 range in dotted-quad form",
			p.String(), mappedPrefixBits, mappedPrefixBits)
	}
	return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-mappedPrefixBits), nil
}

// DeniedByRuleset reports whether addr falls in the compiled-in deny set.
//
// The address is put through canonicalAddr first. Read that function's comment
// before changing this one: comparing an address to a prefix without it is
// wrong for two spellings, both of which fail OPEN.
//
// FAIL CLOSED: an INVALID address is denied. netip.Addr's zero value is
// invalid, and a zero value that reported "not denied" would be a zero value
// that authorized something.
func DeniedByRuleset(addr netip.Addr) bool {
	a := canonicalAddr(addr)
	if !a.IsValid() {
		return true
	}
	set := DenyPrefixesV4()
	if a.Is6() {
		set = DenyPrefixesV6()
	}
	for _, p := range set {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The plan and the ruleset
// ---------------------------------------------------------------------------

// Plan is everything BuildRuleset needs.
type Plan struct {
	// Netns is the namespace the ruleset is installed into.
	Netns Netns

	// Manifest is the target's declared manifest (D.1). Its
	// Scope.AdditionalEgressAllow entries are the only operator-supplied
	// input to the ruleset, and they cannot widen the metadata drop -- see
	// BuildRuleset.
	Manifest *target.Manifest

	// IntraTargetNetworks are the Compose network CIDRs the target's own
	// services live on, supplied by the provisioning layer (D.10) which is
	// what knows them. They are ALLOWED, and they will normally sit inside
	// RFC 1918 space that the deny set otherwise drops -- a target that cannot
	// reach its own database is not a target.
	//
	// This is the one deliberate hole in the deny set, so it is bounded hard:
	// see checkIntraTargetNetworks. Nothing here can reach a metadata address,
	// because the metadata drops are the FIRST rules in the chain and no later
	// accept is evaluated once a packet has been dropped.
	IntraTargetNetworks []netip.Prefix
}

// Ruleset is a built, not-yet-installed nftables ruleset.
type Ruleset struct {
	// Script is the complete `nft -f -` input.
	Script string

	// Rules is the rule list IN EVALUATION ORDER, installed identically into
	// EVERY chain hookedChains names -- `output` and `forward`. It is
	// exported so the ordering guarantees can be pinned by index relation
	// rather than by grepping the script text: nftables evaluates a chain top
	// to bottom, so "the metadata drop precedes every accept" is a statement
	// about ORDER, and a test that only checked both lines were present would
	// pass on a ruleset that had swapped them.
	//
	// One list, both chains, by construction: see ForwardChainName for why
	// there are two chains and renderScript for why they cannot diverge.
	Rules []string

	// UnexpressedAllowEntries are scope.additional_egress_allow entries that
	// are HOSTNAMES. nftables matches addresses, not names; embedding a name
	// would make nft resolve it once at load time and pin whatever it got,
	// which is a TOCTOU hole with a friendly name. They are therefore NOT
	// emitted -- under a default-drop policy an unexpressed allow simply does
	// not work, which is the safe direction -- and they are returned here so
	// the caller can say so out loud rather than the omission being silent.
	UnexpressedAllowEntries []string
}

// maxIntraTargetPrefixes bounds how many holes the provisioning layer may open.
const maxIntraTargetPrefixes = 16

// minIntraTargetV4Bits and minIntraTargetV6Bits are the widest an intra-target
// network may be. A "local network" of 0.0.0.0/0 is a bypass wearing a
// friendly name, and nothing legitimate needs a Compose bridge wider than a /8.
const (
	minIntraTargetV4Bits = 8
	minIntraTargetV6Bits = 32
)

// BuildRuleset turns a Plan into an nftables script. It is PURE -- no exec, no
// filesystem, no clock -- which is what lets the whole ruleset be pinned by
// tests on a host with no nftables.
func BuildRuleset(p Plan) (Ruleset, error) {
	if !p.Netns.Constructed() {
		return Ruleset{}, invalidPlanf("the plan carries an unconstructed Netns; a zero value is " +
			"never a namespace")
	}
	if p.Manifest == nil {
		return Ruleset{}, invalidPlanf("the plan carries a nil manifest")
	}
	intra, err := checkIntraTargetNetworks(p.IntraTargetNetworks)
	if err != nil {
		return Ruleset{}, err
	}
	allowed, unexpressed, err := splitAllowEntries(p.Manifest)
	if err != nil {
		return Ruleset{}, err
	}

	var rules []string
	add := func(format string, args ...any) {
		rules = append(rules, fmt.Sprintf(format, args...))
	}

	// ORDER IS THE CONTROL. Read top to bottom; nftables does.
	//
	// 1. The metadata endpoints, dropped UNCONDITIONALLY and FIRST. No
	//    interface qualifier, no state qualifier, nothing above them. This is
	//    the rule that cannot be reopened by anything below, including the
	//    intra-target accepts and including a future edit that adds an accept
	//    in the wrong place, because a dropped packet never reaches rule 2.
	for _, probe := range MetadataProbes() {
		fam := "ip"
		if probe.Addr.Is6() {
			fam = "ip6"
		}
		add("%s daddr %s drop", fam, probe.Addr.String())
	}
	// 2. Link-local, both families, dropped unconditionally. 169.254.0.0/16
	//    is the whole cloud-metadata neighbourhood, not just the .169.254
	//    host: GCP publishes metadata.google.internal in it and Azure's IMDS
	//    is 169.254.169.254 but its WireServer is 168.63.129.16, reached by a
	//    link-local route. fe80::/10 is the IPv6 twin.
	add("ip daddr %s drop", denyIPv4LinkLocal)
	add("ip6 daddr %s drop", denyIPv6LinkLocal)

	// 3. Loopback INSIDE the namespace, accepted. This is below the drops, so
	//    it cannot be used to reach a metadata address, and it is qualified by
	//    both the output interface AND the destination prefix rather than a
	//    bare `oifname "lo" accept`.
	//
	//    It has to be here: target.checkHealthURL REQUIRES health.url to
	//    address either loopback or the authorized Compose service by name,
	//    and Docker's embedded DNS resolver lives at 127.0.0.11. A ruleset
	//    that dropped 127.0.0.0/8 outright would make every manifest's health
	//    gate fail and every service name unresolvable. Note that this traffic
	//    never leaves the namespace.
	//
	//    In the `forward` chain these two rules never match -- nothing is
	//    forwarded out of `lo` -- and they are emitted there anyway rather
	//    than maintaining a second, shorter rule list. An inert rule costs a
	//    line; two rule lists cost a divergence nobody notices.
	add("oifname \"lo\" ip daddr %s accept", denyIPv4Loopback)
	add("oifname \"lo\" ip6 daddr %s accept", denyIPv6Loopback)

	// 4. Return traffic for flows already accepted. Below the drops, so it
	//    cannot resurrect a metadata flow -- the SYN was dropped, so no
	//    conntrack entry for it exists.
	add("ct state established,related accept")

	// 5. The target's own Compose networks. The bounded hole; see
	//    checkIntraTargetNetworks.
	//
	//    LOAD-BEARING IN THE `forward` CHAIN. A container's traffic to a
	//    sibling, and the probe engine's traffic INTO the target, are both
	//    forwarded across the Compose bridge, so with the forward chain at
	//    `policy drop` these accepts are what make the target reachable at
	//    all. A plan that omits them does not open a hole -- it makes the scan
	//    fail as unreachable_at_scan_time, which is the safe direction and is
	//    a fact the operator hears rather than a silent pass.
	for _, pfx := range intra {
		fam := "ip"
		if pfx.Addr().Is6() {
			fam = "ip6"
		}
		add("%s daddr %s accept", fam, pfx.String())
	}

	// 6. The rest of the deny set, as named sets. Redundant against the
	//    chain's `policy drop` for anything not accepted above, and kept
	//    because the redundancy is what stops a future accept rule appended
	//    below from reopening RFC 1918 wholesale.
	add("ip daddr @%s drop", denySetV4)
	add("ip6 daddr @%s drop", denySetV6)

	// 7. The operator's declared extra egress. LAST, so every drop above wins
	//    over it. plan/50-dast.md is explicit that scope entries grant nothing
	//    the kernel's gate 10 would refuse; this ordering is the network-layer
	//    statement of the same rule.
	for _, a := range allowed {
		fam := "ip"
		if a.Addr().Is6() {
			fam = "ip6"
		}
		add("%s daddr %s accept", fam, a.String())
	}

	// 8. The floor. `policy drop` on the chain already covers this; the
	//    explicit terminal drop is here so that the chain reads as
	//    default-deny to a human auditing `nft list ruleset`, who should not
	//    have to know that an absent verdict falls through to the policy.
	add("drop")

	return Ruleset{
		Script:                  renderScript(rules),
		Rules:                   rules,
		UnexpressedAllowEntries: unexpressed,
	}, nil
}

const (
	denySetV4 = "anvil_deny4"
	denySetV6 = "anvil_deny6"
)

func renderScript(rules []string) string {
	var b strings.Builder
	b.WriteString("# Generated by internal/dast/containment. Do not edit by hand.\n")
	// The add/delete/create idiom: `add table` makes the table exist so that
	// `delete table` cannot fail on a first run, and `delete` guarantees the
	// definition below is the WHOLE ruleset for this table rather than being
	// merged into whatever a previous run left behind. A merge would mean an
	// accept rule from an older, wider plan surviving into a narrower one.
	b.WriteString("add table inet " + TableName + "\n")
	b.WriteString("delete table inet " + TableName + "\n")
	b.WriteString("table inet " + TableName + " {\n")
	writeSet(&b, denySetV4, "ipv4_addr", DenyPrefixesV4())
	writeSet(&b, denySetV6, "ipv6_addr", DenyPrefixesV6())
	// EVERY hooked chain gets the IDENTICAL rule list from the IDENTICAL
	// slice. Two chains built from two rule lists is two rulesets that can
	// drift, and the one that drifts is the one nobody reads.
	for _, hc := range hookedChains() {
		b.WriteString("\tchain " + hc.Chain + " {\n")
		b.WriteString("\t\ttype filter hook " + hc.Hook + " priority filter; policy drop;\n")
		for _, r := range rules {
			b.WriteString("\t\t" + r + "\n")
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func writeSet(b *strings.Builder, name, typ string, prefixes []netip.Prefix) {
	b.WriteString("\tset " + name + " {\n")
	b.WriteString("\t\ttype " + typ + "\n")
	b.WriteString("\t\tflags interval\n")
	parts := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		parts = append(parts, p.String())
	}
	b.WriteString("\t\telements = { " + strings.Join(parts, ", ") + " }\n")
	b.WriteString("\t}\n")
}

// checkIntraTargetNetworks bounds the one deliberate hole in the deny set.
//
// Every check here is a refusal, and each one closes a specific way the hole
// could become a bypass:
//
//   - a prefix that is not valid, or not masked (192.168.1.5/16 rather than
//     192.168.0.0/16), is refused rather than normalised, because a caller
//     that wrote the host bits meant something and Anvil should not guess
//     which;
//   - a prefix wider than /8 (v4) or /32 (v6) is refused, because a "local
//     network" that covers the internet is a bypass;
//   - a prefix that CONTAINS OR IS CONTAINED BY any metadata address is
//     refused. Containment in either direction: 169.254.0.0/16 as a "local
//     network" and 0.0.0.0/0 both have to lose. The metadata drops sit above
//     these accepts and would win anyway; this refuses at build time as well,
//     because a plan that asked for it is a plan the operator should hear
//     about rather than one that quietly does nothing.
func checkIntraTargetNetworks(in []netip.Prefix) ([]netip.Prefix, error) {
	if len(in) > maxIntraTargetPrefixes {
		return nil, invalidPlanf("%d intra-target networks were supplied; the limit is %d",
			len(in), maxIntraTargetPrefixes)
	}
	probes := MetadataProbes()
	out := make([]netip.Prefix, 0, len(in))
	for i, p := range in {
		if !p.IsValid() {
			return nil, invalidPlanf("intra_target_networks[%d] is not a valid prefix", i)
		}
		if p.Masked() != p {
			return nil, invalidPlanf("intra_target_networks[%d] is %q, which has host bits set; "+
				"write it masked (%q) so that what is allowed is unambiguous", i, p.String(), p.Masked().String())
		}
		// Canonicalize BEFORE the width bound and the metadata check, for the
		// reason canonicalPrefix states: "::ffff:169.254.0.0/112" is a /16 of
		// IPv4 link-local space wearing a /112 of IPv6, and both checks below
		// would read the disguise rather than the range.
		p, err := canonicalPrefix(p)
		if err != nil {
			return nil, invalidPlanf("intra_target_networks[%d]: %v", i, err)
		}
		minBits := minIntraTargetV4Bits
		if p.Addr().Is6() {
			minBits = minIntraTargetV6Bits
		}
		if p.Bits() < minBits {
			return nil, invalidPlanf("intra_target_networks[%d] is %q, which is wider than /%d; "+
				"a local network that wide is a containment bypass, not a Compose bridge",
				i, p.String(), minBits)
		}
		for _, probe := range probes {
			if p.Contains(probe.Addr) {
				return nil, invalidPlanf("intra_target_networks[%d] is %q, which contains the "+
					"cloud metadata address %s; that is the one destination containment exists "+
					"to block", i, p.String(), probe.Addr)
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// splitAllowEntries partitions scope.additional_egress_allow into the entries
// nftables can express (addresses and CIDRs) and the ones it cannot
// (hostnames), and REFUSES any address entry that lands on a metadata address.
//
// "ANY ADDRESS ENTRY" MEANS ANY SPELLING OF ONE. Every entry goes through
// canonicalAddr / canonicalPrefix before the metadata comparison, because the
// comparison is netip.Prefix.Contains and Contains is spelling-sensitive: this
// function's doc made exactly the claim above while accepting
// "::ffff:169.254.169.254/128" and emitting an accept rule for it.
func splitAllowEntries(m *target.Manifest) ([]netip.Prefix, []string, error) {
	if m.Scope == nil {
		return nil, nil, nil
	}
	probes := MetadataProbes()
	var expressed []netip.Prefix
	var unexpressed []string
	for i, raw := range m.Scope.AdditionalEgressAllow {
		field := fmt.Sprintf("scope.additional_egress_allow[%d]", i)
		var pfx netip.Prefix
		switch {
		case strings.Contains(raw, "/"):
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, nil, invalidPlanf("%s %q is not a CIDR prefix: %v", field, raw, err)
			}
			if p.Masked() != p {
				return nil, nil, invalidPlanf("%s %q has host bits set; write it masked (%q)",
					field, raw, p.Masked().String())
			}
			c, cerr := canonicalPrefix(p)
			if cerr != nil {
				return nil, nil, invalidPlanf("%s: %v", field, cerr)
			}
			pfx = c
		default:
			a, err := netip.ParseAddr(raw)
			if err != nil {
				// D.1 already validated this as an address, a CIDR or a
				// hostname, so anything left is a hostname.
				unexpressed = append(unexpressed, raw)
				continue
			}
			a = canonicalAddr(a)
			if !a.IsValid() {
				return nil, nil, invalidPlanf("%s %q does not canonicalize to an address", field, raw)
			}
			pfx = netip.PrefixFrom(a, a.BitLen())
		}
		for _, probe := range probes {
			if pfx.Contains(probe.Addr) {
				return nil, nil, invalidPlanf("%s %q covers the cloud metadata address %s; "+
					"the metadata drop is not negotiable and a scope entry may not ask for it",
					field, raw, probe.Addr)
			}
		}
		expressed = append(expressed, pfx)
	}
	return expressed, unexpressed, nil
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

// SetupNetns installs the default-deny egress ruleset into the target's
// network namespace.
//
// NOBODY CALLS IT YET, AND NOTHING COMPOSES THE TWO HALVES OF THIS PACKAGE.
// Provision seals a Target as booted_clean without any network namespace being
// involved: it never calls this function and never calls AssertContainment, and
// a repository-wide grep finds no caller of any of the three outside this
// package's own tests. So booted_clean today means "the container is contained
// by gVisor" and does NOT mean "its egress is default-deny". Wiring that is the
// integration packet's, not this one's, and it is recorded in
// internal/SKIPPED-CONTROLS.md as U1c so it cannot be forgotten -- including
// D.12's criterion that AssertContainment must run BEFORE any probe engine
// starts.
//
// It DOES NOT assert containment. That is deliberate and it is the whole
// reason AssertContainment is a separate exported function: if setup returned
// "installed and contained" in one step, a caller that ran setup once at
// provisioning time would have no reason to check again, and the failure this
// package exists to catch is a namespace that was configured correctly and is
// now not.
//
// Note the signature deviates from plan/50-dast.md's `SetupNetns(target
// *Target) error`: there is no `Target` type in the tree (D.1 landed
// `*target.Manifest`), and the Commander and context are what make the exec
// boundary injectable and cancellable. Reported to the orchestrator.
func SetupNetns(ctx context.Context, c Commander, p Plan) error {
	if c == nil {
		return invalidPlanf("SetupNetns was called with a nil Commander")
	}
	rs, err := BuildRuleset(p)
	if err != nil {
		return err
	}
	argv := []string{"ip", "netns", "exec", p.Netns.Name(), "nft", "-f", "-"}
	if _, err := c.Run(ctx, argv, []byte(rs.Script)); err != nil {
		return fmt.Errorf("%w: installing the containment ruleset in netns %q failed: %v",
			ErrContainment, p.Netns.Name(), err)
	}
	return nil
}

// ReadHostNetnsInode reads THIS process's network namespace inode, without
// entering any namespace. It is one half of the positive control's baseline.
func ReadHostNetnsInode(ctx context.Context, c Commander) (uint64, error) {
	if c == nil {
		return 0, invalidPlanf("ReadHostNetnsInode was called with a nil Commander")
	}
	out, err := c.Run(ctx, []string{"readlink", "/proc/self/ns/net"}, nil)
	if err != nil {
		return 0, fmt.Errorf("%w: reading the host network namespace inode failed: %v", ErrContainment, err)
	}
	return parseNetnsLink(string(out))
}

// ReadNetnsInode stats the named namespace file DIRECTLY, from the host, and
// deliberately NOT through `ip netns exec`.
//
// That is the point. If this read went through the same `ip netns exec` the
// canary later uses, then an `ip netns exec` that silently failed to switch
// namespaces would produce the same wrong inode twice and the two would agree.
// A positive control that shares a failure mode with the thing it controls is
// not a control.
func ReadNetnsInode(ctx context.Context, c Commander, name string) (uint64, error) {
	if c == nil {
		return 0, invalidPlanf("ReadNetnsInode was called with a nil Commander")
	}
	if err := checkNetnsName(name); err != nil {
		return 0, err
	}
	out, err := c.Run(ctx, []string{"stat", "-L", "-c", "%i", NetnsRunDir + "/" + name}, nil)
	if err != nil {
		return 0, fmt.Errorf("%w: stat of netns %q failed: %v", ErrContainment, name, err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: stat of netns %q returned %q, which is not an inode number",
			ErrContainment, name, strings.TrimSpace(string(out)))
	}
	if n == 0 {
		return 0, fmt.Errorf("%w: stat of netns %q returned inode 0", ErrContainment, name)
	}
	return n, nil
}

// parseNetnsLink reads the "net:[4026531840]" form readlink prints for a
// namespace symlink. It refuses anything else rather than salvaging a number
// out of it: a readlink that did not answer in this shape did not answer.
func parseNetnsLink(s string) (uint64, error) {
	t := strings.TrimSpace(s)
	const prefix = "net:["
	if !strings.HasPrefix(t, prefix) || !strings.HasSuffix(t, "]") {
		return 0, fmt.Errorf("%w: %q is not a network namespace link of the form net:[N]",
			ErrContainment, t)
	}
	n, err := strconv.ParseUint(t[len(prefix):len(t)-1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %q does not carry an inode number", ErrContainment, t)
	}
	if n == 0 {
		return 0, fmt.Errorf("%w: %q carries inode 0", ErrContainment, t)
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// The canary protocol
// ---------------------------------------------------------------------------

// CanarySubcommand is the argv[1] that puts the anvil-dast binary into canary
// mode. It is namespaced with a double underscore because it is not a user
// interface: it is an internal re-exec, and a name an operator might type by
// accident is a name that will be typed by accident.
const CanarySubcommand = "__anvil-dast-netns-canary"

// DefaultCanaryDialTimeout bounds one connect attempt. It is the contract a
// ConnectProbe implementation honours.
//
// It is short on purpose, and the asymmetry in the package doc is why that is
// safe rather than sloppy: a REACHABLE metadata endpoint is link-local and
// answers in well under a millisecond, so a timeout in this range can only
// convert a slow "blocked" into a "blocked" -- it can never convert a
// "reachable" into a "blocked".
//
// THAT ARGUMENT IS ONLY SOUND IF THE TIMEOUT IS ACTUALLY WAITED OUT, and this
// package does not hold the socket, so it cannot make a ConnectProbe wait. It
// used to not check either: every report was accepted without a single number
// in it, so a ConnectProbe built with a 50ms dialer -- an entirely plausible
// choice for a probe that expects to be blocked -- would have turned every
// silent timeout into "blocked" and the whole containment assertion into a
// green no-op that could not fail.
//
// So the canary now REPORTS its elapsed time per attempt and
// EvaluateCanaryReport refuses a silent-timeout verdict whose timing cannot
// support it. See minSilentTimeoutEvidence.
//
// The canary remains the UNTRUSTED half and this package cannot authenticate
// it: a substituted binary can write any number it likes. What the check buys
// is that the ordinary way this control rots -- an honest probe with too short
// a dialer -- now fails loudly. The rest is internal/SKIPPED-CONTROLS.md U1b.
const DefaultCanaryDialTimeout = 2 * time.Second

// canaryTimingTolerance is how much short of DefaultCanaryDialTimeout a
// genuine silent timeout may measure.
//
// It is not zero because the elapsed figure is wall-clock around the whole
// Attempt call and clock granularity is coarse on some platforms (Windows'
// default timer interval is ~15.6ms). It is small because its whole job is to
// be too small to admit a probe that did not wait: at 100ms against a 2s
// contract, a probe must show at least 1.9s, and the 50ms dialer above is
// refused by a factor of thirty-eight.
const canaryTimingTolerance = 100 * time.Millisecond

// minSilentTimeoutEvidence is the least elapsed time that makes
// DialFailureSilentTimeout mean anything.
//
// SILENCE IS ONLY EVIDENCE IF YOU LISTENED. A plain nftables `drop` answers
// nothing, so the dialer's own timer is what fires and the attempt must have
// consumed the full budget. An attempt that reported "nothing came back" after
// a fraction of the budget has not shown that nothing was coming -- it has
// shown that it stopped waiting, and a reply arriving one millisecond later
// would have been a REACHABLE metadata endpoint.
//
// The other two blocked failures are not subject to this: DialFailureNoRoute
// and DialFailurePolicyRejected are AFFIRMATIVE answers from the local kernel
// (ENETUNREACH, EPERM) and are correctly returned in microseconds. Applying a
// timing floor to them would refuse the fastest correct answers there are.
func minSilentTimeoutEvidence() time.Duration {
	return DefaultCanaryDialTimeout - canaryTimingTolerance
}

// maxCanaryAttemptMillis bounds a reported elapsed time from above.
//
// A probe declaring a 2s contract and reporting 11 minutes did not honour any
// bound this package can reason about, and a number that large is more likely
// a garbage field than a measurement. Above the bound the report is refused
// rather than believed; the direction is the same as everywhere else here --
// an answer this build cannot interpret is not a blocked answer.
const maxCanaryAttemptMillis = 60_000

// AttemptOutcome is what one connect attempt established.
//
// FAIL CLOSED: the zero value is AttemptOutcomeUnset, which is NOT contained.
// A report that arrived with an outcome field missing -- a truncated write, an
// older canary, a hand-edited fixture -- must abort the run, not pass it.
type AttemptOutcome string

const (
	// AttemptOutcomeUnset is the zero value and means NOTHING WAS
	// ESTABLISHED. EvaluateCanaryReport aborts on it.
	AttemptOutcomeUnset AttemptOutcome = ""

	// AttemptOutcomeReachable means the TCP handshake COMPLETED. This is the
	// abort the whole packet exists for.
	AttemptOutcomeReachable AttemptOutcome = "reachable"

	// AttemptOutcomeBlocked means the attempt was stopped by policy or had
	// nowhere to go: EPERM/EACCES (an nft drop with an admin-prohibited
	// answer), ENETUNREACH/EHOSTUNREACH (no route), or a silent timeout (a
	// plain nft `drop`, which answers nothing at all). This is the only
	// outcome that permits the run to continue.
	AttemptOutcomeBlocked AttemptOutcome = "blocked"

	// AttemptOutcomeIndeterminate means the attempt established neither.
	// ECONNREFUSED lives here and that is a deliberate call: a TCP RST means
	// the packet REACHED something that answered, so it is evidence of
	// delivery, not of containment. So does any error this package cannot
	// classify. EvaluateCanaryReport aborts on it.
	AttemptOutcomeIndeterminate AttemptOutcome = "indeterminate"
)

// Valid reports whether o is one of the three non-zero outcomes.
func (o AttemptOutcome) Valid() bool {
	switch o {
	case AttemptOutcomeReachable, AttemptOutcomeBlocked, AttemptOutcomeIndeterminate:
		return true
	}
	return false
}

// Attempt is one probe's result, as the canary reports it.
type Attempt struct {
	// Target is Probe.String() -- the address:port, canonically formatted.
	// EvaluateCanaryReport matches on THIS, by identity, never by position in
	// the slice. A report whose attempts arrived reordered, deduplicated or
	// padded must not be able to line up a "blocked" against the wrong probe.
	Target  string         `json:"target"`
	Outcome AttemptOutcome `json:"outcome"`
	Detail  string         `json:"detail"`

	// Failure is the RAW reason the ConnectProbe gave, carried alongside the
	// Outcome derived from it rather than instead of it.
	//
	// Both are reported so the RELATION between them can be pinned instead of
	// only the values: EvaluateCanaryReport recomputes
	// ClassifyDialFailure(Failure) and refuses any attempt whose Outcome does
	// not match. A report claiming "blocked" while naming "reset" is a report
	// from something that is not this build's canary, and it is refused
	// rather than half-believed.
	//
	// It is also what makes the timing rule expressible at all: "blocked"
	// alone cannot be checked for timing, because a no-route blocked is
	// correctly instantaneous and a silent-timeout blocked must not be.
	//
	// FAIL CLOSED: the zero value is DialFailureUnset, which classifies as
	// INDETERMINATE, so an attempt that omits this field aborts the run.
	Failure DialFailure `json:"failure"`

	// ElapsedMillis is how long the attempt took, measured by RunCanary
	// around the ConnectProbe call.
	//
	// It is the evidence behind a DialFailureSilentTimeout verdict, and
	// without it that verdict is an assertion that cannot fail. See
	// minSilentTimeoutEvidence.
	//
	// FAIL CLOSED: the zero value is 0, which is below every floor, so an
	// attempt that omits this field cannot produce a silent-timeout pass.
	ElapsedMillis int64 `json:"elapsed_ms"`
}

// CanaryReport is the canary's whole answer, written to stdout as one JSON
// object.
type CanaryReport struct {
	// NetnsInode is the inode of /proc/self/ns/net AS THE CANARY SEES IT.
	// This is the positive control's evidence.
	NetnsInode uint64 `json:"netns_inode"`

	// Attempts is one entry per probe.
	Attempts []Attempt `json:"attempts"`
}

// maxCanaryReportBytes bounds what the parser will accept.
const maxCanaryReportBytes = 64 << 10

// ParseCanaryReport decodes a canary report STRICTLY.
//
// DisallowUnknownFields, exactly one JSON value, and a byte cap. A lenient
// decoder here would let a report from some other program -- or a report from
// a future canary whose schema changed -- be read as a valid "blocked" answer.
func ParseCanaryReport(raw []byte) (CanaryReport, error) {
	if len(raw) == 0 {
		return CanaryReport{}, notContainedf("the canary produced no output; a canary that said " +
			"nothing has not shown that anything is blocked")
	}
	if len(raw) > maxCanaryReportBytes {
		return CanaryReport{}, notContainedf("the canary produced %d bytes; the cap is %d",
			len(raw), maxCanaryReportBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var rep CanaryReport
	if err := dec.Decode(&rep); err != nil {
		return CanaryReport{}, notContainedf("the canary's output is not a containment report: %v", err)
	}
	if dec.More() {
		return CanaryReport{}, notContainedf("the canary's output carries more than one JSON value")
	}
	return rep, nil
}

// EvaluateCanaryReport is the decision. It is PURE, and it is where every
// fail-closed rule in this package lives.
//
// It returns nil ONLY when all of the following hold:
//
//   - RULE 1 -- ns is constructed.
//   - RULE 2 -- rep.NetnsInode == ns.Inode(): the canary ran in the namespace
//     we configured.
//   - RULE 3 -- rep.NetnsInode != ns.HostInode(): `ip netns exec` genuinely
//     switched namespaces. Rules 2 and 3 are not redundant. Rule 3 follows
//     from rule 2 only because NewNetns already refused inode == hostInode,
//     and it is restated here so that a Netns assembled some other way in a
//     later refactor still cannot slip past.
//   - RULE 4 -- every probe in want appears in rep.Attempts EXACTLY ONCE,
//     matched by Target string identity.
//   - RULE 5 -- rep.Attempts carries NO attempt for anything not in want.
//   - RULE 6 -- every attempt's outcome is AttemptOutcomeBlocked.
//   - RULE 7 -- every attempt's Outcome AGREES with
//     ClassifyDialFailure(Attempt.Failure). The report carries both, and a
//     report whose two halves disagree is not this build's report.
//   - RULE 8 -- every attempt's ElapsedMillis is a usable measurement, and an
//     attempt blocked by DialFailureSilentTimeout waited at least
//     minSilentTimeoutEvidence. Silence is only evidence if you listened.
//
// Anything else is ErrNotContained. There is no warning path and no partial
// credit: rule 4 in particular means a canary that quietly stopped probing
// IPv6 aborts the run rather than reporting a clean IPv4 answer.
func EvaluateCanaryReport(ns Netns, want []Probe, rep CanaryReport) error {
	if !ns.Constructed() {
		return notContainedf("the namespace handle is a zero value; containment cannot be " +
			"asserted against a namespace that was never identified")
	}
	if len(want) == 0 {
		return notContainedf("no probe targets were requested; a containment assertion that " +
			"checks nothing always passes, which is the failure this check exists to prevent")
	}
	if rep.NetnsInode == 0 {
		return notContainedf("the canary reported network namespace inode 0; it did not read its "+
			"own namespace, so there is no evidence it ran inside netns %q", ns.Name())
	}
	if rep.NetnsInode == ns.HostInode() {
		return notContainedf("the canary reported network namespace inode %d, which is the HOST's "+
			"namespace: `ip netns exec` did not switch namespaces and the canary probed the host, "+
			"not netns %q. Its results say nothing about the sandbox",
			rep.NetnsInode, ns.Name())
	}
	if rep.NetnsInode != ns.Inode() {
		return notContainedf("the canary reported network namespace inode %d but netns %q has "+
			"inode %d; the canary ran somewhere else and its results describe a different namespace",
			rep.NetnsInode, ns.Name(), ns.Inode())
	}

	// Match by IDENTITY, never by position. An index-matched allowlist loses
	// the moment the two slices are ordered differently, and the canary's
	// ordering is not something this side controls.
	byTarget := make(map[string][]Attempt, len(rep.Attempts))
	for _, a := range rep.Attempts {
		byTarget[a.Target] = append(byTarget[a.Target], a)
	}
	wanted := make(map[string]bool, len(want))
	for _, p := range want {
		wanted[p.String()] = true
	}
	for _, p := range want {
		key := p.String()
		got := byTarget[key]
		switch {
		case len(got) == 0:
			return notContainedf("the canary reported no attempt against %s. A probe that was "+
				"not attempted has not been shown to be blocked", key)
		case len(got) > 1:
			return notContainedf("the canary reported %d attempts against %s; exactly one is "+
				"expected and duplicates make the answer ambiguous", len(got), key)
		}
		a := got[0]
		// THE ORDER OF THE THREE BLOCKS BELOW IS DELIBERATE, and each one
		// exists so a refusal names the thing that is actually wrong. Every
		// path here aborts; what differs is what the operator is told, and a
		// reachable metadata endpoint reported as a schema problem is a
		// message nobody acts on.
		//
		//   1. REACHABLE first. A reachable attempt carries no DialFailure by
		//      construction (RunCanary lets "connected" win over any reported
		//      failure), so the agreement check in step 3 would refuse it as
		//      "the two halves disagree" and bury the one message in this
		//      package that has to be read.
		//   2. The outcome VALUE next -- absent, or a literal this build does
		//      not know. Both would also fail the agreement check, and
		//      "carries no outcome" is what an operator can act on.
		//   3. Then the evidence: the outcome must agree with the reported
		//      failure reason, and the timing must be able to support it.
		if a.Outcome == AttemptOutcomeReachable {
			return notContainedf("THE SANDBOX CAN REACH %s. Cloud instance metadata is reachable "+
				"from inside netns %q, so an SSRF in the target would hand out credentials. "+
				"The scan is aborted. Canary detail: %s", key, ns.Name(), a.Detail)
		}
		if a.Outcome == AttemptOutcomeUnset {
			return notContainedf("the canary's attempt against %s carries no outcome; an absent "+
				"outcome is not a blocked outcome", key)
		}
		if !a.Outcome.Valid() {
			return notContainedf("the canary's attempt against %s carries outcome %q, which this "+
				"build does not recognise", key, string(a.Outcome))
		}
		if err := checkAttemptEvidence(ns, key, a); err != nil {
			return err
		}
		switch a.Outcome {
		case AttemptOutcomeBlocked:
			// The only passing case.
		case AttemptOutcomeIndeterminate:
			return notContainedf("the canary could not establish whether %s is reachable from "+
				"netns %q (%s). Unknown is not contained", key, ns.Name(), a.Detail)
		default:
			// Unreachable: the three checks above have already accounted for
			// every AttemptOutcome literal. It is here because a literal
			// added to the enum and forgotten in this switch must refuse, not
			// fall through into the "blocked" path.
			return notContainedf("the canary's attempt against %s carries outcome %q, which this "+
				"build's evaluation does not handle", key, string(a.Outcome))
		}
	}
	// Extras. A report carrying attempts nobody asked for is a report from
	// something other than the canary this build launched, and it is refused
	// rather than filtered -- filtering would mean accepting the parts of an
	// untrusted answer that happen to look right.
	extras := make([]string, 0)
	for tgt := range byTarget {
		if !wanted[tgt] {
			extras = append(extras, tgt)
		}
	}
	if len(extras) > 0 {
		sort.Strings(extras)
		return notContainedf("the canary reported attempts against %s, which were not requested; "+
			"this is not the report this build asked for", strings.Join(extras, ", "))
	}
	return nil
}

// checkAttemptEvidence is RULES 7 and 8: the reported verdict must agree with
// the reported reason, and the reported timing must be able to support the
// reported reason.
//
// It exists because the package's safety argument used to rest on a number
// nobody carried and a classification nobody re-derived. Both halves are now
// in the report and both are re-checked here, on the host side, where the
// decision is made -- not in the canary, which is the untrusted half.
//
// It is not called for AttemptOutcomeReachable; see the caller.
func checkAttemptEvidence(ns Netns, key string, a Attempt) error {
	// RULE 7. Recompute rather than trust. The canary reports both halves and
	// this side owns the mapping, so a canary that classified differently --
	// an older build, a different program, an edited fixture -- is caught
	// here instead of having its verdict taken at face value.
	wantOutcome, _ := ClassifyDialFailure(a.Failure)
	if a.Outcome != wantOutcome {
		return notContainedf("the canary's attempt against %s reports outcome %q for failure "+
			"reason %q, and this build classifies that reason as %q. The report's own two "+
			"halves disagree, so it is not the report this build asked for",
			key, string(a.Outcome), string(a.Failure), string(wantOutcome))
	}

	// RULE 8, first half: the number has to be a measurement.
	if a.ElapsedMillis < 0 {
		return notContainedf("the canary's attempt against %s reports %d ms elapsed; a negative "+
			"duration is not a measurement", key, a.ElapsedMillis)
	}
	if a.ElapsedMillis > maxCanaryAttemptMillis {
		return notContainedf("the canary's attempt against %s reports %d ms elapsed and the cap "+
			"is %d ms. The probe declared a %s bound and did not honour anything like it, so "+
			"nothing it reports about netns %q can be interpreted against that bound",
			key, a.ElapsedMillis, maxCanaryAttemptMillis, DefaultCanaryDialTimeout, ns.Name())
	}

	// RULE 8, second half: SILENCE IS ONLY EVIDENCE IF YOU LISTENED.
	if a.Failure == DialFailureSilentTimeout {
		floor := minSilentTimeoutEvidence()
		if time.Duration(a.ElapsedMillis)*time.Millisecond < floor {
			return notContainedf("the canary's attempt against %s reports a silent timeout after "+
				"%d ms, and a silent timeout is only evidence of a packet drop if the attempt "+
				"waited out its declared %s bound (at least %d ms here). A probe that stopped "+
				"listening early has shown that it stopped listening, not that %s is "+
				"unreachable from netns %q -- a reply arriving a millisecond later would have "+
				"been a REACHABLE metadata endpoint",
				key, a.ElapsedMillis, DefaultCanaryDialTimeout, floor.Milliseconds(), key, ns.Name())
		}
	}
	return nil
}

// AssertContainment is the gate. It runs ON EVERY SCAN -- there is no flag, no
// cache, no "fast mode" that skips it, and no first-run-only path -- because a
// namespace that was contained at provisioning time and is not now looks
// identical from outside.
//
// canaryPath is the absolute path to the anvil-dast binary that will be
// re-executed inside the namespace. It is a parameter rather than an
// os.Executable() call inside this function so that the caller owns the
// decision and the function stays testable.
func AssertContainment(ctx context.Context, c Commander, ns Netns, canaryPath string) error {
	if c == nil {
		return notContainedf("AssertContainment was called with a nil Commander; containment " +
			"cannot be asserted without running the canary")
	}
	if !ns.Constructed() {
		return notContainedf("AssertContainment was called with a zero-value Netns")
	}
	if canaryPath == "" {
		return notContainedf("AssertContainment was called with an empty canary path; there is "+
			"nothing to launch inside netns %q", ns.Name())
	}
	argv := []string{"ip", "netns", "exec", ns.Name(), canaryPath, CanarySubcommand}
	out, err := c.Run(ctx, argv, nil)
	if err != nil {
		// A canary that would not launch is NOT a clean run. This is the
		// branch that would otherwise become "well, we could not check, carry
		// on".
		return notContainedf("the containment canary could not be run in netns %q: %v. "+
			"Anvil will not treat a canary that did not run as evidence of containment",
			ns.Name(), err)
	}
	rep, err := ParseCanaryReport(out)
	if err != nil {
		return err
	}
	return EvaluateCanaryReport(ns, MetadataProbes(), rep)
}

// ---------------------------------------------------------------------------
// The canary itself -- this half runs INSIDE the namespace
// ---------------------------------------------------------------------------

// WHY THERE IS NO DIALER IN THIS PACKAGE, AND NO `net` IMPORT
//
// The authorization kernel's GATE 3 (the egress choke point, D.2/D.5) refuses
// any socket construction inside `internal/dast` outside
// `internal/dast/authz`, and it says in terms that there is no allowlist for
// it and no code path that can add one. plan/00-SPINE.md S7 is the reason: a
// socket the kernel did not open is a handle it did not authorize.
//
// The first draft of this file dialled the metadata endpoints with net.Dialer
// and gate 3 caught it -- 13 findings, correctly. The gate is right and the
// draft was wrong, so the seam moved rather than the gate.
//
// It could not move by "routing the canary through Adjudicate" as gate 3's
// message suggests, because the canary's whole purpose is to attempt a
// connection the kernel MUST refuse: 169.254.169.254 is gate 10's canonical
// refusal, so an authorized dial to it is a contradiction. What moved instead
// is the capability itself. ConnectProbe is a function value crossing a
// package boundary -- gate 3's own header names this as limit 2 and notes that
// whoever SUPPLIES the capability is the one flagged. This package supplies
// nothing: it holds the rules, the report schema and the verdict, and it is
// structurally incapable of holding a network handle, which is a stronger
// statement of S7 than a comment promising not to.
//
// ConnectProbe attempts ONE TCP connection and returns a verdict. It never
// returns a connection, so there is no handle for this package or anything
// downstream of it to hold.
//
// The implementation belongs to the anvil-dast binary (D.14/D.15). It will be
// flagged by gate 3's tier 2 and must be added to nonKernelEgressAllowlist
// with a justification -- which is exactly the review gate 3 exists to force,
// and is reported to the orchestrator rather than done here.
type ConnectProbe interface {
	// Attempt tries to connect to address over network ("tcp4" or "tcp6")
	// within DefaultCanaryDialTimeout.
	//
	// connected reports ONLY whether the TCP handshake completed. failure
	// describes why it did not, in this package's platform-independent
	// vocabulary; the errno table that produces it lives with the
	// implementation, because errnos are a property of the platform and the
	// classification RULES are a property of the gate.
	Attempt(ctx context.Context, network, address string) (connected bool, failure DialFailure, detail string)
}

// DialFailure is why a connect did not complete, named rather than numbered.
//
// FAIL CLOSED: the zero value is DialFailureUnset, which classifies as
// INDETERMINATE and therefore aborts. A probe implementation that forgot to
// set it -- or an older one that did not have the field -- must not be able to
// produce a "blocked".
type DialFailure string

const (
	// DialFailureUnset is the zero value. It means the implementation said
	// nothing, which is not the same as saying "blocked".
	DialFailureUnset DialFailure = ""

	// DialFailurePolicyRejected: the kernel refused the connect outright.
	// On Linux this is EPERM or EACCES, which is what an nftables `reject`
	// with an admin-prohibited answer produces.
	DialFailurePolicyRejected DialFailure = "policy_rejected"

	// DialFailureNoRoute: nothing in the namespace routes towards the
	// address. On Linux, ENETUNREACH / EHOSTUNREACH / ENETDOWN.
	DialFailureNoRoute DialFailure = "no_route"

	// DialFailureSilentTimeout: the attempt expired with NO reply of any
	// kind. This is the signature of a plain nftables `drop`, which discards
	// the packet and sends nothing back, so the dialer's own timer is what
	// fires.
	DialFailureSilentTimeout DialFailure = "silent_timeout"

	// DialFailureReset: the connect was refused with a TCP RST
	// (ECONNREFUSED). THIS IS NOT CONTAINMENT -- see ClassifyDialFailure.
	DialFailureReset DialFailure = "reset"

	// DialFailureCancelled: the surrounding context ended before the attempt
	// concluded. The caller's clock running out is not a network verdict.
	DialFailureCancelled DialFailure = "cancelled"

	// DialFailureUnclassified: the implementation could not place the error.
	DialFailureUnclassified DialFailure = "unclassified"
)

// ClassifyDialFailure maps a DialFailure onto an AttemptOutcome.
//
// This function is the security-critical half of the classification and it
// lives HERE, next to the gate that acts on it, rather than with the socket.
// The rule it exists to pin is the one a reasonable person gets wrong:
// DialFailureReset is INDETERMINATE, not blocked. A TCP RST is a reply, so
// something received the packet; a containment layer that read "something
// answered" as "nothing is reachable" would be reading delivery as safety.
//
// Every case this build does not recognise lands on INDETERMINATE, which
// aborts. There is no default that continues.
func ClassifyDialFailure(f DialFailure) (AttemptOutcome, string) {
	switch f {
	case DialFailurePolicyRejected:
		return AttemptOutcomeBlocked, "the kernel refused the connect outright (a firewall reject)"
	case DialFailureNoRoute:
		return AttemptOutcomeBlocked, "no route leaves the namespace towards this address"
	case DialFailureSilentTimeout:
		return AttemptOutcomeBlocked, "the connect expired with no reply of any kind, which is " +
			"what a silent packet drop looks like"
	case DialFailureReset:
		return AttemptOutcomeIndeterminate, "the connect was refused with a TCP reset, which means " +
			"the packet reached something that answered; that is evidence of delivery, not of containment"
	case DialFailureCancelled:
		return AttemptOutcomeIndeterminate, "the attempt was cancelled or its deadline expired " +
			"before it concluded; the caller's clock running out is not a network verdict"
	case DialFailureUnclassified:
		return AttemptOutcomeIndeterminate, "the probe could not classify the failure"
	case DialFailureUnset:
		return AttemptOutcomeIndeterminate, "the probe reported no reason for the failure; an " +
			"absent reason is not a blocked reason"
	}
	return AttemptOutcomeIndeterminate, "the probe reported failure reason " + string(f) +
		", which this build does not recognise"
}

// RunCanary performs the attempts and returns the report. inode is the
// canary's own namespace inode, read by the caller (CanaryMain) so that this
// function holds no capability of its own.
//
// IT TIMES EVERY ATTEMPT, and the timing is what makes a silent-timeout verdict
// checkable on the host side. The measurement is taken HERE rather than being
// asked of the ConnectProbe, because a probe that reports its own honesty is
// not a measurement of it: this loop brackets the call it does not control.
//
// It is still the canary reporting on itself and the canary is the untrusted
// half -- a substituted binary can write any number it likes. What the number
// buys is that the ordinary way this control rots, a ConnectProbe built with a
// dialer shorter than DefaultCanaryDialTimeout, now fails loudly instead of
// producing a green verdict. That is the difference between an assertion and a
// no-op, and it is not the same thing as authenticating the canary.
func RunCanary(ctx context.Context, probe ConnectProbe, inode uint64, probes []Probe) CanaryReport {
	rep := CanaryReport{NetnsInode: inode, Attempts: make([]Attempt, 0, len(probes))}
	for _, p := range probes {
		// tcp4/tcp6 explicitly, never "tcp". "tcp" lets the stack choose a
		// family, and a probe that silently fell back would report "blocked"
		// for a family it never tried.
		network := "tcp4"
		if p.Addr.Is6() {
			network = "tcp6"
		}
		started := time.Now()
		connected, failure, detail := probe.Attempt(ctx, network, p.String())
		elapsed := time.Since(started).Milliseconds()
		if elapsed < 0 {
			// A clock that ran backwards. Report it as it measured rather
			// than clamping: EvaluateCanaryReport refuses a negative elapsed,
			// and a silently clamped 0 would be refused with a message about
			// the wrong thing.
			elapsed = -1
		}
		if connected {
			// Reachable wins over any reported failure. That is the
			// fail-closed direction: a probe that both connected and reported
			// a failure is confused, and the confused reading that aborts is
			// the safe one.
			// Failure is left UNSET on a reachable attempt, deliberately: the
			// probe's failure reason is meaningless once the handshake
			// completed, and EvaluateCanaryReport decides reachable before it
			// checks the outcome/failure agreement precisely so this case
			// aborts with the reachability message and not a schema one.
			rep.Attempts = append(rep.Attempts, Attempt{
				Target:        p.String(),
				Outcome:       AttemptOutcomeReachable,
				Detail:        "the TCP handshake completed",
				ElapsedMillis: elapsed,
			})
			continue
		}
		outcome, why := ClassifyDialFailure(failure)
		if detail != "" {
			why = why + " (" + detail + ")"
		}
		rep.Attempts = append(rep.Attempts, Attempt{
			Target:        p.String(),
			Outcome:       outcome,
			Detail:        why,
			Failure:       failure,
			ElapsedMillis: elapsed,
		})
	}
	return rep
}

// CanaryMain is the in-namespace entry point. The anvil-dast binary wires it
// to CanarySubcommand and supplies the ConnectProbe; both halves of that
// wiring belong to the packaging packet, not to this one.
//
// It writes the report to w and returns a process exit code. The exit code is
// ALWAYS 0 when a report was written, including when a probe was reachable:
// the verdict belongs to EvaluateCanaryReport on the host side, and a canary
// that also rendered a verdict would give a caller two places to read the
// answer from -- and one of them would eventually be the only one checked.
//
// A nil ConnectProbe is a REFUSAL, not an empty report. A canary that wrote
// `{"attempts":[]}` would be handed to EvaluateCanaryReport, which would abort
// on the missing attempts -- but it would abort with "no attempt against
// 169.254.169.254:80" rather than "this binary was built without a probe", and
// the operator deserves the second message.
func CanaryMain(ctx context.Context, w io.Writer, probe ConnectProbe) int {
	if probe == nil {
		fmt.Fprintln(os.Stderr, "anvil-dast canary: no connect probe was supplied; this binary "+
			"cannot test reachability and will not pretend to")
		return 2
	}
	link, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		fmt.Fprintf(os.Stderr, "anvil-dast canary: cannot read /proc/self/ns/net: %v\n", err)
		return 2
	}
	inode, err := parseNetnsLink(link)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anvil-dast canary: %v\n", err)
		return 2
	}
	rep := RunCanary(ctx, probe, inode, MetadataProbes())
	enc := json.NewEncoder(w)
	if err := enc.Encode(rep); err != nil {
		fmt.Fprintf(os.Stderr, "anvil-dast canary: cannot write the report: %v\n", err)
		return 2
	}
	return 0
}

// ---------------------------------------------------------------------------
// The relation this package must keep with the authorization kernel
// ---------------------------------------------------------------------------

// GateTenAgreesWith reports whether the containment deny set is at least as
// strict as the authorization kernel's gate 10 for this address.
//
// It exists so the relation can be pinned rather than the values: gate 10 owns
// the reserved-range denylist for the HTTP layer, this package owns it for the
// network layer, and the two lists were written from the same source. The one
// direction that matters is that the network layer is never WEAKER -- an
// address gate 10 calls reserved must be one the ruleset drops. The reverse is
// allowed: the ruleset may drop more.
//
// It is exported and lives in the non-test file because it is not test-only
// scaffolding -- a caller assembling a plan can ask it directly.
//
// BOTH SIDES ARE ASKED ABOUT THE SAME CANONICAL ADDRESS. Handing the raw
// spelling to one side and the canonical one to the other would compare two
// different questions, and the answer would drift with the spelling rather than
// with the address.
//
// It matters in a direction worth naming, because it is a live blind spot and
// not a hypothetical: authz.AddressIsReserved walks netip prefixes first and
// falls back to the Go runtime's own classification, and NEITHER layer sees a
// zoned address in the NAT64, 6to4 or unspecified ranges. MEASURED on
// go1.26.5: AddressIsReserved reports reserved=false for "64:ff9b::1.2.3.4%eth0",
// "2002:c000:204::1%eth0" and "::%eth0", and reserved=true for the same three
// with the zone removed. Canonicalizing here means the containment layer asks
// gate 10 the question gate 10 can actually answer.
//
// That blind spot is in internal/dast/authz, which this packet does not write.
// It is reported to the orchestrator rather than patched from here, and
// TestGateTenHasAZoneBlindSpotThisPackageCanonicalizesAround pins the measured
// behaviour so the report cannot rot into a claim nobody can check.
func GateTenAgreesWith(addr netip.Addr) bool {
	a := canonicalAddr(addr)
	_, reserved := authz.AddressIsReserved(a)
	if !reserved {
		return true
	}
	return DeniedByRuleset(a)
}
