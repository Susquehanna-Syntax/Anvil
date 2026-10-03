package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleRecord = `{"version":"2.1.0","runs":[{"results":[{"ruleId":"anvil.sca/v1","message":{"text":"x"}}]}]}`

func TestPayloadRoundTripsAndHashesTheCanonicalJSON(t *testing.T) {
	in := []byte(strings.Repeat(sampleRecord, 50))
	payload, sum, err := EncodePayload(in)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(in)
	if sum != hex.EncodeToString(want[:]) {
		t.Fatalf("payload_sha256 = %s, want the SHA-256 of the canonical JSON", sum)
	}
	// zstd's frame magic, little-endian 0xFD2FB528: the column holds zstd and
	// nothing else.
	if !bytes.HasPrefix(payload, []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		t.Fatalf("payload does not start with the zstd frame magic: % x", payload[:4])
	}
	if len(payload) >= len(in) {
		t.Errorf("a repetitive %d-byte record compressed to %d bytes", len(in), len(payload))
	}
	out, err := DecodePayload(payload, sum)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, in) {
		t.Fatal("round trip changed the bytes")
	}
}

// The same record must always produce the same column bytes, or two writers
// of one record disagree about what was stored.
func TestPayloadEncodingIsDeterministic(t *testing.T) {
	in := []byte(strings.Repeat(sampleRecord, 200))
	first, _, err := EncodePayload(in)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, _, err := EncodePayload(in)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("encoding %d differs from the first", i+2)
		}
	}
}

func TestPayloadDecodeRefuses(t *testing.T) {
	payload, sum, err := EncodePayload([]byte(sampleRecord))
	if err != nil {
		t.Fatal(err)
	}
	other := sha256.Sum256([]byte("another record"))

	if _, err := DecodePayload(payload, hex.EncodeToString(other[:])); !errors.Is(err, ErrPayloadDigest) {
		t.Errorf("a payload under the wrong hash: err = %v, want ErrPayloadDigest", err)
	}
	if _, err := DecodePayload(payload, "not-hex"); !errors.Is(err, ErrPayloadDigest) {
		t.Errorf("a malformed hash: err = %v, want ErrPayloadDigest", err)
	}
	corrupt := append([]byte(nil), payload...)
	corrupt[len(corrupt)/2] ^= 0xff
	if _, err := DecodePayload(corrupt, sum); err == nil {
		t.Error("a corrupted payload decoded")
	}
	if _, err := DecodePayload([]byte(sampleRecord), sum); err == nil {
		t.Error("uncompressed JSON in the payload column decoded as if it were zstd")
	}
	if _, _, err := EncodePayload(nil); err == nil {
		t.Error("an empty payload was encoded")
	}
}

// A payload that decompresses past MaxPayloadBytes is refused, however small
// it is on disk. This builds a real bomb: 300 MiB of zeros compresses to a
// few kilobytes.
func TestPayloadDecodeRefusesABomb(t *testing.T) {
	big := make([]byte, MaxPayloadBytes+44<<20)
	bomb := payloadEncoder.EncodeAll(big, nil)
	t.Logf("%d bytes of zeros compress to %d", len(big), len(bomb))
	sum := sha256.Sum256(big)
	if _, err := DecodePayload(bomb, hex.EncodeToString(sum[:])); err == nil {
		t.Fatal("a payload over MaxPayloadBytes decoded")
	}
}

// TestThePayloadCodecIsThePinnedModule: the codec is pinned at the version
// whose licence bodies third_party/klauspost-compress/PIN.md records, by the
// module hash go.sum carries for it. A different version or hash is a
// dependency change nobody re-read.
func TestThePayloadCodecIsThePinnedModule(t *testing.T) {
	const (
		require = "github.com/klauspost/compress v1.20.1"
		sum     = "github.com/klauspost/compress v1.20.1 h1:T7kKElXUMXrUJ2E9QhQhxFtcK5rPyLdsGZvdbLMPdiQ="
	)
	mod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod, so the pin is UNCHECKED: %v", err)
	}
	gosum, err := os.ReadFile(filepath.Join("..", "..", "go.sum"))
	if err != nil {
		t.Fatalf("reading go.sum, so the pin is UNCHECKED: %v", err)
	}
	if !strings.Contains(string(mod), "\t"+require+"\n") {
		t.Errorf("go.mod does not require %q; the codec moved without its licence being re-read", require)
	}
	if !strings.Contains(string(gosum), sum+"\n") {
		t.Errorf("go.sum does not carry %q", sum)
	}
	if strings.Contains(string(mod), "replace github.com/klauspost/compress") {
		t.Error("go.mod replaces the codec module")
	}
}

// TestTheCodecLicenceBodiesAreArchived re-hashes the licence bodies
// third_party/klauspost-compress/PIN.md records. A body that changed is a
// determination nobody re-made.
func TestTheCodecLicenceBodiesAreArchived(t *testing.T) {
	dir := filepath.Join("..", "..", "third_party", "klauspost-compress")
	for name, want := range map[string]string{
		"LICENSE":                          "0d9e582ee4bff57bf1189c9e514e6da7ce277f9cd3bc2d488b22fbb39a6d87cf",
		"zstd-internal-xxhash-LICENSE.txt": "f566a9f97bacdaf00d9f21dd991e81dc11201c4e016c86b470799429a1c9a79c",
		"internal-snapref-LICENSE":         "f69f157b0be75da373605dbc8bbf142e8924ee82d8f44f11bcaf351335bf98cf",
	} {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s hashes to %s, but PIN.md records %s", name, got, want)
		}
	}
}
