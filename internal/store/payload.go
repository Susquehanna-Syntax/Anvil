// This file is the audit payload codec: what `audit_record.payload` and
// `audit_record.payload_sha256` hold, and the one way to produce and read them.
//
// THE CODEC IS zstd, FROM github.com/klauspost/compress v1.20.1 (pure Go, no
// cgo, BSD-3-Clause; third_party/klauspost-compress/PIN.md records the licence
// bodies read and their hashes). The schema has said "zstd(canonical SARIF
// JSON)" since the store schema was written; no writer existed until plan node
// contractgaps, so the library was never chosen. It is pinned in go.sum, and
// TestThePayloadCodecIsThePinnedModule fails if the build links another
// version.
//
// WHAT THE HASH COVERS. payload_sha256 is the SHA-256 of the CANONICAL JSON,
// not of the compressed bytes. It is "proof of what was handed over" and it
// outlives the payload (the reaper NULLs payload at deadline_at and keeps the
// hash), so it has to identify the record itself: a hash of the compressed
// bytes would change with the encoder level or the library version while the
// record stayed the same. The canonical JSON is encoding/json's output for the
// record, which is deterministic for a struct (fixed field order, sorted map
// keys); the caller marshals, this file never re-marshals.
//
// WHAT DECODING REFUSES. A payload that does not decompress, decompresses to
// more than MaxPayloadBytes, or decompresses to bytes whose hash is not the
// stored one. The size bound is the decompression-bomb guard: a few kilobytes
// of zstd can claim gigabytes.

package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/klauspost/compress/zstd"
)

// MaxPayloadBytes bounds one decompressed audit payload: 256 MiB. GitHub's own
// SARIF upload limit is 10 MB compressed, and a record over this bound is a
// defect upstream of the store, not a payload to admit.
const MaxPayloadBytes = 256 << 20

// ErrPayloadDigest means the decompressed payload is not the record its row's
// payload_sha256 names.
var ErrPayloadDigest = errors.New("store: payload does not match payload_sha256")

// The encoder and decoder are stateless for EncodeAll/DecodeAll and safe for
// concurrent use; one of each serves the process. Concurrency 1 keeps the
// encoder's output a function of its input alone.
var (
	payloadEncoder = mustEncoder()
	payloadDecoder = mustDecoder()
)

func mustEncoder() *zstd.Encoder {
	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderConcurrency(1),
		zstd.WithEncoderCRC(true))
	if err != nil {
		panic(fmt.Sprintf("store: building the payload encoder: %v", err))
	}
	return enc
}

func mustDecoder() *zstd.Decoder {
	dec, err := zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(MaxPayloadBytes),
		zstd.WithDecoderMaxWindow(MaxPayloadBytes))
	if err != nil {
		panic(fmt.Sprintf("store: building the payload decoder: %v", err))
	}
	return dec
}

// EncodePayload compresses a record's canonical JSON for audit_record.payload
// and returns it with the payload_sha256 of the canonical JSON.
func EncodePayload(canonicalJSON []byte) (payload []byte, sha256Hex string, err error) {
	if len(canonicalJSON) == 0 {
		return nil, "", errors.New("store: refusing to encode an empty payload")
	}
	if len(canonicalJSON) > MaxPayloadBytes {
		return nil, "", fmt.Errorf("store: payload is %d bytes, over MaxPayloadBytes (%d)",
			len(canonicalJSON), MaxPayloadBytes)
	}
	sum := sha256.Sum256(canonicalJSON)
	return payloadEncoder.EncodeAll(canonicalJSON, nil), hex.EncodeToString(sum[:]), nil
}

// DecodePayload decompresses audit_record.payload and checks it against the
// row's payload_sha256. It returns the canonical JSON or an error, never
// bytes that failed either check.
func DecodePayload(payload []byte, wantSHA256Hex string) ([]byte, error) {
	out, err := payloadDecoder.DecodeAll(payload, nil)
	if err != nil {
		return nil, fmt.Errorf("store: decompressing the audit payload: %w", err)
	}
	if len(out) > MaxPayloadBytes {
		return nil, fmt.Errorf("store: payload decompresses to %d bytes, over MaxPayloadBytes", len(out))
	}
	sum := sha256.Sum256(out)
	want, err := hex.DecodeString(wantSHA256Hex)
	if err != nil || len(want) != sha256.Size || !bytes.Equal(sum[:], want) {
		return nil, ErrPayloadDigest
	}
	return out, nil
}
