// This file is the SAST half's spec harvest: it finds the API specifications
// a repository checks in (OpenAPI, Swagger, AsyncAPI, GraphQL SDL, WSDL,
// Postman collections) and carries them on the SAST run, where the dynamic
// tier's repo spec reader picks them up. plan/design/dynamic-tier.md:628-630
// makes harvesting the SAST tier's job and forbids the DAST tier from doing
// it, so this is the only place a checked-in spec enters Anvil.
//
// It CLAIMS NO FORMAT. declaredFormat is left empty: the repo spec reader
// classifies from the bytes, and its format vocabulary is the dynamic tier's
// growing allowlist, which the core binary does not import (TestSplit) and
// must not copy.
//
// IT ACCOUNTS FOR WHAT IT DROPS. A spec file it found and did not carry
// (larger than MaxSpecBytes, not valid UTF-8, or past MaxSpecFiles) is counted
// in omittedFileCount, never silently left out: a missing spec shrinks the
// DAST coverage denominator, and a smaller denominator reads as better
// coverage.

package laneb

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// MaxSpecBytes is the largest spec file carried, the repo spec reader's own
// per-file bound (4 MiB).
const MaxSpecBytes = 4 << 20

// MaxSpecFiles is the most spec files one harvest carries, the repo spec
// reader's per-ingest bound.
const MaxSpecFiles = 4096

// IsSpecFile reports whether a file name is one the harvest carries.
func IsSpecFile(name string) bool {
	n := strings.ToLower(name)
	for _, base := range []string{"openapi", "swagger", "asyncapi"} {
		for _, ext := range []string{".json", ".yaml", ".yml"} {
			if n == base+ext || strings.HasSuffix(n, "."+base+ext) {
				return true
			}
		}
	}
	for _, ext := range []string{".graphql", ".graphqls", ".gql", ".wsdl", ".postman_collection.json"} {
		if strings.HasSuffix(n, ext) {
			return true
		}
	}
	return false
}

// Harvest walks root and returns the SAST run's anvil/specHarvest. It never
// follows a symbolic link and never enters .git. An error walking the tree is
// returned, never reported as an empty harvest.
func Harvest(root string) (*record.SpecHarvest, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var found []string
	err = filepath.WalkDir(abs, func(full string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" && full != abs {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() && IsSpecFile(d.Name()) {
			found = append(found, full)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(found)
	h := &record.SpecHarvest{Outcome: record.SpecHarvestRan, Files: []record.SpecHarvestFile{}}
	omitted := 0
	for _, full := range found {
		if len(h.Files) >= MaxSpecFiles {
			omitted++
			continue
		}
		st, err := os.Lstat(full)
		if err != nil {
			return nil, err
		}
		if st.Size() > MaxSpecBytes {
			omitted++
			continue
		}
		b, err := os.ReadFile(full)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(b) {
			omitted++
			continue
		}
		rel, _ := filepath.Rel(abs, full)
		sum := sha256.Sum256(b)
		h.Files = append(h.Files, record.SpecHarvestFile{
			Location:      record.ArtifactLocation{URI: filepath.ToSlash(rel)},
			SizeBytes:     len(b),
			ContentSHA256: hex.EncodeToString(sum[:]),
			Content:       &record.ArtifactContent{Text: string(b)},
			Trust:         record.TrustUntrusted,
		})
	}
	h.OmittedFileCount = &omitted
	if err := record.ValidateSpecHarvest(h); err != nil {
		return nil, err
	}
	return h, nil
}
