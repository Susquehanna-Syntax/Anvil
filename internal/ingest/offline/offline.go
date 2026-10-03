package offline

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/delta"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/license"
)

// The snapshot directory's layout.
const (
	FeedTableFile = "feeds.yaml"    // the feed table, internal/ingest/config's format
	SnapshotFile  = "snapshot.json" // {"asOf": RFC 3339}: when the documents were captured
	MirrorDir     = "mirror"        // licence evidence, in the repository mirror/ layout
	DocumentsDir  = "advisories"    // advisories/<feed id>/*.json
)

// FeedReport is what one feed's import did.
type FeedReport struct {
	FeedID    string
	Refused   string // non-empty when the licence gate refused the feed
	Documents int
	Stats     delta.BatchStats
}

// Report is one import.
type Report struct {
	AsOf  time.Time
	Feeds []FeedReport
}

// Load reads the snapshot's feed table, for callers that need the feed rows
// (their freshness SLOs) without importing.
func Load(dir string) (config.FeedSet, error) {
	return config.Load(filepath.Join(dir, FeedTableFile))
}

// Import loads every enabled feed in the snapshot at dir into db.
func Import(ctx context.Context, db *sql.DB, dir string) (Report, error) {
	feeds, err := Load(dir)
	if err != nil {
		return Report{}, err
	}
	asOf, err := snapshotTime(dir)
	if err != nil {
		return Report{}, err
	}
	// The licence gate reads mirror/<tier>/... and mirror/LICENSE-MANIFEST.toml
	// relative to the root it is given, so it is given the snapshot root.
	mirror := os.DirFS(dir)
	rep := Report{AsOf: asOf}
	for _, f := range feeds.Feeds {
		if !f.Enabled {
			continue
		}
		fr := FeedReport{FeedID: f.ID}
		d, err := license.Resolve(license.FromFeed(f, "", mirror))
		if err != nil || d.Refused() {
			fr.Refused = fmt.Sprintf("the licence gate refused feed %q: %v", f.ID, err)
			rep.Feeds = append(rep.Feeds, fr)
			continue
		}
		docs, err := documents(filepath.Join(dir, DocumentsDir, f.ID))
		if err != nil {
			return rep, err
		}
		for _, p := range docs {
			raw, err := os.ReadFile(p)
			if err != nil {
				return rep, err
			}
			recs, _, err := delta.Decode(f.ID, raw)
			if err != nil {
				return rep, fmt.Errorf("offline: %s: %w", p, err)
			}
			st, err := delta.Apply(ctx, db, f, d, recs, asOf, 0)
			if err != nil {
				return rep, fmt.Errorf("offline: applying %s: %w", p, err)
			}
			fr.Stats.Merge(st)
			fr.Documents++
		}
		rep.Feeds = append(rep.Feeds, fr)
	}
	return rep, nil
}

func snapshotTime(dir string) (time.Time, error) {
	raw, err := os.ReadFile(filepath.Join(dir, SnapshotFile))
	if err != nil {
		return time.Time{}, fmt.Errorf("offline: a snapshot states when it was captured: %w", err)
	}
	var s struct {
		AsOf time.Time `json:"asOf"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return time.Time{}, fmt.Errorf("offline: %s: %w", SnapshotFile, err)
	}
	if s.AsOf.IsZero() {
		return time.Time{}, errors.New("offline: the snapshot's asOf is missing; an import with no data age would report it as fresh")
	}
	return s.AsOf.UTC(), nil
}

// documents lists a feed's documents in name order, so an import is
// deterministic.
func documents(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".json") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}
