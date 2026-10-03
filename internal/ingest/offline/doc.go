// Package offline imports a feed snapshot from a directory into the advisory
// cache, with no network: the path an air-gapped installation takes, and the
// path the Lane A fixture takes so `anvil scan` can be proven without one.
//
// It is not a second ingestion path. Every byte goes through the same gates the
// live poller uses: the feed table through internal/ingest/config, the licence
// through internal/ingest/license against the snapshot's own mirror (pinned
// bodies, digests checked), and each document through delta.Decode and
// delta.Apply, so the sanitizer, the decoders and the cache's constraints all
// run. A feed the licence gate refuses imports nothing.
package offline
