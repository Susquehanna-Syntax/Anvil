// Package bootstrap fills a feed's ingestion cache ONCE, from a bulk artifact,
// so that the conditional-GET poller only ever has to carry deltas.
package bootstrap
