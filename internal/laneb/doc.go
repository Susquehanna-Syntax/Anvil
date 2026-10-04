// Package laneb is the Lane B pipeline (plan node pipeline): it runs the
// recall tier over a repository, places every candidate on the record as an
// unconfirmed SAST finding with its rule's provenance, and hands any
// checked-in API specification to the dynamic tier's inventory through the
// SAST run's spec harvest. It owns the one mapping from a recall candidate to
// anvil/verdict, and that mapping has exactly one answer: unconfirmed.
package laneb
