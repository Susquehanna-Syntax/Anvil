// Package recall is Lane B's recall tier (plan nodes recall, opengrep and
// candidatelist): it runs the vendored rule corpora through opengrep, and gosec
// and bandit natively, each as a subprocess, and turns what they report into
// candidates that carry their rule's provenance. It decides nothing about a
// candidate: every one is a rule match nobody has judged.
package recall
