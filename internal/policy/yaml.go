// This file is the policy file decoder: a deliberately small YAML subset, and
// Load, which turns a policy file on disk into a Policy.
//
// WHY A DECODER LIVES HERE. Anvil carries no YAML library, and FromDocument
// takes a generically decoded document, so until plan node cli there was no
// production way to read .anvil/policy.yml at all: the only decoder was a
// test helper. It is promoted here unchanged in what it accepts — block
// mappings, block sequences, flow collections, quoted and plain scalars — and
// hardened for what it now reads, which is a file from the repository under
// scan and therefore attacker-controlled:
//
//   - the file is refused past MaxPolicyBytes before it is parsed;
//   - nesting, block or flow, is refused past MaxPolicyNesting levels;
//   - anchors, aliases, tags, block scalars and directives are refused by
//     their leading indicator rather than read as plain text;
//   - tabs in indentation, document markers and duplicate keys are refused.
//
// Everything outside the subset is an error, never a guess, and FromDocument
// then applies the schema's own strictness to what was decoded.

package policy

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// MaxPolicyBytes bounds a policy file: 1 MiB. MaxScanRules x MaxListItems x
// MaxGlobPatternBytes allows far more text than any hand-written policy holds,
// and a file this size is already an attack or an accident.
const MaxPolicyBytes = 1 << 20

// MaxPolicyNesting bounds how deep a policy document nests. The schema's
// deepest legal path (scanRules -> rule -> dast -> key -> list) is five
// levels; 32 leaves room for future keys and none for a recursion attack.
const MaxPolicyNesting = 32

// yamlReservedIndicators are the characters YAML reserves at the start of a
// plain scalar for constructs outside this subset: & anchor, * alias, ! tag,
// | and > block scalars, % directive, and @ and the backtick reserved
// outright.
const yamlReservedIndicators = "&*!|>%@`"

// ErrPolicyFile reports a policy file that could not be read or decoded. It
// wraps the reason, with the line number when the decoder had one.
var ErrPolicyFile = errors.New("policy: unreadable policy file")

// DecodeYAML decodes a policy document written in the YAML subset this file
// accepts into the generic form FromDocument takes.
func DecodeYAML(src []byte) (any, error) {
	if len(src) > MaxPolicyBytes {
		return nil, fmt.Errorf("%w: %d bytes, over MaxPolicyBytes (%d)", ErrPolicyFile, len(src), MaxPolicyBytes)
	}
	doc, err := decodeYAMLText(string(src))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPolicyFile, err)
	}
	return doc, nil
}

// Load reads, decodes and validates the policy file at path. It reads at most
// MaxPolicyBytes+1 bytes, so an oversized file is refused without being read
// whole.
func Load(path string) (Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return Policy{}, fmt.Errorf("%w: %w", ErrPolicyFile, err)
	}
	defer f.Close()
	src, err := io.ReadAll(io.LimitReader(f, MaxPolicyBytes+1))
	if err != nil {
		return Policy{}, fmt.Errorf("%w: reading %s: %w", ErrPolicyFile, path, err)
	}
	doc, err := DecodeYAML(src)
	if err != nil {
		return Policy{}, fmt.Errorf("%s: %w", path, err)
	}
	p, err := FromDocument(doc)
	if err != nil {
		return Policy{}, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

type yamlline struct {
	num    int
	indent int
	text   string
}

// decodeYAMLText decodes the YAML subset policy files are written in. Anything
// outside that subset -- tabs for indentation, anchors, multi-document streams,
// block scalars, duplicate keys -- is an error, never a guess.
func decodeYAMLText(src string) (any, error) {
	lines, err := yamlScan(src)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, nil
	}
	return yamlBlock(lines, 0)
}

func yamlScan(src string) ([]yamlline, error) {
	var out []yamlline

	for i, raw := range strings.Split(src, "\n") {
		num := i + 1
		text := strings.TrimSuffix(raw, "\r")

		if strings.ContainsRune(text[:len(text)-len(strings.TrimLeft(text, " \t"))], '\t') {
			return nil, fmt.Errorf("line %d: tab in indentation is not supported", num)
		}

		text = yamlStripComment(text)
		trimmed := strings.TrimRight(text, " ")
		if strings.TrimSpace(trimmed) == "" {
			continue
		}
		if strings.TrimSpace(trimmed) == "---" || strings.TrimSpace(trimmed) == "..." {
			return nil, fmt.Errorf("line %d: document markers are not supported", num)
		}

		indent := len(trimmed) - len(strings.TrimLeft(trimmed, " "))
		out = append(out, yamlline{num: num, indent: indent, text: strings.TrimLeft(trimmed, " ")})
	}
	return out, nil
}

// yamlStripComment removes a trailing comment. A '#' only starts a comment when
// it is outside quotes and at the start of the line or preceded by a space, so
// a pattern like "**/#tag" survives.
func yamlStripComment(text string) string {
	var quote rune
	for i, r := range text {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '#':
			if i == 0 || text[i-1] == ' ' || text[i-1] == '\t' {
				return text[:i]
			}
		}
	}
	return text
}

func yamlBlock(lines []yamlline, depth int) (any, error) {
	if len(lines) == 0 {
		return nil, nil
	}
	if depth > MaxPolicyNesting {
		return nil, fmt.Errorf("line %d: nested deeper than %d levels", lines[0].num, MaxPolicyNesting)
	}
	base := lines[0].indent
	for _, ln := range lines {
		if ln.indent < base {
			return nil, fmt.Errorf("line %d: indent %d is shallower than the block's %d", ln.num, ln.indent, base)
		}
	}
	if yamlisSeqItem(lines[0].text) {
		return yamlSequence(lines, base, depth)
	}
	return yamlMapping(lines, base, depth)
}

func yamlisSeqItem(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

func yamlSequence(lines []yamlline, base, depth int) ([]any, error) {
	out := []any{}

	for i := 0; i < len(lines); {
		ln := lines[i]
		if ln.indent != base {
			return nil, fmt.Errorf("line %d: expected a sequence item at indent %d", ln.num, base)
		}
		if !yamlisSeqItem(ln.text) {
			return nil, fmt.Errorf("line %d: expected %q to start with %q", ln.num, ln.text, "- ")
		}

		end := i + 1
		for end < len(lines) && lines[end].indent > base {
			end++
		}

		after := ln.text[1:]
		rest := strings.TrimLeft(after, " ")
		restIndent := ln.indent + 1 + (len(after) - len(rest))

		var (
			item any
			err  error
		)
		switch {
		case rest == "":
			item, err = yamlBlock(lines[i+1:end], depth+1)
		case yamlisMappingEntry(rest):
			sub := make([]yamlline, 0, end-i)
			sub = append(sub, yamlline{num: ln.num, indent: restIndent, text: rest})
			sub = append(sub, lines[i+1:end]...)
			item, err = yamlBlock(sub, depth+1)
		default:
			if end > i+1 {
				return nil, fmt.Errorf("line %d: a scalar sequence item cannot have child lines", ln.num)
			}
			item, err = yamlValue(rest, ln.num)
		}
		if err != nil {
			return nil, err
		}

		out = append(out, item)
		i = end
	}
	return out, nil
}

func yamlMapping(lines []yamlline, base, depth int) (map[string]any, error) {
	out := map[string]any{}

	for i := 0; i < len(lines); {
		ln := lines[i]
		if ln.indent != base {
			return nil, fmt.Errorf("line %d: indent %d does not line up with the mapping's %d", ln.num, ln.indent, base)
		}

		key, rest, ok := yamlsplitKey(ln.text)
		if !ok {
			return nil, fmt.Errorf("line %d: %q is not a mapping entry", ln.num, ln.text)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate key %q", ln.num, key)
		}

		end := i + 1
		for end < len(lines) && lines[end].indent > base {
			end++
		}

		var (
			val any
			err error
		)
		if rest != "" {
			if end > i+1 {
				return nil, fmt.Errorf("line %d: key %q has both an inline value and child lines", ln.num, key)
			}
			val, err = yamlValue(rest, ln.num)
		} else {
			val, err = yamlBlock(lines[i+1:end], depth+1)
		}
		if err != nil {
			return nil, err
		}

		out[key] = val
		i = end
	}
	return out, nil
}

func yamlisMappingEntry(text string) bool {
	_, _, ok := yamlsplitKey(text)
	return ok
}

// yamlsplitKey splits "key: value" at the first top-level colon. The colon must
// end the line or be followed by a space, which is what keeps a bare scalar
// containing a colon from being misread as a key.
func yamlsplitKey(text string) (key, rest string, ok bool) {
	var quote rune
	depth := 0

	for i, r := range text {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '[' || r == '{':
			depth++
		case r == ']' || r == '}':
			depth--
		case r == ':' && depth == 0:
			if i+1 < len(text) && text[i+1] != ' ' {
				return "", "", false
			}
			key = strings.TrimSpace(text[:i])
			if unquoted, wasQuoted := yamlunquote(key); wasQuoted {
				key = unquoted
			}
			if key == "" {
				return "", "", false
			}
			return key, strings.TrimSpace(text[i+1:]), true
		}
	}
	return "", "", false
}

func yamlValue(text string, line int) (any, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, nil
	}
	if text[0] == '[' || text[0] == '{' {
		flow := &yamlflow{src: []rune(text), line: line}
		val, err := flow.value()
		if err != nil {
			return nil, err
		}
		flow.skipSpace()
		if flow.pos != len(flow.src) {
			return nil, fmt.Errorf("line %d: trailing text after flow collection: %q", line, string(flow.src[flow.pos:]))
		}
		return val, nil
	}
	return yamlscalar(text, line)
}

type yamlflow struct {
	src   []rune
	pos   int
	line  int
	depth int
}

func (f *yamlflow) skipSpace() {
	for f.pos < len(f.src) && (f.src[f.pos] == ' ' || f.src[f.pos] == '\t') {
		f.pos++
	}
}

func (f *yamlflow) value() (any, error) {
	f.skipSpace()
	if f.pos >= len(f.src) {
		return nil, fmt.Errorf("line %d: unexpected end of flow collection", f.line)
	}
	switch f.src[f.pos] {
	case '[', '{':
		f.depth++
		if f.depth > MaxPolicyNesting {
			return nil, fmt.Errorf("line %d: flow collection nested deeper than %d levels", f.line, MaxPolicyNesting)
		}
		defer func() { f.depth-- }()
		if f.src[f.pos] == '[' {
			return f.sequence()
		}
		return f.mapping()
	default:
		return yamlscalar(f.token(), f.line)
	}
}

// token reads a bare or quoted token, stopping at a flow delimiter.
func (f *yamlflow) token() string {
	f.skipSpace()
	start := f.pos

	if f.pos < len(f.src) && (f.src[f.pos] == '"' || f.src[f.pos] == '\'') {
		quote := f.src[f.pos]
		f.pos++
		for f.pos < len(f.src) {
			if f.src[f.pos] == '\\' && quote == '"' && f.pos+1 < len(f.src) {
				f.pos += 2
				continue
			}
			if f.src[f.pos] == quote {
				f.pos++
				break
			}
			f.pos++
		}
		return string(f.src[start:f.pos])
	}

	for f.pos < len(f.src) && !strings.ContainsRune(",[]{}:", f.src[f.pos]) {
		f.pos++
	}
	return strings.TrimSpace(string(f.src[start:f.pos]))
}

func (f *yamlflow) sequence() ([]any, error) {
	f.pos++ // '['
	out := []any{}

	for {
		f.skipSpace()
		if f.pos >= len(f.src) {
			return nil, fmt.Errorf("line %d: unterminated flow sequence", f.line)
		}
		if f.src[f.pos] == ']' {
			f.pos++
			return out, nil
		}

		item, err := f.value()
		if err != nil {
			return nil, err
		}
		out = append(out, item)

		f.skipSpace()
		if f.pos >= len(f.src) {
			return nil, fmt.Errorf("line %d: unterminated flow sequence", f.line)
		}
		switch f.src[f.pos] {
		case ',':
			f.pos++
		case ']':
			f.pos++
			return out, nil
		default:
			return nil, fmt.Errorf("line %d: expected %q or %q in flow sequence, got %q", f.line, ",", "]", string(f.src[f.pos]))
		}
	}
}

func (f *yamlflow) mapping() (map[string]any, error) {
	f.pos++ // '{'
	out := map[string]any{}

	for {
		f.skipSpace()
		if f.pos >= len(f.src) {
			return nil, fmt.Errorf("line %d: unterminated flow mapping", f.line)
		}
		if f.src[f.pos] == '}' {
			f.pos++
			return out, nil
		}

		key := f.token()
		if unquoted, wasQuoted := yamlunquote(key); wasQuoted {
			key = unquoted
		}
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key in flow mapping", f.line)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate key %q in flow mapping", f.line, key)
		}

		f.skipSpace()
		if f.pos >= len(f.src) || f.src[f.pos] != ':' {
			return nil, fmt.Errorf("line %d: expected %q after key %q in flow mapping", f.line, ":", key)
		}
		f.pos++

		val, err := f.value()
		if err != nil {
			return nil, err
		}
		out[key] = val

		f.skipSpace()
		if f.pos >= len(f.src) {
			return nil, fmt.Errorf("line %d: unterminated flow mapping", f.line)
		}
		switch f.src[f.pos] {
		case ',':
			f.pos++
		case '}':
			f.pos++
			return out, nil
		default:
			return nil, fmt.Errorf("line %d: expected %q or %q in flow mapping, got %q", f.line, ",", "}", string(f.src[f.pos]))
		}
	}
}

var (
	yamlintPattern   = regexp.MustCompile(`^-?[0-9]+$`)
	yamlfloatPattern = regexp.MustCompile(`^-?[0-9]+\.[0-9]+$`)
)

func yamlscalar(text string, line int) (any, error) {
	text = strings.TrimSpace(text)

	if unquoted, wasQuoted := yamlunquote(text); wasQuoted {
		return unquoted, nil
	}

	if text != "" && strings.ContainsRune(yamlReservedIndicators, rune(text[0])) {
		return nil, fmt.Errorf("line %d: %q starts with a YAML indicator this decoder does not support "+
			"(anchors, aliases, tags, block scalars and directives are refused, never guessed at); quote it "+
			"if it is meant as text", line, text)
	}

	switch text {
	case "", "null", "~":
		return nil, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	}

	if yamlintPattern.MatchString(text) {
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("line %d: %q looks like an integer but does not parse: %v", line, text, err)
		}
		return n, nil
	}
	if yamlfloatPattern.MatchString(text) {
		n, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return nil, fmt.Errorf("line %d: %q looks like a float but does not parse: %v", line, text, err)
		}
		return n, nil
	}
	return text, nil
}

// yamlunquote strips one layer of quoting, reporting whether the input was
// quoted at all. Only the escapes policy files plausibly use are handled.
func yamlunquote(text string) (string, bool) {
	if len(text) < 2 {
		return text, false
	}

	switch {
	case text[0] == '\'' && text[len(text)-1] == '\'':
		return strings.ReplaceAll(text[1:len(text)-1], "''", "'"), true

	case text[0] == '"' && text[len(text)-1] == '"':
		body := text[1 : len(text)-1]
		var b strings.Builder
		for i := 0; i < len(body); i++ {
			if body[i] == '\\' && i+1 < len(body) {
				i++
				switch body[i] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				default:
					b.WriteByte(body[i])
				}
				continue
			}
			b.WriteByte(body[i])
		}
		return b.String(), true
	}
	return text, false
}
