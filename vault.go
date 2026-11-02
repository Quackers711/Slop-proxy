package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Entry is one known secret and the stand-in the model sees instead of it.
type Entry struct {
	Name, Value, Token, Source string
}

// Vault maps real secret values to deterministic tokens and back.
// Tokens are derived with an HMAC key so the same secret always gets the same
// token, which keeps re-masked conversation history byte-identical (prompt cache hits).
type Vault struct {
	key []byte

	mu               sync.RWMutex
	entries          []*Entry
	byValue, byToken map[string]*Entry
	mask, unmaskJSON *strings.Replacer

	renames              map[string]string // real name -> name the agent sees, and the reverse
	unrenames            map[string]string
	renameRe, unrenameRe *regexp.Regexp
}

func NewVault(key []byte) *Vault {
	v := &Vault{key: key, byValue: map[string]*Entry{}, byToken: map[string]*Entry{}}
	v.rebuild()
	return v
}

func (v *Vault) mac(s string) []byte {
	h := hmac.New(sha256.New, v.key)
	h.Write([]byte(s))
	return h.Sum(nil)
}

func (v *Vault) shortHash(s string) string { return hex.EncodeToString(v.mac(s)[:3]) }

var nameSanitizer = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

// Add registers a secret. The agent sees replacement, or [[SECRET:name]] when
// replacement is empty or already taken. Adding a value twice returns the existing entry.
func (v *Vault) Add(name, value, replacement, source string) *Entry {
	v.mu.Lock()
	defer v.mu.Unlock()
	if e := v.byValue[value]; e != nil {
		return e
	}
	token := replacement
	if token == "" || v.byToken[token] != nil {
		token = "[[SECRET:" + nameSanitizer.ReplaceAllString(name, "_") + "]]"
		if v.byToken[token] != nil {
			token = token[:len(token)-2] + "_" + v.shortHash(value) + "]]"
		}
	}
	e := &Entry{Name: name, Value: value, Token: token, Source: source}
	v.entries = append(v.entries, e)
	v.byValue[value], v.byToken[token] = e, e
	v.rebuild()
	return e
}

// rebuild must be called with mu held.
func (v *Vault) rebuild() {
	// strings.Replacer prefers earlier pairs at the same position, so longest first
	// keeps a secret that contains another secret from being split.
	es := slices.Clone(v.entries)
	slices.SortFunc(es, func(a, b *Entry) int { return len(jsonEscape(b.Value)) - len(jsonEscape(a.Value)) })
	var m []string
	for _, e := range es {
		m = append(m, jsonEscape(e.Value), e.Token)
	}
	slices.SortFunc(es, func(a, b *Entry) int { return len(b.Token) - len(a.Token) })
	var u []string
	for _, e := range es {
		u = append(u, e.Token, jsonEscape(e.Value))
	}
	v.mask, v.unmaskJSON = strings.NewReplacer(m...), strings.NewReplacer(u...)
}

func (v *Vault) Entries() []Entry {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]Entry, len(v.entries))
	for i, e := range v.entries {
		out[i] = *e
	}
	return out
}

// Mask replaces secrets in a raw JSON body. It works on the escaped bytes so key
// order and formatting are untouched. It refuses to return JSON it broke.
func (v *Vault) Mask(body []byte) ([]byte, error) {
	v.mu.RLock()
	r := v.mask
	v.mu.RUnlock()
	out := []byte(r.Replace(string(body)))
	if json.Valid(body) && !json.Valid(out) {
		return nil, errors.New("masking produced invalid JSON (a secret matched outside a JSON string?)")
	}
	// Renames go after secrets, so a rename can never alter a secret before it is masked.
	if renamed, err := v.renameJSON(out, false); err == nil {
		out = renamed
	}
	return out, nil
}

// UnmaskInput restores a tool input (JSON text): renames first, then secrets,
// the reverse of Mask, so a secret token containing a renamed word still resolves.
func (v *Vault) UnmaskInput(js string) string {
	if b, err := v.renameJSON([]byte(js), true); err == nil {
		js = string(b)
	}
	return v.UnmaskJSON(js)
}

// AddRename makes the agent see to wherever from appears as a whole word.
func (v *Vault) AddRename(from, to string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.renames == nil {
		v.renames, v.unrenames = map[string]string{}, map[string]string{}
	}
	v.renames[from], v.unrenames[to] = to, from
	v.renameRe, v.unrenameRe = wordRe(v.renames), wordRe(v.unrenames)
}

func (v *Vault) Renames() map[string]string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return maps.Clone(v.renames)
}

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// wordRe matches any key of m as a whole word: an end that is an identifier
// character must not run into another one, so "key" skips "keyboard" and "VALID_KEY".
func wordRe(m map[string]string) *regexp.Regexp {
	words := slices.Collect(maps.Keys(m))
	slices.SortFunc(words, func(a, b string) int { return len(b) - len(a) }) // leftmost-first: longest wins
	for i, w := range words {
		q := regexp.QuoteMeta(w)
		if isWordByte(w[0]) {
			q = `\b` + q
		}
		if isWordByte(w[len(w)-1]) {
			q += `\b`
		}
		words[i] = q
	}
	return regexp.MustCompile(strings.Join(words, "|"))
}

// renameJSON applies renames (or their reverse) to every string value in a JSON
// document. Keys stay put, and so do thinking blocks, whose signature covers their text.
func (v *Vault) renameJSON(body []byte, inverse bool) ([]byte, error) {
	v.mu.RLock()
	re, m := v.renameRe, v.renames
	if inverse {
		re, m = v.unrenameRe, v.unrenames
	}
	v.mu.RUnlock()
	if re == nil {
		return body, nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	var walk func(any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case string:
			return re.ReplaceAllStringFunc(t, func(w string) string { return m[w] })
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
		case map[string]any:
			if t["type"] == "thinking" || t["type"] == "redacted_thinking" {
				return t
			}
			for k := range t {
				t[k] = walk(t[k])
			}
		}
		return x
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(walk(doc)); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// UnmaskJSON swaps tokens back inside JSON text (values are JSON-escaped).
func (v *Vault) UnmaskJSON(s string) string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.unmaskJSON.Replace(s)
}

// ponytail: small hand-picked rule set; port gitleaks rules if coverage falls short.
var patterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"anthropic-key", regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`)},
	{"openai-key", regexp.MustCompile(`sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}`)},
	{"github-token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`)},
	{"github-pat", regexp.MustCompile(`github_pat_[A-Za-z0-9_]{50,}`)},
	{"aws-access-key", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)},
	{"stripe-key", regexp.MustCompile(`[rs]k_(?:live|test)_[A-Za-z0-9]{20,}`)},
	{"slack-token", regexp.MustCompile(`xox[abposr]-[A-Za-z0-9-]{10,}`)},
	{"google-api-key", regexp.MustCompile(`AIza[A-Za-z0-9_-]{35}`)},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{"private-key", regexp.MustCompile(`-----BEGIN[A-Z ]*PRIVATE KEY-----[^-]+-----END[A-Z ]*PRIVATE KEY-----`)},
}

// Detect scans b for well-known secret formats and registers new ones.
// isJSON means b is a JSON body, so hits are still escaped.
func (v *Vault) Detect(b []byte, source string, isJSON bool) []*Entry {
	var added []*Entry
	for _, p := range patterns {
		for _, hit := range p.re.FindAll(b, -1) {
			s := string(hit)
			if isJSON && json.Unmarshal(append(append([]byte{'"'}, hit...), '"'), &s) != nil {
				continue
			}
			v.mu.RLock()
			known := v.byValue[s] != nil || v.byToken[s] != nil
			v.mu.RUnlock()
			if !known {
				added = append(added, v.Add(p.name+"-"+v.shortHash(s), s, "", source))
			}
		}
	}
	return added
}

// jsonEscape matches JSON.stringify for everything but U+2028/2029 and invalid UTF-8.
func jsonEscape(s string) string {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.Encode(s)
	out := b.Bytes()
	return string(out[1 : len(out)-2])
}
