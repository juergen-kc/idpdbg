package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestGroupsCoverRegistry(t *testing.T) {
	known := map[string]bool{}
	for _, g := range groups {
		if known[g.Name] {
			t.Errorf("group %q listed twice", g.Name)
		}
		known[g.Name] = true
		for _, name := range g.Lead {
			if findOp(g.Name+"."+name) == nil {
				t.Errorf("group %q leads with unknown operation %q", g.Name, name)
			}
		}
	}
	listed := 0
	for _, ops := range opsByGroup() {
		listed += len(ops)
	}
	for _, op := range registry {
		if !known[op.group()] {
			t.Errorf("operation %s: group %q is missing from groups in docs.go", op.Name, op.group())
		}
	}
	if listed != len(registry) {
		t.Errorf("opsByGroup lists %d operations, registry has %d", listed, len(registry))
	}
}

// TestReferenceUpToDate fails when docs/reference no longer matches the
// operation definitions; regenerate it with `go run . docs`.
func TestReferenceUpToDate(t *testing.T) {
	dir := filepath.Join("docs", "reference")
	want := referenceDocs()
	for name, content := range want {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s: %v (run: go run . docs)", name, err)
			continue
		}
		// A Windows checkout may have turned LF into CRLF.
		got = bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n"))
		if !bytes.Equal(got, content) {
			t.Errorf("%s is out of date (run: go run . docs)", filepath.Join(dir, name))
		}
	}
	existing, _ := filepath.Glob(filepath.Join(dir, "*.md"))
	for _, f := range existing {
		if _, ok := want[filepath.Base(f)]; !ok {
			t.Errorf("%s is not generated any more; delete it (go run . docs does)", f)
		}
	}
}

func TestReferenceContent(t *testing.T) {
	docs := referenceDocs()
	idx := string(docs["README.md"])
	for _, op := range registry {
		page := string(docs[op.group()+".md"])
		if !strings.Contains(page, "\n## "+op.group()+" "+op.short()+"\n") {
			t.Errorf("%s has no section on its group page", op.Name)
		}
		if !strings.Contains(idx, "("+op.group()+".md#"+anchor(op)+")") {
			t.Errorf("%s is not linked from the index", op.Name)
		}
		if op.Mutating && !strings.Contains(page, "`"+op.tool()+"`. **Changes data") {
			t.Errorf("%s is mutating but its page does not say so", op.Name)
		}
		for _, p := range op.Params {
			if !strings.Contains(page, "| `"+flagName(p)+"` |") {
				t.Errorf("%s: parameter %s missing", op.Name, p.Name)
			}
		}
	}
	if got := mdText("a|b <c>"); got != `a\|b &lt;c&gt;` {
		t.Errorf("mdText = %q", got)
	}
}

// shellWords splits a command line the way a POSIX shell would for the
// simple quoting used in the docs: whitespace, '…', "…" and \x.
func shellWords(line string) []string {
	var words []string
	var cur strings.Builder
	in, quote := false, rune(0)
	for i := 0; i < len(line); i++ {
		ch := rune(line[i])
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			} else {
				cur.WriteRune(ch)
			}
		case ch == '\'' || ch == '"':
			quote, in = ch, true
		case ch == '\\' && i+1 < len(line):
			i++
			cur.WriteByte(line[i])
			in = true
		case ch == ' ' || ch == '\t':
			if in {
				words = append(words, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteRune(ch)
			in = true
		}
	}
	if in {
		words = append(words, cur.String())
	}
	return words
}

// docCommands returns the idpdbg command lines in the ```bash blocks of a
// Markdown file, with line continuations joined.
func docCommands(md string) []string {
	var out []string
	inBlock := false
	pending := ""
	for _, line := range strings.Split(md, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "```") {
			inBlock = !inBlock && strings.TrimPrefix(t, "```") == "bash"
			continue
		}
		if !inBlock {
			continue
		}
		if strings.HasSuffix(t, "\\") {
			pending += strings.TrimSuffix(t, "\\") + " "
			continue
		}
		out = append(out, pending+t)
		pending = ""
	}
	return out
}

// endOfCommand reports whether a shell word ends the idpdbg command: a pipe,
// a redirection or a command separator.
func endOfCommand(w string) bool {
	switch w {
	case "|", "&&", "||", ";":
		return true
	}
	return strings.HasPrefix(w, ">") || strings.HasPrefix(w, "2>") || strings.HasPrefix(w, "<")
}

// TestDocExamples checks that every idpdbg command in the README and the
// how-to guides names a real operation and real parameters, and gives a
// value to every non-bool parameter.
func TestDocExamples(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("docs", "howto", "*.md"))
	more, _ := filepath.Glob(filepath.Join("docs", "*.md"))
	files = append(append(files, more...), "README.md")
	commands := map[string]bool{"mcp": true, "docs": true, "profiles": true, "version": true}
	groupNames := map[string]bool{}
	for _, g := range groups {
		groupNames[g.Name] = true
	}
	checked := 0
	for _, f := range files {
		md, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range docCommands(string(md)) {
			w := shellWords(line)
			for i := 0; i+1 < len(w); i++ {
				if w[i] != "idpdbg" || commands[w[i+1]] || !groupNames[w[i+1]] {
					continue
				}
				if i+2 >= len(w) {
					t.Errorf("%s: %q names a group but no operation", f, line)
					break
				}
				op := findOp(w[i+1] + "." + w[i+2])
				if op == nil {
					t.Errorf("%s: unknown operation %s %s in %q", f, w[i+1], w[i+2], line)
					break
				}
				params := map[string]Param{}
				for _, p := range op.allParams() {
					params[p.Name] = p
				}
				for j := i + 3; j < len(w) && !endOfCommand(w[j]); j++ {
					name, _, hasVal := strings.Cut(strings.TrimPrefix(w[j], "--"), "=")
					if !strings.HasPrefix(w[j], "--") {
						t.Errorf("%s: %s: unexpected argument %q", f, op.Name, w[j])
						continue
					}
					if name == "report" { // CLI-only, not an operation parameter
						j++
						continue
					}
					p, ok := params[strings.ReplaceAll(name, "-", "_")]
					if !ok {
						t.Errorf("%s: %s has no parameter --%s", f, op.Name, name)
						continue
					}
					if p.Type != "bool" && !hasVal {
						if j+1 >= len(w) || endOfCommand(w[j+1]) {
							t.Errorf("%s: %s: --%s needs a value", f, op.Name, name)
						}
						j++
					}
				}
				checked++
			}
		}
	}
	if checked < 20 {
		t.Errorf("only %d documented commands found; is the parser broken?", checked)
	}
}

// TestChangelog keeps CHANGELOG.md in the shape scripts/release-notes.sh and
// the release workflow rely on: [Unreleased] first, then one non-empty
// section per version, newest first, each with a compare link.
func TestChangelog(t *testing.T) {
	b, err := os.ReadFile("CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	md := strings.ReplaceAll(string(b), "\r\n", "\n")
	heading := regexp.MustCompile(`(?m)^## \[([^\]]+)\](.*)$`)
	version := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)
	date := regexp.MustCompile(`^ - \d{4}-\d{2}-\d{2}$`)
	hs := heading.FindAllStringSubmatchIndex(md, -1)
	if len(hs) < 2 || md[hs[0][2]:hs[0][3]] != "Unreleased" {
		t.Fatalf("CHANGELOG.md must start with ## [Unreleased] and list versions after it")
	}
	var prev [3]int
	prevDate := "9999"
	for i, h := range hs {
		name, rest := md[h[2]:h[3]], md[h[4]:h[5]]
		end := len(md)
		if i+1 < len(hs) {
			end = hs[i+1][0]
		}
		body := md[h[1]:end]
		if j := strings.Index(body, "\n["); j >= 0 && i == len(hs)-1 {
			body = body[:j] // the link definitions after the last section
		}
		// Versions before the first public release (0.24.0) have no tags here.
		if i <= 1 && !regexp.MustCompile(`(?m)^\[`+regexp.QuoteMeta(name)+`\]: https://`).MatchString(md) {
			t.Errorf("[%s] has no link definition", name)
		}
		if i == 0 {
			continue
		}
		m := version.FindStringSubmatch(name)
		if m == nil || !date.MatchString(rest) {
			t.Errorf("heading %q: want ## [X.Y.Z] - YYYY-MM-DD", md[h[0]:h[1]])
			continue
		}
		var v [3]int
		for k := range v {
			v[k], _ = strconv.Atoi(m[k+1])
		}
		if i > 1 && !(v[0] < prev[0] || v[0] == prev[0] && (v[1] < prev[1] || v[1] == prev[1] && v[2] < prev[2])) {
			t.Errorf("%s is listed after %d.%d.%d: newest first", name, prev[0], prev[1], prev[2])
		}
		if d := rest[3:]; d > prevDate {
			t.Errorf("%s is dated %s, after the newer release's %s", name, d, prevDate)
		} else {
			prevDate = d
		}
		prev = v
		if !strings.Contains(body, "\n- ") {
			t.Errorf("%s has no entries", name)
		}
	}
}

// TestDocLinks checks that every relative link in the README, the
// changelog and the hand-written docs points at a file that exists.
func TestDocLinks(t *testing.T) {
	files := []string{"README.md", "CHANGELOG.md", "SECURITY.md"}
	for _, pattern := range []string{"docs/*.md", "docs/howto/*.md"} {
		more, _ := filepath.Glob(filepath.FromSlash(pattern))
		files = append(files, more...)
	}
	link := regexp.MustCompile(`\]\(([^)\s]+)\)`)
	checked := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range link.FindAllStringSubmatch(string(b), -1) {
			target := m[1]
			if strings.Contains(target, "://") || strings.HasPrefix(target, "#") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			target, _, _ = strings.Cut(target, "#")
			path := filepath.Join(filepath.Dir(f), filepath.FromSlash(target))
			if _, err := os.Stat(path); err != nil {
				t.Errorf("%s links to %s, which does not exist", f, m[1])
			}
			checked++
		}
	}
	if checked < 30 {
		t.Errorf("only %d links checked; is the pattern broken?", checked)
	}
}

func TestWriteReferenceLeavesOtherFilesAlone(t *testing.T) {
	dir := t.TempDir()
	notes := filepath.Join(dir, "notes.md")
	os.WriteFile(notes, []byte("my notes"), 0o644)
	if _, err := writeReference(dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(notes); string(b) != "my notes" {
		t.Fatalf("writeReference removed or changed notes.md")
	}
	// Its own pages are regenerated, including stale ones it made.
	stale := filepath.Join(dir, "gone.md")
	os.WriteFile(stale, []byte(generatedNote+"old group"), 0o644)
	if _, err := writeReference(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("a stale generated page was kept")
	}
	// A foreign file with a page's name is refused, not overwritten.
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("the project's README"), 0o644)
	if _, err := writeReference(dir); err == nil || !strings.Contains(err.Error(), "not generated by idpdbg docs") {
		t.Errorf("want a refusal, got %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "README.md")); string(b) != "the project's README" {
		t.Errorf("the foreign README.md was overwritten")
	}
	// A link in place of a page is not written through.
	os.Remove(filepath.Join(dir, "README.md"))
	target := filepath.Join(t.TempDir(), "elsewhere.md")
	os.WriteFile(target, []byte("elsewhere"), 0o644)
	if os.Symlink(target, filepath.Join(dir, "README.md")) == nil {
		if _, err := writeReference(dir); err == nil {
			t.Errorf("wrote through a symbolic link")
		}
		if b, _ := os.ReadFile(target); string(b) != "elsewhere" {
			t.Errorf("the link's target was overwritten")
		}
	}
}
