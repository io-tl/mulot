// Package assets bundles the agent-facing knowledge that used to live on disk —
// the per-stack skill playbooks, the JS helper libraries (crypto, wordlist), and
// the bruteforce wordlists — straight into the mulot binary via go:embed.
//
// The design rule is "complexity in mulot, minimal tool surface": the heavy
// content (multi-thousand-entry wordlists, full playbooks, crypto libraries) is
// served server-side or injected into the page by tag/name, so it never has to
// cross the model's context window.
package assets

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

//go:embed skills js wordlists
var files embed.FS

// workflowFile is the shared workflow doc: the tool catalogue + generic method,
// loaded into the system prompt before any stack is known.
const workflowFile = "skills/00-workflow.md"

// Skills returns the available stack names — the sub-directories under skills/,
// each holding one playbook set. The top-level *.md (the shared workflow) are
// not stacks and are excluded.
func Skills() []string {
	entries, err := fs.ReadDir(files, "skills")
	if err != nil {
		return nil
	}
	var stacks []string
	for _, e := range entries {
		if e.IsDir() {
			stacks = append(stacks, e.Name())
		}
	}
	sort.Strings(stacks)
	return stacks
}

// Workflow returns the shared workflow doc (skills/00-workflow.md).
func Workflow() (string, error) {
	b, err := files.ReadFile(workflowFile)
	if err != nil {
		return "", fmt.Errorf("workflow not embedded: %w", err)
	}
	return string(b), nil
}

// LoadSkill concatenates the playbooks (skills/<stack>/*.md, sorted) for each
// requested stack. Unknown stacks are reported inline rather than failing the
// whole call, so a partly-correct fingerprint still loads what it can.
func LoadSkill(stacks ...string) (string, error) {
	known := map[string]bool{}
	for _, s := range Skills() {
		known[s] = true
	}
	var b strings.Builder
	for _, stack := range stacks {
		if !known[stack] {
			fmt.Fprintf(&b, "# unknown stack: %s (have: %s)\n\n", stack, strings.Join(Skills(), ", "))
			continue
		}
		dir := path.Join("skills", stack)
		entries, err := fs.ReadDir(files, dir)
		if err != nil {
			return "", err
		}
		var names []string
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			data, err := files.ReadFile(path.Join(dir, n))
			if err != nil {
				return "", err
			}
			b.Write(data)
			b.WriteString("\n\n")
		}
	}
	return b.String(), nil
}

// WordlistTags returns the available wordlist tags — the basenames (without
// .txt) of wordlists/*.txt.
func WordlistTags() []string {
	entries, err := fs.ReadDir(files, "wordlists")
	if err != nil {
		return nil
	}
	var tags []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".txt") {
			tags = append(tags, strings.TrimSuffix(e.Name(), ".txt"))
		}
	}
	sort.Strings(tags)
	return tags
}

// Wordlist parses the embedded wordlists/<tag>.txt into a slice: one entry per
// line, trimmed, skipping blank lines and '#' comments. This text→[]string
// conversion is done HERE (in Go) so neither the fuzzer nor the in-page helper
// hands the model raw text to split.
func Wordlist(tag string) ([]string, error) {
	b, err := files.ReadFile(path.Join("wordlists", tag+".txt"))
	if err != nil {
		return nil, fmt.Errorf("unknown wordlist tag %q (have: %s)", tag, strings.Join(WordlistTags(), ", "))
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

// JS returns an embedded JS helper library by name (js/<name>.js), e.g. "crypto".
func JS(name string) (string, error) {
	b, err := files.ReadFile(path.Join("js", name+".js"))
	if err != nil {
		return "", fmt.Errorf("unknown js helper %q", name)
	}
	return string(b), nil
}
