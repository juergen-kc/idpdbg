package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
)

func usage() {
	fmt.Fprintf(os.Stderr, `idpdbg %s — an identity protocol debugger for the terminal and for MCP clients

Usage:
  idpdbg <group> <operation> [--param value ...]
  idpdbg <group> <operation> --help     parameters of one operation
  ... --report out.html                 also write an HTML report of the run
  idpdbg mcp                            serve every operation as an MCP tool over stdio
  idpdbg profiles                       list profiles in %s
  idpdbg docs [dir]                     write the Markdown command reference (default docs/reference)
  idpdbg version

Operations:
`, version, configPath())
	for i, ops := range opsByGroup() {
		fmt.Fprintf(os.Stderr, "\n  %s — %s\n", groups[i].Name, groups[i].Title)
		for _, op := range ops {
			fmt.Fprintf(os.Stderr, "    %-20s %s\n", op.short(), firstSentence(op.Summary))
		}
	}
	fmt.Fprint(os.Stderr, `
Every operation prints JSON on stdout with a "checks" list of spec findings.
Add --trace to include the raw HTTP exchanges, and --report out.html for a
readable HTML page of the run. Exit status: 0 ok, 1 error, 2 when a check
failed.
`)
}

func opHelp(op *Op) {
	fmt.Fprintf(os.Stderr, "idpdbg %s %s\n\n%s\n\nParameters:\n", op.group(), op.short(), op.Summary)
	for _, p := range op.allParams() {
		flag := "--" + strings.ReplaceAll(p.Name, "_", "-")
		if p.Type != "bool" {
			flag += " <" + p.Type + ">"
		}
		notes := []string{}
		if p.Required {
			notes = append(notes, "required")
		}
		if p.Default != nil {
			notes = append(notes, fmt.Sprintf("default %v", p.Default))
		}
		if len(p.Enum) > 0 {
			notes = append(notes, "one of "+strings.Join(p.Enum, "|"))
		}
		if p.Secret {
			notes = append(notes, "env IDPDBG_"+strings.ToUpper(p.Name))
		}
		desc := p.Desc
		if len(notes) > 0 {
			desc += " [" + strings.Join(notes, "; ") + "]"
		}
		fmt.Fprintf(os.Stderr, "  %-36s %s\n", flag, desc)
	}
}

// cutReportFlag takes the CLI-only --report <file> out of the arguments.
// It is not an operation parameter, so MCP callers cannot write files.
func cutReportFlag(argv []string) (string, []string, error) {
	var path string
	rest := make([]string, 0, len(argv))
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--report":
			if i+1 >= len(argv) || argv[i+1] == "" || strings.HasPrefix(argv[i+1], "--") {
				return "", nil, fmt.Errorf("--report needs a file name")
			}
			i++
			path = argv[i]
		case strings.HasPrefix(a, "--report="):
			if path = strings.TrimPrefix(a, "--report="); path == "" {
				return "", nil, fmt.Errorf("--report needs a file name")
			}
		default:
			rest = append(rest, a)
		}
	}
	return path, rest, nil
}

func parseFlags(op *Op, argv []string) (M, error) {
	params := map[string]Param{}
	for _, p := range op.allParams() {
		params[p.Name] = p
	}
	raw := M{}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if !strings.HasPrefix(a, "--") {
			return nil, fmt.Errorf("unexpected argument %q (parameters are passed as --name value)", a)
		}
		name, val, hasVal := strings.Cut(a[2:], "=")
		name = strings.ReplaceAll(name, "-", "_")
		p, ok := params[name]
		if !ok {
			return nil, fmt.Errorf("unknown parameter --%s (see: idpdbg %s %s --help)", strings.ReplaceAll(name, "_", "-"), op.group(), op.short())
		}
		if !hasVal {
			if p.Type == "bool" {
				val = "true"
			} else {
				if i+1 >= len(argv) {
					return nil, fmt.Errorf("--%s needs a value", strings.ReplaceAll(name, "_", "-"))
				}
				i++
				val = argv[i]
			}
		}
		if p.Type == "list" {
			prev, _ := raw[name].([]any)
			for _, part := range strings.Split(val, ",") {
				prev = append(prev, strings.TrimSpace(part))
			}
			raw[name] = prev
		} else {
			raw[name] = val
		}
	}
	return raw, nil
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		usage()
		return
	}
	switch args[0] {
	case "version", "--version":
		pcsc := "with PC/SC"
		if listReaders == nil {
			pcsc = "without PC/SC (card read unavailable)"
		}
		fmt.Printf("idpdbg %s %s/%s, %s\n", version, runtime.GOOS, runtime.GOARCH, pcsc)
		return
	case "mcp":
		if err := serveMCP(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "idpdbg mcp:", err)
			os.Exit(1)
		}
		return
	case "docs":
		dir := filepath.Join("docs", "reference")
		if len(args) > 1 {
			if strings.HasPrefix(args[1], "-") {
				fmt.Fprintln(os.Stderr, "usage: idpdbg docs [dir]   (writes the Markdown command reference, default docs/reference)")
				os.Exit(1)
			}
			dir = args[1]
		}
		written, err := writeReference(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote %d files to %s\n", len(written), dir)
		return
	case "profiles":
		profs, err := loadProfiles()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		if len(profs) == 0 {
			fmt.Fprintf(os.Stderr, "no profiles in %s\n", configPath())
		}
		for _, name := range sortedKeys(profs) {
			fmt.Printf("%s: %s\n", name, strings.Join(sortedKeys(profs[name]), ", "))
		}
		return
	}

	var op *Op
	rest := args[1:]
	if op = findOp(args[0]); op == nil && len(args) > 1 {
		op = findOp(args[0] + "." + args[1])
		rest = args[2:]
	}
	if op == nil {
		// A bare group lists its operations.
		found := false
		for _, o := range registry {
			if o.group() == args[0] {
				if !found {
					fmt.Fprintf(os.Stderr, "Operations in %s:\n", args[0])
				}
				found = true
				fmt.Fprintf(os.Stderr, "  %-20s %s\n", o.short(), o.Summary)
			}
		}
		if !found || len(args) > 1 {
			fmt.Fprintf(os.Stderr, "unknown operation %q; run idpdbg --help\n", strings.Join(args[:min(2, len(args))], " "))
			os.Exit(1)
		}
		return
	}
	for _, a := range rest {
		if a == "--help" || a == "-h" {
			opHelp(op)
			return
		}
	}
	report, rest, err := cutReportFlag(rest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	raw, err := parseFlags(op, rest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, err := runOp(ctx, op, raw, true, func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", a...)
	})
	if res != nil {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		_ = enc.Encode(res)
	}
	exit := 0
	switch {
	case err != nil:
		exit = 1
	case hasFailure(res):
		exit = 2
	}
	if report != "" {
		if werr := writeReport(report, op, raw, res, err, exit); werr != nil {
			fmt.Fprintln(os.Stderr, "error: writing the report:", werr)
			if exit == 0 {
				exit = 1
			}
		} else {
			fmt.Fprintf(os.Stderr, "report written to %s\n", report)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	os.Exit(exit)
}
