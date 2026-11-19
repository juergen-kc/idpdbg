package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// An HTML report of one run (--report on the command line): the checks,
// grouped by the step that produced them, the parameters used (secrets
// left out), the full JSON result and any HTTP exchanges. One file, no
// scripts, readable in light and dark mode.

type reportCheck struct{ Status, Name, Detail, Ref, Section string }

type reportSection struct {
	Title  string
	Checks []reportCheck
}

type reportParam struct{ Name, Value string }

type reportExchange struct {
	Summary string
	JSON    string
}

type reportData struct {
	Command    string
	Summary    string
	When       string
	Version    string
	Exit       int
	ExitText   string
	Error      string
	Counts     map[string]int
	Statuses   []string
	Params     []reportParam
	Sections   []reportSection
	Attention  []reportCheck // fail and warn, from every section
	ResultJSON string
	Exchanges  []reportExchange
}

// reportSections collects every Checks list in a result, the top-level one
// first, the nested ones titled by where they sit ("token", "probes › …").
func reportSections(res M) []reportSection {
	var out []reportSection
	var walk func(v any, path []string)
	walk = func(v any, path []string) {
		switch x := v.(type) {
		case M:
			if cs, ok := x["checks"].(Checks); ok && len(cs) > 0 {
				title := "Result"
				if len(path) > 0 {
					title = strings.Join(path, " › ")
				}
				sec := reportSection{Title: title}
				for _, c := range cs {
					sec.Checks = append(sec.Checks, reportCheck{c.Status, c.Name, c.Detail, c.Ref, title})
				}
				out = append(out, sec)
			}
			for _, k := range sortedKeys(x) {
				if k == "checks" || k == "http_trace" {
					continue
				}
				walk(x[k], append(append([]string{}, path...), k))
			}
		case []any:
			for i, e := range x {
				walk(e, append(append([]string{}, path...), fmt.Sprint(i+1)))
			}
		case []M:
			for i, e := range x {
				walk(e, append(append([]string{}, path...), fmt.Sprint(i+1)))
			}
		}
	}
	walk(res, nil)
	return out
}

// reportParams lists the parameters of the run, leaving out secrets and key
// material and shortening long values.
func reportParams(op *Op, args M) []reportParam {
	var out []reportParam
	for _, p := range op.allParams() {
		v, ok := args[p.Name]
		if !ok || v == nil || v == "" || v == false {
			continue
		}
		var s string
		switch {
		case !reportShows(p):
			s = "(not shown: may hold credentials)"
		default:
			if str, isStr := v.(string); isStr {
				s = str
			} else {
				b, _ := json.Marshal(v)
				s = string(b)
			}
			if strings.Contains(s, "PRIVATE KEY") {
				s = "(key material, not shown)"
			} else if len(s) > 200 {
				s = s[:200] + "…"
			}
		}
		out = append(out, reportParam{"--" + strings.ReplaceAll(p.Name, "_", "-"), s})
	}
	return out
}

// reportSafeParams are the string parameters the report shows: they say
// what was run (where, as whom, which modes), never with what credentials.
// Everything else is left out, so a parameter added later stays hidden
// until someone decides it is harmless.
var reportSafeParams = map[string]bool{
	"issuer": true, "client_id": true, "client_auth": true, "base_url": true, "url": true, "host": true, "hostname": true,
	"sni": true, "alpn": true, "starttls": true, "scope": true, "scenario": true, "probes": true, "profile": true, "mode": true,
	"method": true, "path": true, "realm": true, "kdc": true, "principal": true, "spn": true, "target_spn": true,
	"service_principal": true, "impersonate": true, "armor_principal": true, "etypes": true, "base_dn": true, "bind_dn": true,
	"user_dn": true, "dn": true, "filter": true, "attributes": true, "redirect_uri": true, "redirect_host": true,
	"redirect_path": true, "post_logout_redirect_uri": true, "response_type": true, "response_mode": true, "prompt": true,
	"acr_values": true, "audience": true, "resource": true, "signing_alg": true, "alg": true, "algorithm": true,
	"sp_entity_id": true, "acs_url": true, "acs_path": true, "slo_url": true, "slo_path": true, "sso_url": true,
	"binding": true, "response_binding": true, "name_id_format": true, "rp_id": true, "origin": true, "trust_domain": true,
	"authorization_endpoint": true, "introspection_endpoint": true, "revocation_endpoint": true, "userinfo_endpoint": true,
	"registration_endpoint": true, "pushed_authorization_request_endpoint": true, "device_authorization_endpoint": true,
	"end_session_endpoint": true, "email_domain": true, "reader": true, "slot": true, "applet": true, "type": true,
}

// reportShows reports whether the report may show a parameter's value.
func reportShows(p Param) bool {
	if p.Secret || p.Explicit {
		return false
	}
	switch p.Type {
	case "bool", "int":
		return true
	}
	return reportSafeParams[p.Name]
}

func exitText(code int) string {
	switch code {
	case 0:
		return "0: no check failed"
	case 2:
		return "2: a check failed"
	default:
		return fmt.Sprintf("%d: the run did not complete", code)
	}
}

// renderReport builds the HTML page for a run.
func renderReport(op *Op, args M, res M, runErr error, exit int, when time.Time) ([]byte, error) {
	d := reportData{
		Command:  "idpdbg " + op.group() + " " + op.short(),
		Summary:  op.Summary,
		When:     when.Format("2006-01-02 15:04:05 MST"),
		Version:  version,
		Exit:     exit,
		ExitText: exitText(exit),
		Counts:   map[string]int{},
		Statuses: []string{"fail", "warn", "pass", "info"},
		Params:   reportParams(op, args),
	}
	if runErr != nil {
		d.Error = runErr.Error()
	}
	if res != nil {
		d.Sections = reportSections(res)
		for _, s := range d.Sections {
			for _, c := range s.Checks {
				d.Counts[c.Status]++
			}
		}
		for _, want := range []string{"fail", "warn"} {
			for _, s := range d.Sections {
				for _, c := range s.Checks {
					if c.Status == want {
						d.Attention = append(d.Attention, c)
					}
				}
			}
		}
		if tr, ok := res["http_trace"].([]*Exchange); ok {
			for _, ex := range tr {
				b, _ := json.MarshalIndent(ex, "", "  ")
				d.Exchanges = append(d.Exchanges, reportExchange{fmt.Sprintf("%s %s → %d", ex.Method, ex.URL, ex.Status), string(b)})
			}
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(res); err != nil {
			return nil, err
		}
		d.ResultJSON = buf.String()
	}
	var out bytes.Buffer
	if err := reportTemplate.Execute(&out, d); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// writeReport writes the HTML report to path, readable only by the user:
// like the JSON output, it can hold tokens from the responses.
//
// It is written to a new file (mode 0600) and renamed into place, so an
// existing file's looser mode is not kept and a symbolic link at path is
// replaced rather than written through.
func writeReport(path string, op *Op, args M, res M, runErr error, exit int) error {
	b, err := renderReport(op, args, res, runErr, exit, time.Now())
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".idpdbg-report-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // no-op after a successful rename
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

var reportTemplate = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Command}}: idpdbg report</title>
<style>
:root{--bg:#fff;--fg:#1d2330;--muted:#5d6675;--line:#e3e6eb;--card:#f6f7f9;
--pass:#1a7f37;--pass-bg:#e6f4ea;--fail:#c62828;--fail-bg:#fdecea;--warn:#9a6700;--warn-bg:#fff4d6;--info:#3a5a8c;--info-bg:#e8eef8}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e4e7ec;--muted:#9aa3b2;--line:#2a2f38;--card:#1b1f26;
--pass:#5cc97a;--pass-bg:#173322;--fail:#ff7a70;--fail-bg:#3a1a1a;--warn:#e8b54a;--warn-bg:#3a2e12;--info:#8fb0e8;--info-bg:#1c2738}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.1rem;margin:28px 0 8px}
.muted{color:var(--muted)}.sum{margin:0 0 12px;color:var(--muted)}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}
.chip{border-radius:999px;padding:4px 12px;font-weight:600;font-size:.9rem}
.s-pass{color:var(--pass);background:var(--pass-bg)}.s-fail{color:var(--fail);background:var(--fail-bg)}
.s-warn{color:var(--warn);background:var(--warn-bg)}.s-info{color:var(--info);background:var(--info-bg)}
.exit{border:1px solid var(--line);border-radius:999px;padding:3px 12px;font-size:.9rem}
.error{border-left:4px solid var(--fail);background:var(--fail-bg);padding:10px 14px;border-radius:6px;margin:16px 0;white-space:pre-wrap}
table{width:100%;border-collapse:collapse;font-size:.92rem}
th,td{text-align:left;vertical-align:top;padding:7px 10px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600;font-size:.82rem;text-transform:uppercase;letter-spacing:.03em}
td.st{width:1%;white-space:nowrap}
.badge{display:inline-block;min-width:3.6em;text-align:center;border-radius:4px;padding:1px 6px;font-weight:700;font-size:.78rem;text-transform:uppercase}
td.detail{word-break:break-word}td.ref{white-space:nowrap;color:var(--muted);font-size:.85rem}
.wrap{overflow-x:auto}
details{border:1px solid var(--line);border-radius:6px;margin:8px 0;background:var(--card)}
summary{cursor:pointer;padding:8px 12px;font-weight:600}
pre{margin:0;padding:12px;overflow-x:auto;font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;word-break:break-word}
code{font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
footer{margin-top:32px;color:var(--muted);font-size:.85rem}
@media (max-width:640px){
table,tbody,tr,td{display:block;width:100%}
tr:has(th){display:none}
tr{padding:10px 0;border-bottom:1px solid var(--line)}
td{border:0;padding:2px 0}
td.st{width:auto}
td.ref{white-space:normal}
}
</style>
</head>
<body>
<main>
<h1>{{.Command}}</h1>
<p class="sum">{{.Summary}}</p>
<div class="muted">{{.When}} · idpdbg {{.Version}}</div>
<div class="chips">
{{range $s := .Statuses}}{{with index $.Counts $s}}<span class="chip s-{{$s}}">{{.}} {{$s}}</span>{{end}}{{end}}
<span class="exit">exit {{.ExitText}}</span>
</div>
{{if .Error}}<div class="error"><strong>Error:</strong> {{.Error}}</div>{{end}}
{{if .Params}}
<h2>Parameters</h2>
<div class="wrap"><table>
<tr><th>Parameter</th><th>Value</th></tr>
{{range .Params}}<tr><td><code>{{.Name}}</code></td><td class="detail">{{.Value}}</td></tr>
{{end}}</table></div>
{{end}}
{{if .Attention}}
<h2>Needs attention</h2>
<div class="wrap"><table>
<tr><th>Status</th><th>Check</th><th>Detail</th><th>Step</th></tr>
{{range .Attention}}<tr><td class="st"><span class="badge s-{{.Status}}">{{.Status}}</span></td><td>{{.Name}}</td><td class="detail">{{.Detail}}</td><td class="ref">{{.Section}}</td></tr>
{{end}}</table></div>
{{end}}
{{range .Sections}}
<h2>{{.Title}}</h2>
<div class="wrap"><table>
<tr><th>Status</th><th>Check</th><th>Detail</th><th>Reference</th></tr>
{{range .Checks}}<tr><td class="st"><span class="badge s-{{.Status}}">{{.Status}}</span></td><td>{{.Name}}</td><td class="detail">{{.Detail}}</td><td class="ref">{{.Ref}}</td></tr>
{{end}}</table></div>
{{end}}
{{if .Exchanges}}
<h2>HTTP exchanges</h2>
{{range .Exchanges}}<details><summary>{{.Summary}}</summary><pre>{{.JSON}}</pre></details>
{{end}}{{end}}
{{if .ResultJSON}}
<h2>Full result</h2>
<details><summary>JSON, as printed on stdout</summary><pre>{{.ResultJSON}}</pre></details>
{{end}}
<footer>The result can contain tokens and other data from the responses. Share it only with people who may see them.</footer>
</main>
</body>
</html>
`))
