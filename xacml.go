package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// XACML 3.0 policy decision point: XML policies, XML or JSON-profile
// requests, targets, conditions, the core function library, all standard
// combining algorithms with extended Indeterminate, obligations and advice.

const (
	catSubject  = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
	catResource = "urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
	catAction   = "urn:oasis:names:tc:xacml:3.0:attribute-category:action"
	catEnv      = "urn:oasis:names:tc:xacml:3.0:attribute-category:environment"
	stMissing   = "urn:oasis:names:tc:xacml:1.0:status:missing-attribute"
	stProc      = "urn:oasis:names:tc:xacml:1.0:status:processing-error"
	stSyntax    = "urn:oasis:names:tc:xacml:1.0:status:syntax-error"
	xacmlRef    = "XACML 3.0"
)

const (
	dPermit, dDeny, dNA  = "Permit", "Deny", "NotApplicable"
	dIndD, dIndP, dIndDP = "Indeterminate{D}", "Indeterminate{P}", "Indeterminate{DP}"
)

func isInd(d string) bool { return strings.HasPrefix(d, "Indeterminate") }

// ---- values ----

type xv struct {
	T  string
	S  string
	B  bool
	I  int64
	F  float64
	Tm time.Time
}

type xbag struct {
	T string
	V []xv
}

type xfn struct{ name string }

type xerr struct{ code, msg string }

func (e *xerr) Error() string { return e.msg }

func perr(format string, a ...any) *xerr { return &xerr{stProc, fmt.Sprintf(format, a...)} }

func shortType(uri string) string {
	if i := strings.LastIndexAny(uri, "#:"); i >= 0 {
		return uri[i+1:]
	}
	return uri
}

func (v xv) String() string {
	switch v.T {
	case "boolean":
		return strconv.FormatBool(v.B)
	case "integer":
		return strconv.FormatInt(v.I, 10)
	case "double":
		return strconv.FormatFloat(v.F, 'g', -1, 64)
	}
	return v.S
}

func parseXV(t, s string) (xv, error) {
	s = strings.TrimSpace(s)
	v := xv{T: t, S: s}
	var err error
	switch t {
	case "string", "anyURI", "x500Name", "dnsName", "ipAddress", "hexBinary", "base64Binary", "dayTimeDuration", "yearMonthDuration":
	case "rfc822Name":
		if !strings.Contains(s, "@") {
			return v, fmt.Errorf("%q is not an rfc822Name", s)
		}
	case "boolean":
		switch s {
		case "true", "1":
			v.B = true
		case "false", "0":
		default:
			return v, fmt.Errorf("%q is not a boolean", s)
		}
	case "integer":
		v.I, err = strconv.ParseInt(strings.TrimPrefix(s, "+"), 10, 64)
	case "double":
		v.F, err = strconv.ParseFloat(s, 64)
	case "date":
		v.Tm, err = parseXSTime(s, "2006-01-02")
	case "dateTime":
		v.Tm, err = parseXSTime(s, "2006-01-02T15:04:05")
	case "time":
		v.Tm, err = parseXSTime(s, "15:04:05")
	default:
		return v, fmt.Errorf("unsupported data type %s", t)
	}
	if err != nil {
		return v, fmt.Errorf("%q is not a valid %s", s, t)
	}
	return v, nil
}

// parseXSTime reads an XML Schema date/time with optional fraction and zone;
// values without a zone are taken as UTC.
func parseXSTime(s, base string) (time.Time, error) {
	for _, z := range []string{"Z07:00", ""} {
		for _, frac := range []string{"", ".999999999"} {
			layout := base
			if base != "2006-01-02" {
				layout += frac
			}
			if t, err := time.Parse(layout+z, s); err == nil {
				return t, nil
			}
		}
	}
	return time.Time{}, errors.New("bad time")
}

func cmpXV(a, b xv) (int, error) {
	if a.T != b.T {
		return 0, perr("cannot compare %s with %s", a.T, b.T)
	}
	switch a.T {
	case "integer":
		return cmpOrdered(a.I, b.I), nil
	case "double":
		return cmpOrdered(a.F, b.F), nil
	case "boolean":
		if a.B == b.B {
			return 0, nil
		}
		return 1, nil
	case "date", "dateTime", "time":
		return a.Tm.Compare(b.Tm), nil
	case "rfc822Name":
		la, da, _ := strings.Cut(a.S, "@")
		lb, db, _ := strings.Cut(b.S, "@")
		if la == lb && strings.EqualFold(da, db) {
			return 0, nil
		}
		return strings.Compare(a.S, b.S) | 1, nil
	}
	return strings.Compare(a.S, b.S), nil
}

func cmpOrdered[T int64 | float64](a, b T) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// ---- request ----

type xattr struct {
	Cat, ID, Issuer string
	V               xv
}

type xrequest struct{ attrs []xattr }

var jsonCategories = map[string]string{
	"AccessSubject": catSubject, "Resource": catResource, "Action": catAction, "Environment": catEnv,
	"RecipientSubject":    "urn:oasis:names:tc:xacml:1.0:subject-category:recipient-subject",
	"IntermediarySubject": "urn:oasis:names:tc:xacml:1.0:subject-category:intermediary-subject",
	"Codebase":            "urn:oasis:names:tc:xacml:1.0:subject-category:codebase",
	"RequestingMachine":   "urn:oasis:names:tc:xacml:1.0:subject-category:requesting-machine",
}

func parseXACMLRequest(s string) (*xrequest, error) {
	s = strings.TrimSpace(s)
	r := &xrequest{}
	if strings.HasPrefix(s, "<") {
		doc := etree.NewDocument()
		if err := doc.ReadFromString(s); err != nil || doc.Root() == nil {
			return nil, fmt.Errorf("request is not XML: %v", err)
		}
		for _, as := range kids(doc.Root(), "Attributes") {
			cat := as.SelectAttrValue("Category", "")
			for _, a := range kids(as, "Attribute") {
				for _, av := range kids(a, "AttributeValue") {
					v, err := parseXV(shortType(av.SelectAttrValue("DataType", "string")), av.Text())
					if err != nil {
						return nil, fmt.Errorf("attribute %s: %w", a.SelectAttrValue("AttributeId", ""), err)
					}
					r.attrs = append(r.attrs, xattr{cat, a.SelectAttrValue("AttributeId", ""), a.SelectAttrValue("Issuer", ""), v})
				}
			}
		}
		return r, nil
	}
	var top map[string]any
	if err := json.Unmarshal([]byte(s), &top); err != nil {
		return nil, fmt.Errorf("request is neither XML nor JSON: %w", err)
	}
	req, _ := top["Request"].(map[string]any)
	if req == nil {
		return nil, errors.New(`a JSON request needs a "Request" object (XACML JSON Profile)`)
	}
	addCat := func(cat string, obj any) error {
		var objs []any
		switch o := obj.(type) {
		case []any:
			objs = o
		case map[string]any:
			objs = []any{o}
		}
		for _, o := range objs {
			m, _ := o.(map[string]any)
			if id := str(m["CategoryId"]); id != "" {
				cat = id
				if full := jsonCategories[id]; full != "" {
					cat = full
				}
			}
			list, _ := m["Attribute"].([]any)
			for _, ai := range list {
				a, _ := ai.(map[string]any)
				if a["Value"] == nil {
					return fmt.Errorf("attribute %s has no Value", str(a["AttributeId"]))
				}
				vals, ok := a["Value"].([]any)
				if !ok {
					vals = []any{a["Value"]}
				}
				for _, raw := range vals {
					t := shortType(str(a["DataType"]))
					var sv string
					switch x := raw.(type) {
					case bool:
						if t == "" {
							t = "boolean"
						}
						sv = strconv.FormatBool(x)
					case float64:
						if t == "" {
							t = "double"
							if x == math.Trunc(x) {
								t = "integer"
							}
						}
						sv = strconv.FormatFloat(x, 'f', -1, 64)
					default:
						if t == "" {
							t = "string"
						}
						sv = fmt.Sprint(x)
					}
					v, err := parseXV(t, sv)
					if err != nil {
						return fmt.Errorf("attribute %s: %w", str(a["AttributeId"]), err)
					}
					r.attrs = append(r.attrs, xattr{cat, str(a["AttributeId"]), str(a["Issuer"]), v})
				}
			}
		}
		return nil
	}
	for k, obj := range req {
		if k == "Category" {
			if err := addCat("", obj); err != nil {
				return nil, err
			}
		} else if cat := jsonCategories[k]; cat != "" {
			if err := addCat(cat, obj); err != nil {
				return nil, err
			}
		}
	}
	return r, nil
}

// ---- evaluation ----

type xeval struct {
	req     *xrequest
	trace   []M
	missing []M
	firstEr *xerr
	vars    map[string]*etree.Element
	refs    map[string]*etree.Element
	depth   int
}

type xres struct {
	D        string
	Obl, Adv []M
}

func (e *xeval) note(err *xerr) {
	if e.firstEr == nil {
		e.firstEr = err
	}
}

func (e *xeval) designator(el *etree.Element) (*xbag, *xerr) {
	cat, id, t := el.SelectAttrValue("Category", ""), el.SelectAttrValue("AttributeId", ""), shortType(el.SelectAttrValue("DataType", ""))
	iss := el.SelectAttrValue("Issuer", "")
	b := &xbag{T: t}
	for _, a := range e.req.attrs {
		if a.Cat == cat && a.ID == id && a.V.T == t && (iss == "" || a.Issuer == iss) {
			b.V = append(b.V, a.V)
		}
	}
	if len(b.V) == 0 && el.SelectAttrValue("MustBePresent", "false") == "true" {
		e.missing = append(e.missing, M{"category": cat, "attribute_id": id, "data_type": t})
		return nil, &xerr{stMissing, "missing required attribute " + id + " (" + shortType(cat) + ")"}
	}
	return b, nil
}

func (e *xeval) expr(el *etree.Element) (any, *xerr) {
	switch el.Tag {
	case "AttributeValue":
		v, err := parseXV(shortType(el.SelectAttrValue("DataType", "")), el.Text())
		if err != nil {
			return nil, &xerr{stSyntax, err.Error()}
		}
		return v, nil
	case "AttributeDesignator":
		return e.designator(el)
	case "AttributeSelector":
		return nil, perr("AttributeSelector (XPath over request content) is not supported")
	case "Function":
		return xfn{fnName(el.SelectAttrValue("FunctionId", ""))}, nil
	case "VariableReference":
		def := e.vars[el.SelectAttrValue("VariableId", "")]
		if def == nil || len(def.ChildElements()) == 0 {
			return nil, &xerr{stSyntax, "unknown variable " + el.SelectAttrValue("VariableId", "")}
		}
		if e.depth > 64 {
			return nil, &xerr{stSyntax, "variable references nest too deeply (a cycle?)"}
		}
		e.depth++
		defer func() { e.depth-- }()
		return e.expr(def.ChildElements()[0])
	case "Apply":
		return e.apply(fnName(el.SelectAttrValue("FunctionId", "")), el.ChildElements())
	}
	return nil, &xerr{stSyntax, "unsupported expression " + el.Tag}
}

func fnName(id string) string {
	if i := strings.LastIndex(id, "function:"); i >= 0 {
		return id[i+9:]
	}
	return id
}

var xtypes = []string{"dayTimeDuration", "yearMonthDuration", "dateTime", "rfc822Name", "x500Name", "anyURI", "boolean", "integer", "double", "string", "date", "time", "ipAddress", "dnsName", "hexBinary", "base64Binary"}

func splitFn(name string) (string, string) {
	for _, t := range xtypes {
		if strings.HasPrefix(name, t+"-") {
			return t, name[len(t)+1:]
		}
	}
	return "", name
}

// apply evaluates a function application; and/or/n-of are lazy.
func (e *xeval) apply(name string, args []*etree.Element) (any, *xerr) {
	switch name {
	case "and", "or":
		want := name == "or"
		for _, a := range args {
			v, err := e.expr(a)
			if err != nil {
				return nil, err
			}
			b, ok := v.(xv)
			if !ok || b.T != "boolean" {
				return nil, perr("%s takes booleans", name)
			}
			if b.B == want {
				return xv{T: "boolean", B: want}, nil
			}
		}
		return xv{T: "boolean", B: !want}, nil
	case "n-of":
		if len(args) == 0 {
			return nil, perr("n-of needs arguments")
		}
		nv, err := e.expr(args[0])
		if err != nil {
			return nil, err
		}
		n, ok := nv.(xv)
		if !ok || n.T != "integer" {
			return nil, perr("n-of: first argument must be an integer")
		}
		count := int64(0)
		for _, a := range args[1:] {
			if count >= n.I {
				break
			}
			v, err := e.expr(a)
			if err != nil {
				return nil, err
			}
			if b, ok := v.(xv); ok && b.B {
				count++
			}
		}
		return xv{T: "boolean", B: count >= n.I}, nil
	}
	vals := make([]any, len(args))
	for i, a := range args {
		v, err := e.expr(a)
		if err != nil {
			return nil, err
		}
		vals[i] = v
	}
	return callFn(name, vals)
}

func boolV(b bool) xv { return xv{T: "boolean", B: b} }

func asPrim(a any) (xv, *xerr) {
	v, ok := a.(xv)
	if !ok {
		return xv{}, perr("expected a single value, got a bag")
	}
	return v, nil
}

func asBag(a any) (*xbag, *xerr) {
	b, ok := a.(*xbag)
	if !ok {
		return nil, perr("expected a bag")
	}
	return b, nil
}

func bagHas(b *xbag, v xv) bool {
	for _, x := range b.V {
		if c, err := cmpXV(x, v); err == nil && c == 0 {
			return true
		}
	}
	return false
}

func rfc822Match(pattern, name string) bool {
	local, domain, _ := strings.Cut(name, "@")
	if pl, pd, ok := strings.Cut(pattern, "@"); ok {
		return pl == local && strings.EqualFold(pd, domain)
	}
	if strings.HasPrefix(pattern, ".") {
		return strings.HasSuffix(strings.ToLower(domain), strings.ToLower(pattern))
	}
	return strings.EqualFold(pattern, domain)
}

// callFn implements the function library on evaluated arguments.
func callFn(name string, a []any) (any, *xerr) {
	arity := func(n int) *xerr {
		if len(a) != n {
			return perr("%s takes %d arguments, got %d", name, n, len(a))
		}
		return nil
	}
	prims := func() ([]xv, *xerr) {
		out := make([]xv, len(a))
		for i := range a {
			v, err := asPrim(a[i])
			if err != nil {
				return nil, perr("%s: %s", name, err.msg)
			}
			out[i] = v
		}
		return out, nil
	}
	switch name {
	case "not":
		if err := arity(1); err != nil {
			return nil, err
		}
		v, err := asPrim(a[0])
		if err != nil {
			return nil, err
		}
		return boolV(!v.B), nil
	case "string-equal-ignore-case":
		p, err := prims()
		if err != nil || arity(2) != nil {
			return nil, perr("%s takes two strings", name)
		}
		return boolV(strings.EqualFold(p[0].S, p[1].S)), nil
	case "string-concatenate":
		p, err := prims()
		if err != nil {
			return nil, err
		}
		var b strings.Builder
		for _, v := range p {
			b.WriteString(v.S)
		}
		return xv{T: "string", S: b.String()}, nil
	case "string-starts-with", "string-ends-with", "string-contains", "anyURI-starts-with", "anyURI-ends-with", "anyURI-contains":
		p, err := prims()
		if err != nil || len(p) != 2 {
			return nil, perr("%s takes two arguments", name)
		}
		f := map[string]func(string, string) bool{"starts-with": strings.HasPrefix, "ends-with": strings.HasSuffix, "contains": strings.Contains}[name[strings.Index(name, "-")+1:]]
		return boolV(f(p[1].S, p[0].S)), nil
	case "string-normalize-space":
		p, err := prims()
		if err != nil || len(p) != 1 {
			return nil, perr("%s takes one string", name)
		}
		return xv{T: "string", S: strings.TrimSpace(p[0].S)}, nil
	case "string-normalize-to-lower-case":
		p, err := prims()
		if err != nil || len(p) != 1 {
			return nil, perr("%s takes one string", name)
		}
		return xv{T: "string", S: strings.ToLower(p[0].S)}, nil
	case "string-substring":
		p, err := prims()
		if err != nil || len(p) != 3 {
			return nil, perr("%s takes a string and two integers", name)
		}
		s, b, e := []rune(p[0].S), p[1].I, p[2].I
		if e == -1 {
			e = int64(len(s))
		}
		if b < 0 || b > e || e > int64(len(s)) {
			return nil, perr("%s: indices out of range", name)
		}
		return xv{T: "string", S: string(s[b:e])}, nil
	case "rfc822Name-match":
		p, err := prims()
		if err != nil || len(p) != 2 {
			return nil, perr("%s takes a pattern and an rfc822Name", name)
		}
		return boolV(rfc822Match(p[0].S, p[1].S)), nil
	case "integer-to-double":
		p, err := prims()
		if err != nil || len(p) != 1 {
			return nil, perr("%s takes one integer", name)
		}
		return xv{T: "double", F: float64(p[0].I)}, nil
	case "double-to-integer":
		p, err := prims()
		if err != nil || len(p) != 1 {
			return nil, perr("%s takes one double", name)
		}
		return xv{T: "integer", I: int64(p[0].F)}, nil
	case "time-in-range":
		p, err := prims()
		if err != nil || len(p) != 3 {
			return nil, perr("%s takes three times", name)
		}
		t, lo, hi := p[0].Tm, p[1].Tm, p[2].Tm
		if hi.Before(lo) { // the range wraps past midnight
			return boolV(!t.Before(lo) || !t.After(hi)), nil
		}
		return boolV(!t.Before(lo) && !t.After(hi)), nil
	case "any-of", "all-of", "any-of-any", "all-of-any", "any-of-all", "all-of-all", "map":
		return higherOrder(name, a)
	}
	t, op := splitFn(name)
	if t == "" {
		return nil, perr("unsupported function %s", name)
	}
	switch op {
	case "equal", "greater-than", "greater-than-or-equal", "less-than", "less-than-or-equal":
		p, err := prims()
		if err != nil || len(p) != 2 {
			return nil, perr("%s takes two %s values", name, t)
		}
		if p[0].T != t || p[1].T != t {
			return nil, perr("%s: arguments must be %s, got %s and %s", name, t, p[0].T, p[1].T)
		}
		c, cerr := cmpXV(p[0], p[1])
		if cerr != nil {
			return nil, perr("%s: %v", name, cerr)
		}
		return boolV(map[string]bool{"equal": c == 0, "greater-than": c > 0, "greater-than-or-equal": c >= 0, "less-than": c < 0, "less-than-or-equal": c <= 0}[op]), nil
	case "add", "subtract", "multiply", "divide", "mod", "abs", "round", "floor":
		p, err := prims()
		if err != nil || len(p) == 0 {
			return nil, perr("%s takes numbers", name)
		}
		if t == "integer" {
			r := p[0].I
			for _, v := range p[1:] {
				switch op {
				case "add":
					r += v.I
				case "subtract":
					r -= v.I
				case "multiply":
					r *= v.I
				case "divide", "mod":
					if v.I == 0 {
						return nil, perr("%s: division by zero", name)
					}
					if op == "divide" {
						r /= v.I
					} else {
						r %= v.I
					}
				}
			}
			if op == "abs" && r < 0 {
				r = -r
			}
			return xv{T: "integer", I: r}, nil
		}
		r := p[0].F
		for _, v := range p[1:] {
			switch op {
			case "add":
				r += v.F
			case "subtract":
				r -= v.F
			case "multiply":
				r *= v.F
			case "divide":
				if v.F == 0 {
					return nil, perr("%s: division by zero", name)
				}
				r /= v.F
			}
		}
		switch op {
		case "abs":
			r = math.Abs(r)
		case "round":
			r = math.RoundToEven(r)
		case "floor":
			r = math.Floor(r)
		}
		return xv{T: "double", F: r}, nil
	case "regexp-match":
		p, err := prims()
		if err != nil || len(p) != 2 {
			return nil, perr("%s takes a pattern and a value", name)
		}
		re, rerr := regexp.Compile(p[0].S)
		if rerr != nil {
			return nil, perr("%s: bad pattern: %v", name, rerr)
		}
		return boolV(re.MatchString(p[1].S)), nil
	case "one-and-only":
		if err := arity(1); err != nil {
			return nil, err
		}
		b, err := asBag(a[0])
		if err != nil {
			return nil, perr("%s takes one bag", name)
		}
		if len(b.V) != 1 {
			return nil, perr("%s: the bag has %d values, not exactly one", name, len(b.V))
		}
		return b.V[0], nil
	case "bag-size":
		if err := arity(1); err != nil {
			return nil, err
		}
		b, err := asBag(a[0])
		if err != nil {
			return nil, err
		}
		return xv{T: "integer", I: int64(len(b.V))}, nil
	case "is-in":
		if err := arity(2); err != nil {
			return nil, err
		}
		v, err := asPrim(a[0])
		if err != nil {
			return nil, err
		}
		b, err := asBag(a[1])
		if err != nil {
			return nil, err
		}
		return boolV(bagHas(b, v)), nil
	case "bag":
		p, err := prims()
		if err != nil {
			return nil, err
		}
		return &xbag{T: t, V: p}, nil
	case "intersection", "union", "at-least-one-member-of", "subset", "set-equals":
		if err := arity(2); err != nil {
			return nil, err
		}
		x, err1 := asBag(a[0])
		y, err2 := asBag(a[1])
		if err1 != nil || err2 != nil {
			return nil, perr("%s takes two bags", name)
		}
		switch op {
		case "intersection", "union":
			out := &xbag{T: t}
			add := func(v xv) {
				if !bagHas(out, v) {
					out.V = append(out.V, v)
				}
			}
			for _, v := range x.V {
				if op == "union" || bagHas(y, v) {
					add(v)
				}
			}
			if op == "union" {
				for _, v := range y.V {
					add(v)
				}
			}
			return out, nil
		case "at-least-one-member-of":
			for _, v := range x.V {
				if bagHas(y, v) {
					return boolV(true), nil
				}
			}
			return boolV(false), nil
		case "subset", "set-equals":
			sub := func(p, q *xbag) bool {
				for _, v := range p.V {
					if !bagHas(q, v) {
						return false
					}
				}
				return true
			}
			if op == "subset" {
				return boolV(sub(x, y)), nil
			}
			return boolV(sub(x, y) && sub(y, x)), nil
		}
	case "from-string":
		p, err := prims()
		if err != nil || len(p) != 1 {
			return nil, perr("%s takes one string", name)
		}
		v, perr2 := parseXV(t, p[0].S)
		if perr2 != nil {
			return nil, &xerr{stSyntax, perr2.Error()}
		}
		return v, nil
	}
	if t == "string" && strings.HasPrefix(op, "from-") { // string-from-integer, string-from-boolean, ...
		p, err := prims()
		if err != nil || len(p) != 1 {
			return nil, perr("%s takes one value", name)
		}
		return xv{T: "string", S: p[0].String()}, nil
	}
	return nil, perr("unsupported function %s", name)
}

var specialFns = map[string]bool{"and": true, "or": true, "n-of": true, "not": true, "string-equal-ignore-case": true, "string-concatenate": true,
	"string-starts-with": true, "string-ends-with": true, "string-contains": true, "anyURI-starts-with": true, "anyURI-ends-with": true, "anyURI-contains": true,
	"string-normalize-space": true, "string-normalize-to-lower-case": true, "string-substring": true, "rfc822Name-match": true,
	"integer-to-double": true, "double-to-integer": true, "time-in-range": true,
	"any-of": true, "all-of": true, "any-of-any": true, "all-of-any": true, "any-of-all": true, "all-of-all": true, "map": true}

var typedOps = map[string]bool{"equal": true, "greater-than": true, "greater-than-or-equal": true, "less-than": true, "less-than-or-equal": true,
	"add": true, "subtract": true, "multiply": true, "divide": true, "mod": true, "abs": true, "round": true, "floor": true, "regexp-match": true,
	"one-and-only": true, "bag-size": true, "is-in": true, "bag": true, "intersection": true, "union": true, "at-least-one-member-of": true,
	"subset": true, "set-equals": true, "from-string": true}

// supportedFn reports whether callFn implements a function name.
func supportedFn(n string) bool {
	if specialFns[n] {
		return true
	}
	t, op := splitFn(n)
	return t != "" && (typedOps[op] || (t == "string" && strings.HasPrefix(op, "from-")))
}

func higherOrder(name string, a []any) (any, *xerr) {
	if len(a) < 2 {
		return nil, perr("%s takes a function and arguments", name)
	}
	f, ok := a[0].(xfn)
	if !ok {
		return nil, perr("%s: the first argument must be a Function", name)
	}
	call := func(args ...xv) (xv, *xerr) {
		in := make([]any, len(args))
		for i := range args {
			in[i] = args[i]
		}
		r, err := callFn(f.name, in)
		if err != nil {
			return xv{}, err
		}
		v, ok := r.(xv)
		if !ok {
			return xv{}, perr("%s: %s must return a single value", name, f.name)
		}
		return v, nil
	}
	if name == "any-of-any" || name == "all-of-any" || name == "any-of-all" || name == "all-of-all" {
		if len(a) != 3 {
			return nil, perr("%s takes a function and two bags", name)
		}
		x, err1 := asBag(a[1])
		y, err2 := asBag(a[2])
		if err1 != nil || err2 != nil {
			if name != "any-of-any" {
				return nil, perr("%s takes two bags", name)
			}
		}
		if name == "any-of-any" && (err1 != nil || err2 != nil) {
			// 3.0 any-of-any accepts primitives as well as bags.
			return crossProduct(name, a[1:], call, true)
		}
		outerAll := name == "all-of-any" || name == "all-of-all"
		innerAll := name == "any-of-all" || name == "all-of-all"
		for _, u := range x.V {
			inner := innerAll
			for _, w := range y.V {
				r, err := call(u, w)
				if err != nil {
					return nil, err
				}
				if innerAll && !r.B {
					inner = false
					break
				}
				if !innerAll && r.B {
					inner = true
					break
				}
			}
			if outerAll && !inner {
				return boolV(false), nil
			}
			if !outerAll && inner {
				return boolV(true), nil
			}
		}
		return boolV(outerAll), nil
	}
	if name == "map" {
		out := &xbag{}
		_, err := crossProductEach(a[1:], func(args []xv) (bool, *xerr) {
			r, err := call(args...)
			if err != nil {
				return false, err
			}
			out.T = r.T
			out.V = append(out.V, r)
			return false, nil
		})
		return out, err
	}
	return crossProduct(name, a[1:], call, name == "any-of")
}

// crossProduct applies call across every tuple of the bags and primitives:
// any reports whether some tuple is true, otherwise whether all are.
func crossProduct(name string, args []any, call func(...xv) (xv, *xerr), any bool) (any, *xerr) {
	found, err := crossProductEach(args, func(t []xv) (bool, *xerr) {
		r, err := call(t...)
		if err != nil {
			return false, err
		}
		return r.B == any, nil // stop early on the deciding value
	})
	if err != nil {
		return nil, err
	}
	if any {
		return boolV(found), nil
	}
	return boolV(!found), nil
}

func crossProductEach(args []any, f func([]xv) (bool, *xerr)) (bool, *xerr) {
	lists := make([][]xv, len(args))
	for i, x := range args {
		switch v := x.(type) {
		case xv:
			lists[i] = []xv{v}
		case *xbag:
			lists[i] = v.V
		default:
			return false, perr("arguments must be values or bags")
		}
	}
	tuple := make([]xv, len(lists))
	var walk func(int) (bool, *xerr)
	walk = func(i int) (bool, *xerr) {
		if i == len(lists) {
			return f(append([]xv{}, tuple...))
		}
		for _, v := range lists[i] {
			tuple[i] = v
			stop, err := walk(i + 1)
			if err != nil || stop {
				return stop, err
			}
		}
		return false, nil
	}
	return walk(0)
}

// ---- targets, rules, policies ----

func (e *xeval) match(m *etree.Element) (string, *xerr) {
	var lit, desig *etree.Element
	for _, ch := range m.ChildElements() {
		if ch.Tag == "AttributeValue" {
			lit = ch
		} else {
			desig = ch
		}
	}
	if lit == nil || desig == nil {
		return "Indeterminate", &xerr{stSyntax, "Match needs an AttributeValue and a designator"}
	}
	lv, err := e.expr(lit)
	if err != nil {
		return "Indeterminate", err
	}
	bv, err := e.expr(desig)
	if err != nil {
		return "Indeterminate", err
	}
	bag, ok := bv.(*xbag)
	if !ok {
		return "Indeterminate", perr("Match designator did not produce a bag")
	}
	fn := fnName(m.SelectAttrValue("MatchId", ""))
	var firstErr *xerr
	for _, v := range bag.V {
		r, err := callFn(fn, []any{lv, v})
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if b, ok := r.(xv); ok && b.B {
			return "Match", nil
		}
	}
	if firstErr != nil {
		return "Indeterminate", firstErr
	}
	return "NoMatch", nil
}

func (e *xeval) target(t *etree.Element) (string, *xerr) {
	if t == nil {
		return "Match", nil
	}
	result := "Match"
	var firstErr *xerr
	for _, anyOf := range kids(t, "AnyOf") {
		anyRes := "NoMatch"
		for _, allOf := range kids(anyOf, "AllOf") {
			allRes := "Match"
			for _, m := range kids(allOf, "Match") {
				r, err := e.match(m)
				if err != nil && firstErr == nil {
					firstErr = err
				}
				if r == "NoMatch" {
					allRes = "NoMatch"
					break
				}
				if r == "Indeterminate" {
					allRes = "Indeterminate"
				}
			}
			if allRes == "Match" {
				anyRes = "Match"
				break
			}
			if allRes == "Indeterminate" {
				anyRes = "Indeterminate"
			}
		}
		if anyRes == "NoMatch" {
			return "NoMatch", nil
		}
		if anyRes == "Indeterminate" {
			result = "Indeterminate"
		}
	}
	if result == "Indeterminate" {
		return result, firstErr
	}
	return result, nil
}

func (e *xeval) assignments(el *etree.Element, effect string, tag, idAttr, onAttr string) []M {
	var out []M
	if el == nil {
		return nil
	}
	for _, ex := range kids(el, tag) {
		if ex.SelectAttrValue(onAttr, "") != effect {
			continue
		}
		var assigns []M
		for _, aa := range kids(ex, "AttributeAssignmentExpression") {
			entry := M{"attribute_id": aa.SelectAttrValue("AttributeId", ""), "category": aa.SelectAttrValue("Category", "")}
			if len(aa.ChildElements()) > 0 {
				v, err := e.expr(aa.ChildElements()[0])
				switch {
				case err != nil:
					entry["error"] = err.msg
				default:
					switch x := v.(type) {
					case xv:
						entry["value"] = x.String()
					case *xbag:
						var vs []string
						for _, i := range x.V {
							vs = append(vs, i.String())
						}
						entry["value"] = vs
					}
				}
			}
			assigns = append(assigns, entry)
		}
		out = append(out, M{"id": ex.SelectAttrValue(idAttr, ""), "assignments": assigns})
	}
	return out
}

func (e *xeval) rule(r *etree.Element) xres {
	effect := r.SelectAttrValue("Effect", "")
	tr := M{"type": "Rule", "id": r.SelectAttrValue("RuleId", ""), "effect": effect}
	defer func() { e.trace = append(e.trace, tr) }()
	indFor := map[string]string{"Permit": dIndP, "Deny": dIndD}[effect]
	t, err := e.target(kid(r, "Target"))
	tr["target"] = t
	if t == "NoMatch" {
		tr["decision"] = dNA
		return xres{D: dNA}
	}
	if t == "Indeterminate" {
		e.note(err)
		tr["decision"], tr["error"] = indFor, err.msg
		return xres{D: indFor}
	}
	if c := kid(r, "Condition"); c != nil && len(c.ChildElements()) > 0 {
		v, err := e.expr(c.ChildElements()[0])
		if err != nil {
			e.note(err)
			tr["condition"], tr["decision"], tr["error"] = "Indeterminate", indFor, err.msg
			return xres{D: indFor}
		}
		b, ok := v.(xv)
		if !ok || b.T != "boolean" {
			err := perr("the condition did not produce a boolean")
			e.note(err)
			tr["condition"], tr["decision"], tr["error"] = "Indeterminate", indFor, err.msg
			return xres{D: indFor}
		}
		tr["condition"] = b.B
		if !b.B {
			tr["decision"] = dNA
			return xres{D: dNA}
		}
	}
	tr["decision"] = effect
	return xres{D: effect, Obl: e.assignments(kid(r, "ObligationExpressions"), effect, "ObligationExpression", "ObligationId", "FulfillOn"),
		Adv: e.assignments(kid(r, "AdviceExpressions"), effect, "AdviceExpression", "AdviceId", "AppliesTo")}
}

// combine applies a combining algorithm (C.2 to C.9) to child evaluations.
func combine(alg string, n int, eval func(i int) xres, applicable func(i int) (string, *xerr)) xres {
	short := alg[strings.LastIndex(alg, ":")+1:]
	gather := func(rs []xres, d string) xres {
		out := xres{D: d}
		for _, r := range rs {
			if r.D == d {
				out.Obl = append(out.Obl, r.Obl...)
				out.Adv = append(out.Adv, r.Adv...)
			}
		}
		return out
	}
	var rs []xres
	switch short {
	case "deny-overrides", "ordered-deny-overrides", "permit-overrides", "ordered-permit-overrides":
		win, other := dDeny, dPermit
		indWin, indOther := dIndD, dIndP
		if strings.HasSuffix(short, "permit-overrides") {
			win, other, indWin, indOther = dPermit, dDeny, dIndP, dIndD
		}
		var errWin, errOther, errDP, sawOther bool
		for i := 0; i < n; i++ {
			r := eval(i)
			rs = append(rs, r)
			switch r.D {
			case win:
				return gather(rs, win)
			case other:
				sawOther = true
			case indWin:
				errWin = true
			case indOther:
				errOther = true
			case dIndDP:
				errDP = true
			}
		}
		switch {
		case errDP:
			return xres{D: dIndDP}
		case errWin && (errOther || sawOther):
			return xres{D: dIndDP}
		case errWin:
			return xres{D: indWin}
		case sawOther:
			return gather(rs, other)
		case errOther:
			return xres{D: indOther}
		}
		return xres{D: dNA}
	case "first-applicable":
		for i := 0; i < n; i++ {
			r := eval(i)
			if r.D != dNA {
				return r
			}
		}
		return xres{D: dNA}
	case "only-one-applicable":
		chosen := -1
		for i := 0; i < n; i++ {
			a, _ := applicable(i)
			if a == "Indeterminate" {
				return xres{D: dIndDP}
			}
			if a == "Match" {
				if chosen >= 0 {
					return xres{D: dIndDP}
				}
				chosen = i
			}
		}
		if chosen < 0 {
			return xres{D: dNA}
		}
		return eval(chosen)
	case "deny-unless-permit", "permit-unless-deny":
		win, other := dPermit, dDeny
		if short == "permit-unless-deny" {
			win, other = dDeny, dPermit
		}
		for i := 0; i < n; i++ {
			r := eval(i)
			rs = append(rs, r)
			if r.D == win {
				return gather(rs, win)
			}
		}
		return gather(rs, other)
	}
	return xres{D: dIndDP}
}

var knownAlgs = map[string]bool{"deny-overrides": true, "ordered-deny-overrides": true, "permit-overrides": true, "ordered-permit-overrides": true,
	"first-applicable": true, "only-one-applicable": true, "deny-unless-permit": true, "permit-unless-deny": true}

func (e *xeval) policy(p *etree.Element) xres {
	isSet := p.Tag == "PolicySet"
	idAttr, algAttr := "PolicyId", "RuleCombiningAlgId"
	if isSet {
		idAttr, algAttr = "PolicySetId", "PolicyCombiningAlgId"
	}
	tr := M{"type": p.Tag, "id": p.SelectAttrValue(idAttr, "")}
	if !isSet {
		for _, vd := range kids(p, "VariableDefinition") {
			e.vars[vd.SelectAttrValue("VariableId", "")] = vd
		}
	}
	t, terr := e.target(kid(p, "Target"))
	tr["target"] = t
	if t == "NoMatch" {
		tr["decision"] = dNA
		e.trace = append(e.trace, tr)
		return xres{D: dNA}
	}
	var children []*etree.Element
	for _, ch := range p.ChildElements() {
		switch ch.Tag {
		case "Rule", "Policy", "PolicySet":
			if !isSet && ch.Tag != "Rule" || isSet && ch.Tag == "Rule" {
				continue
			}
			children = append(children, ch)
		case "PolicyIdReference", "PolicySetIdReference":
			if ref := e.refs[text(ch)]; ref != nil {
				children = append(children, ref)
			} else {
				children = append(children, ch) // evaluated as an unresolved reference
			}
		}
	}
	alg := p.SelectAttrValue(algAttr, "")
	if e.depth > 32 {
		tr["decision"], tr["error"] = dIndDP, "policy references nest too deeply (a cycle?)"
		e.trace = append(e.trace, tr)
		return xres{D: dIndDP}
	}
	e.depth++
	defer func() { e.depth-- }()
	evalChild := func(i int) xres {
		ch := children[i]
		switch ch.Tag {
		case "Rule":
			return e.rule(ch)
		case "PolicyIdReference", "PolicySetIdReference":
			err := perr("unresolved %s %s", ch.Tag, text(ch))
			e.note(err)
			e.trace = append(e.trace, M{"type": ch.Tag, "id": text(ch), "decision": dIndDP, "error": err.msg})
			return xres{D: dIndDP}
		}
		return e.policy(ch)
	}
	applicable := func(i int) (string, *xerr) { return e.target(kid(children[i], "Target")) }
	r := combine(alg, len(children), evalChild, applicable)
	if !knownAlgs[alg[strings.LastIndex(alg, ":")+1:]] {
		err := &xerr{stSyntax, "unknown combining algorithm " + alg}
		e.note(err)
		tr["error"] = err.msg
	}
	if t == "Indeterminate" {
		e.note(terr)
		switch r.D {
		case dPermit:
			r = xres{D: dIndP}
		case dDeny:
			r = xres{D: dIndD}
		}
		tr["error"] = terr.msg
	}
	if r.D == dPermit || r.D == dDeny {
		r.Obl = append(r.Obl, e.assignments(kid(p, "ObligationExpressions"), r.D, "ObligationExpression", "ObligationId", "FulfillOn")...)
		r.Adv = append(r.Adv, e.assignments(kid(p, "AdviceExpressions"), r.D, "AdviceExpression", "AdviceId", "AppliesTo")...)
	}
	tr["algorithm"], tr["decision"] = alg[strings.LastIndex(alg, ":")+1:], r.D
	e.trace = append(e.trace, tr)
	return r
}

// lintPolicy reports structural problems without evaluating.
func lintPolicy(cs *Checks, root *etree.Element) {
	var all []*etree.Element
	findAll(root, "Apply", &all)
	var fns []*etree.Element
	findAll(root, "Function", &fns)
	var matches []*etree.Element
	findAll(root, "Match", &matches)
	unknown := map[string]bool{}
	check := func(id string) {
		if !supportedFn(fnName(id)) {
			unknown[id] = true
		}
	}
	for _, a := range all {
		check(a.SelectAttrValue("FunctionId", ""))
	}
	for _, f := range fns {
		check(f.SelectAttrValue("FunctionId", ""))
	}
	for _, m := range matches {
		check(m.SelectAttrValue("MatchId", ""))
	}
	var ids []string
	for id := range unknown {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	cs.ok(len(ids) == 0, "all functions are supported", strings.Join(ids, ", "), xacmlRef+" Appendix A.3")
	var sels []*etree.Element
	findAll(root, "AttributeSelector", &sels)
	if len(sels) > 0 {
		cs.add("AttributeSelector", "warn", fmt.Sprintf("%d XPath selector(s): not evaluated by idpdbg (they yield Indeterminate)", len(sels)), xacmlRef+" §5.30")
	}
	var rules []*etree.Element
	findAll(root, "Rule", &rules)
	if root.Tag == "Rule" {
		rules = append(rules, root)
	}
	seen := map[string]bool{}
	for _, r := range rules {
		id := r.SelectAttrValue("RuleId", "")
		if seen[id] {
			cs.add("rule ids unique", "fail", "duplicate RuleId "+id, xacmlRef+" §5.21")
		}
		seen[id] = true
		eff := r.SelectAttrValue("Effect", "")
		cs.ok(eff == "Permit" || eff == "Deny", "rule "+id+": Effect is Permit or Deny", eff, xacmlRef+" §5.21")
	}
	var pols []*etree.Element
	findAll(root, "Policy", &pols)
	findAll(root, "PolicySet", &pols)
	pols = append(pols, root)
	for _, p := range pols {
		for _, attr := range []string{"RuleCombiningAlgId", "PolicyCombiningAlgId"} {
			if alg := p.SelectAttrValue(attr, ""); alg != "" {
				cs.ok(knownAlgs[alg[strings.LastIndex(alg, ":")+1:]], p.Tag+" "+p.SelectAttrValue("PolicyId", p.SelectAttrValue("PolicySetId", ""))+": combining algorithm known", alg, xacmlRef+" Appendix C")
				if strings.Contains(alg, ":1.0:") && !strings.HasSuffix(alg, "first-applicable") && !strings.HasSuffix(alg, "only-one-applicable") {
					cs.add("legacy combining algorithm", "info", alg+" is the XACML 1.0 version; it is evaluated with XACML 3.0 semantics", xacmlRef+" Appendix C.10")
				}
			}
		}
		if p.SelectAttrValue("Version", "") == "" && (p.Tag == "Policy" || p.Tag == "PolicySet") {
			cs.add(p.Tag+" Version", "warn", "Version is required", xacmlRef+" §5.1, §5.14")
		}
	}
}

func runXACML(c *Ctx) (M, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(c.Str("policy")); err != nil || doc.Root() == nil {
		return nil, fmt.Errorf("policy is not XML: %v", err)
	}
	root := doc.Root()
	if root.Tag != "Policy" && root.Tag != "PolicySet" {
		return nil, fmt.Errorf("the policy document's root is %s, not Policy or PolicySet", root.Tag)
	}
	var cs Checks
	lintPolicy(&cs, root)
	out := M{}
	if c.Str("request") == "" {
		out["checks"] = cs
		return out, nil
	}
	req, err := parseXACMLRequest(c.Str("request"))
	if err != nil {
		return nil, err
	}
	e := &xeval{req: req, vars: map[string]*etree.Element{}, refs: map[string]*etree.Element{}}
	var ps []*etree.Element
	findAll(root, "Policy", &ps)
	findAll(root, "PolicySet", &ps)
	for _, p := range ps {
		e.refs[p.SelectAttrValue("PolicyId", p.SelectAttrValue("PolicySetId", ""))] = p
	}
	r := e.policy(root)
	status := M{"code": "urn:oasis:names:tc:xacml:1.0:status:ok"}
	if isInd(r.D) && e.firstEr != nil {
		status = M{"code": e.firstEr.code, "message": e.firstEr.msg}
		if len(e.missing) > 0 {
			status["missing_attributes"] = e.missing
		}
	}
	decision := r.D
	if isInd(decision) {
		decision = "Indeterminate"
	}
	out["decision"], out["extended_decision"], out["status"] = decision, r.D, status
	if len(r.Obl) > 0 {
		out["obligations"] = r.Obl
	}
	if len(r.Adv) > 0 {
		out["advice"] = r.Adv
	}
	out["trace"] = e.trace
	// What a PEP does with the decision (§7.2).
	pep := M{"deny_biased": map[bool]string{true: "permit", false: "deny"}[decision == dPermit], "permit_biased": map[bool]string{true: "deny", false: "permit"}[decision == dDeny]}
	if len(r.Obl) > 0 {
		pep["note"] = "both PEPs must deny if they cannot fulfil every obligation"
	}
	out["pep"] = pep
	cs.add("decision", "info", r.D, xacmlRef+" §7")
	out["checks"] = cs
	return out, nil
}

func init() {
	register(&Op{
		Name:    "xacml.evaluate",
		Summary: "Evaluate an XACML 3.0 policy or policy set against a request (XML, or the JSON Profile): targets, conditions, variables, the core function library (equality, comparison, arithmetic, string, regexp, rfc822Name, bag, set, higher-order), every standard combining algorithm with extended Indeterminate, and obligations and advice. Returns the decision, status and missing attributes, a trace of every rule and policy, and what deny- and permit-biased PEPs would enforce. Without a request it only checks the policy.",
		Params: []Param{
			{Name: "policy", Type: "string", Required: true, Path: true, File: true, Desc: "XACML 3.0 Policy or PolicySet (XML)"},
			{Name: "request", Type: "string", Path: true, File: true, Desc: "XACML request: XML <Request>, or JSON Profile {\"Request\": {...}}"}},
		Run: runXACML,
	})
}
