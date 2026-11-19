package main

import (
	"fmt"
	"strings"
	"testing"
)

const (
	xsString = "http://www.w3.org/2001/XMLSchema#string"
	xsInt    = "http://www.w3.org/2001/XMLSchema#integer"
	xsTime   = "http://www.w3.org/2001/XMLSchema#time"
	fnPrefix = "urn:oasis:names:tc:xacml:1.0:function:"
)

// XACML 3.0 core §4.2.1 Example one: "Any user with an e-mail name in the
// med.example.com namespace is allowed to perform any action on any resource."
const exampleOnePolicy = `<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="urn:oasis:names:tc:xacml:3.0:example:SimplePolicy1" Version="1.0"
  RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">
  <Description>Medi Corp access control policy</Description>
  <Target/>
  <Rule RuleId="urn:oasis:names:tc:xacml:3.0:example:SimpleRule1" Effect="Permit">
    <Target><AnyOf><AllOf>
      <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:rfc822Name-match">
        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">med.example.com</AttributeValue>
        <AttributeDesignator MustBePresent="false" Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
          AttributeId="urn:oasis:names:tc:xacml:1.0:subject:subject-id" DataType="urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name"/>
      </Match>
    </AllOf></AnyOf></Target>
  </Rule>
</Policy>`

func subjectRequest(email string) string {
	return `<Request xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" CombinedDecision="false" ReturnPolicyIdList="false">
  <Attributes Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject">
    <Attribute IncludeInResult="false" AttributeId="urn:oasis:names:tc:xacml:1.0:subject:subject-id">
      <AttributeValue DataType="urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name">` + email + `</AttributeValue></Attribute></Attributes>
  <Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource">
    <Attribute IncludeInResult="false" AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id">
      <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#anyURI">file://example/med/record/patient/BartSimpson</AttributeValue></Attribute></Attributes>
  <Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action">
    <Attribute IncludeInResult="false" AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id">
      <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">read</AttributeValue></Attribute></Attributes>
</Request>`
}

// rule builds a rule whose outcome is fixed: Permit, Deny, NA (target misses)
// or Ind (its condition needs a missing attribute).
func xrule(id, effect, outcome string) string {
	switch outcome {
	case "NA":
		return fmt.Sprintf(`<Rule RuleId="%s" Effect="%s"><Target><AnyOf><AllOf><Match MatchId="%sstring-equal"><AttributeValue DataType="%s">nobody</AttributeValue>`+
			`<AttributeDesignator Category="%s" AttributeId="role" DataType="%s" MustBePresent="false"/></Match></AllOf></AnyOf></Target></Rule>`, id, effect, fnPrefix, xsString, catSubject, xsString)
	case "Ind":
		return fmt.Sprintf(`<Rule RuleId="%s" Effect="%s"><Condition><Apply FunctionId="%sstring-is-in"><AttributeValue DataType="%s">x</AttributeValue>`+
			`<AttributeDesignator Category="%s" AttributeId="absent" DataType="%s" MustBePresent="true"/></Apply></Condition></Rule>`, id, effect, fnPrefix, xsString, catSubject, xsString)
	}
	return fmt.Sprintf(`<Rule RuleId="%s" Effect="%s"/>`, id, effect)
}

func xpolicy(alg string, rules ...string) string {
	return `<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="p" Version="1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:` + alg + `">` + strings.Join(rules, "") + `</Policy>`
}

const emptyRequest = `{"Request": {"AccessSubject": {"Attribute": [{"AttributeId": "role", "Value": "doctor"}]}}}`

func decide(t *testing.T, policy, request string) M {
	t.Helper()
	return run(t, "xacml.evaluate", M{"policy": policy, "request": request}, nil)
}

func TestXACMLSpecExample(t *testing.T) {
	if d := decide(t, exampleOnePolicy, subjectRequest("bs@simpsons.com"))["decision"]; d != "NotApplicable" {
		t.Errorf("Example one with bs@simpsons.com: %v, the spec says NotApplicable", d)
	}
	res := decide(t, exampleOnePolicy, subjectRequest("Julius.Hibbert@med.example.com"))
	if res["decision"] != "Permit" {
		t.Errorf("a med.example.com subject: %v", res["decision"])
	}
	if res["pep"].(M)["deny_biased"] != "permit" {
		t.Errorf("pep: %v", res["pep"])
	}
	noFailures(t, res)
}

func TestXACMLCombiningAlgorithms(t *testing.T) {
	// Each case: algorithm, rule outcomes (effect:outcome), expected extended decision.
	cases := []struct {
		alg   string
		rules []string
		want  string
	}{
		{"deny-overrides", []string{"Permit:Permit", "Deny:Deny"}, dDeny},
		{"deny-overrides", []string{"Permit:Permit", "Permit:NA"}, dPermit},
		{"deny-overrides", []string{"Deny:Ind", "Permit:Permit"}, dIndDP},
		{"deny-overrides", []string{"Deny:Ind"}, dIndD},
		{"deny-overrides", []string{"Permit:Ind"}, dIndP},
		{"deny-overrides", []string{"Permit:Ind", "Permit:Permit"}, dPermit},
		{"deny-overrides", []string{"Deny:Ind", "Permit:Ind"}, dIndDP},
		{"deny-overrides", []string{"Permit:NA", "Deny:NA"}, dNA},
		{"permit-overrides", []string{"Deny:Deny", "Permit:Permit"}, dPermit},
		{"permit-overrides", []string{"Permit:Ind", "Deny:Deny"}, dIndDP},
		{"permit-overrides", []string{"Permit:Ind"}, dIndP},
		{"permit-overrides", []string{"Deny:Ind", "Deny:Deny"}, dDeny},
		{"ordered-deny-overrides", []string{"Deny:Ind", "Permit:Permit"}, dIndDP},
		{"deny-unless-permit", []string{"Permit:Ind", "Deny:NA"}, dDeny},
		{"deny-unless-permit", []string{"Deny:Deny", "Permit:Permit"}, dPermit},
		{"permit-unless-deny", []string{"Deny:Ind"}, dPermit},
		{"permit-unless-deny", []string{"Permit:Permit", "Deny:Deny"}, dDeny},
		{"first-applicable", []string{"Permit:NA", "Deny:Ind", "Permit:Permit"}, dIndD},
		{"first-applicable", []string{"Permit:NA", "Deny:Deny", "Permit:Permit"}, dDeny},
	}
	for i, tc := range cases {
		var rules []string
		for j, r := range tc.rules {
			eff, out, _ := strings.Cut(r, ":")
			rules = append(rules, xrule(fmt.Sprintf("r%d", j), eff, out))
		}
		res := decide(t, xpolicy(tc.alg, rules...), emptyRequest)
		if res["extended_decision"] != tc.want {
			t.Errorf("case %d %s %v: got %v, want %s", i, tc.alg, tc.rules, res["extended_decision"], tc.want)
		}
	}
}

func TestXACMLPolicySets(t *testing.T) {
	ps := func(alg string, policies ...string) string {
		return `<PolicySet xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicySetId="ps" Version="1" PolicyCombiningAlgId="urn:oasis:names:tc:xacml:1.0:policy-combining-algorithm:` + alg + `">` +
			strings.Join(policies, "") + `</PolicySet>`
	}
	permit := strings.Replace(xpolicy("deny-overrides", xrule("a", "Permit", "Permit")), `PolicyId="p"`, `PolicyId="p1"`, 1)
	deny := strings.Replace(xpolicy("deny-overrides", xrule("b", "Deny", "Deny")), `PolicyId="p"`, `PolicyId="p2"`, 1)
	if d := decide(t, ps("only-one-applicable", permit, deny), emptyRequest)["extended_decision"]; d != dIndDP {
		t.Errorf("only-one-applicable with two applicable policies: %v", d)
	}
	if d := decide(t, ps("only-one-applicable", permit), emptyRequest)["extended_decision"]; d != dPermit {
		t.Errorf("only-one-applicable with one: %v", d)
	}
	if d := decide(t, ps("first-applicable", deny, permit), emptyRequest)["extended_decision"]; d != dDeny {
		t.Errorf("first-applicable policy set: %v", d)
	}
	// A policy whose target is Indeterminate turns its Permit into Indeterminate{P} (§7.13).
	indTarget := `<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="pt" Version="1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">` +
		`<Target><AnyOf><AllOf><Match MatchId="` + fnPrefix + `string-equal"><AttributeValue DataType="` + xsString + `">x</AttributeValue>` +
		`<AttributeDesignator Category="` + catResource + `" AttributeId="absent" DataType="` + xsString + `" MustBePresent="true"/></Match></AllOf></AnyOf></Target>` +
		xrule("r", "Permit", "Permit") + `</Policy>`
	res := decide(t, indTarget, emptyRequest)
	if res["extended_decision"] != dIndP || res["status"].(M)["code"] != stMissing {
		t.Errorf("Indeterminate target: %v %v", res["extended_decision"], res["status"])
	}
	if miss := res["status"].(M)["missing_attributes"].([]M); len(miss) != 1 || miss[0]["attribute_id"] != "absent" {
		t.Errorf("missing attributes: %v", miss)
	}
}

func TestXACMLFunctionsAndObligations(t *testing.T) {
	cond := func(expr string) string {
		return xpolicy("deny-overrides", `<Rule RuleId="c" Effect="Permit"><Condition>`+expr+`</Condition>`+
			`<ObligationExpressions><ObligationExpression ObligationId="log" FulfillOn="Permit"><AttributeAssignmentExpression AttributeId="msg">`+
			`<AttributeValue DataType="`+xsString+`">granted</AttributeValue></AttributeAssignmentExpression></ObligationExpression>`+
			`<ObligationExpression ObligationId="never" FulfillOn="Deny"/></ObligationExpressions></Rule>`)
	}
	des := func(id, typ string) string {
		return `<AttributeDesignator Category="` + catSubject + `" AttributeId="` + id + `" DataType="` + typ + `" MustBePresent="false"/>`
	}
	val := func(typ, v string) string { return `<AttributeValue DataType="` + typ + `">` + v + `</AttributeValue>` }
	ap := func(fn string, args ...string) string {
		return `<Apply FunctionId="` + fn + `">` + strings.Join(args, "") + `</Apply>`
	}
	req := `{"Request":{"AccessSubject":{"Attribute":[{"AttributeId":"role","Value":["nurse","doctor"]},{"AttributeId":"level","Value":7},
		{"AttributeId":"email","Value":"alice@Med.Example.com","DataType":"rfc822Name"},{"AttributeId":"at","Value":"23:30:00","DataType":"time"}]}}}`
	cases := []struct {
		name, expr, want string
	}{
		{"any-of over a bag", ap("urn:oasis:names:tc:xacml:3.0:function:any-of", `<Function FunctionId="`+fnPrefix+`string-equal"/>`, val(xsString, "doctor"), des("role", xsString)), dPermit},
		{"all-of over a bag", ap("urn:oasis:names:tc:xacml:3.0:function:all-of", `<Function FunctionId="`+fnPrefix+`string-equal"/>`, val(xsString, "doctor"), des("role", xsString)), dNA},
		{"arithmetic", ap(fnPrefix+"integer-greater-than", ap(fnPrefix+"integer-add", ap(fnPrefix+"integer-one-and-only", des("level", xsInt)), val(xsInt, "3")), val(xsInt, "9")), dPermit},
		{"one-and-only on two values", ap(fnPrefix+"string-equal", ap(fnPrefix+"string-one-and-only", des("role", xsString)), val(xsString, "x")), dIndP},
		{"regexp", ap(fnPrefix+"string-regexp-match", val(xsString, "^d.c"), ap(fnPrefix+"string-one-and-only", ap(fnPrefix+"string-bag", val(xsString, "doctor")))), dPermit},
		{"rfc822Name domain is case-insensitive", ap(fnPrefix+"rfc822Name-match", val(xsString, ".example.com"), ap(fnPrefix+"rfc822Name-one-and-only", des("email", "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name"))), dPermit},
		{"time-in-range wrapping midnight", ap("urn:oasis:names:tc:xacml:2.0:function:time-in-range", ap(fnPrefix+"time-one-and-only", des("at", xsTime)), val(xsTime, "22:00:00"), val(xsTime, "06:00:00")), dPermit},
		{"set functions", ap(fnPrefix+"string-at-least-one-member-of", des("role", xsString), ap(fnPrefix+"string-bag", val(xsString, "admin"), val(xsString, "nurse"))), dPermit},
		{"subset", ap(fnPrefix+"string-subset", des("role", xsString), ap(fnPrefix+"string-bag", val(xsString, "nurse"))), dNA},
		{"lazy and", ap(fnPrefix+"and", val("http://www.w3.org/2001/XMLSchema#boolean", "false"), ap(fnPrefix+"string-one-and-only", des("role", xsString))), dNA},
		{"n-of", ap(fnPrefix+"n-of", val(xsInt, "2"), val("http://www.w3.org/2001/XMLSchema#boolean", "true"), val("http://www.w3.org/2001/XMLSchema#boolean", "false"), val("http://www.w3.org/2001/XMLSchema#boolean", "true")), dPermit},
		{"wrong argument type", ap(fnPrefix+"integer-equal", val(xsString, "1"), val(xsInt, "1")), dIndP},
	}
	for _, tc := range cases {
		res := decide(t, cond(tc.expr), req)
		if res["extended_decision"] != tc.want {
			t.Errorf("%s: got %v (%v), want %s", tc.name, res["extended_decision"], res["status"], tc.want)
			continue
		}
		if tc.want == dPermit {
			obl, _ := res["obligations"].([]M)
			if len(obl) != 1 || obl[0]["id"] != "log" || obl[0]["assignments"].([]M)[0]["value"] != "granted" {
				t.Errorf("%s: obligations %v", tc.name, res["obligations"])
			}
		}
	}
}

func TestXACMLRequestFormatsAndLint(t *testing.T) {
	jsonReq := `{"Request":{"AccessSubject":{"Attribute":[{"AttributeId":"urn:oasis:names:tc:xacml:1.0:subject:subject-id","Value":"Julius.Hibbert@med.example.com","DataType":"urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name"}]}}}`
	if d := decide(t, exampleOnePolicy, jsonReq)["decision"]; d != "Permit" {
		t.Errorf("JSON profile request: %v", d)
	}
	bad := `<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="x" RuleCombiningAlgId="urn:example:my-own-alg">` +
		`<Rule RuleId="r" Effect="Permit"><Condition><Apply FunctionId="urn:example:function:frobnicate"/></Condition></Rule><Rule RuleId="r" Effect="Permit"/><Rule RuleId="odd" Effect="Allow"/></Policy>`
	lint := run(t, "xacml.evaluate", M{"policy": bad}, nil)
	for _, n := range []string{"all functions are supported", "rule ids unique", "rule odd: Effect is Permit or Deny", "combining algorithm known"} {
		wantStatus(t, lint, n, "fail")
	}
	wantStatus(t, lint, "Policy Version", "warn")
	noFailures(t, run(t, "xacml.evaluate", M{"policy": exampleOnePolicy}, nil))
}
