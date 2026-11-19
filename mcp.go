package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
)

// A minimal MCP server over stdio (newline-delimited JSON-RPC 2.0) exposing
// every registered operation as a tool.

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

const mcpInstructions = `idpdbg is an identity protocol debugger. It plays the client / relying party / service provider against a real identity provider and returns each exchange decoded, with a "checks" list of spec-conformance findings (pass, fail, warn, info).
Tools are grouped by prefix: oidc_ and jwt_/jwks_ (OAuth 2.0, OpenID Connect), saml_ (SAML 2.0), scim_ (SCIM 2.0 provisioning), ldap_ (directories).
Set trace=true on any HTTP-based tool to see the raw requests and responses.
Secrets: prefer a named profile (the profile parameter) or IDPDBG_* environment variables over passing secrets as arguments.
oidc_login and saml_login open the person's browser and block until they finish signing in; tell them before calling. webauthn_register and webauthn_login with a security key wait for the person to touch it; tell them before calling.
Tools marked as not read-only change data at the remote system; confirm with the person first.`

func toolSchema(op *Op) M {
	props := M{}
	required := []string{}
	for _, p := range op.allParams() {
		prop := M{"description": p.Desc}
		switch p.Type {
		case "string":
			prop["type"] = "string"
		case "bool":
			prop["type"] = "boolean"
		case "int":
			prop["type"] = "integer"
		case "list":
			prop["type"] = "array"
			prop["items"] = M{"type": "string"}
		}
		if len(p.Enum) > 0 {
			prop["enum"] = p.Enum
		}
		if p.Default != nil {
			prop["default"] = p.Default
		}
		props[p.Name] = prop
		if p.Required && !p.Secret {
			required = append(required, p.Name)
		}
	}
	return M{"type": "object", "properties": props, "required": required}
}

func toolList() []M {
	tools := []M{}
	for _, op := range registry {
		tools = append(tools, M{
			"name":        op.tool(),
			"description": op.Summary,
			"inputSchema": toolSchema(op),
			"annotations": M{"readOnlyHint": !op.Mutating, "destructiveHint": op.Mutating, "openWorldHint": true},
		})
	}
	return tools
}

func serveMCP(in io.Reader, out io.Writer) error {
	var wmu sync.Mutex
	send := func(v any) {
		b, _ := json.Marshal(v)
		wmu.Lock()
		defer wmu.Unlock()
		out.Write(append(b, '\n'))
	}
	reply := func(id json.RawMessage, result any) {
		send(M{"jsonrpc": "2.0", "id": id, "result": result})
	}
	fail := func(id json.RawMessage, code int, msg string) {
		send(M{"jsonrpc": "2.0", "id": id, "error": M{"code": code, "message": msg}})
	}

	var cmu sync.Mutex
	cancels := map[string]context.CancelFunc{}
	var wg sync.WaitGroup
	defer wg.Wait()

	rd := bufio.NewReaderSize(in, 1<<20)
	for {
		line, err := rd.ReadBytes('\n')
		if len(strings.TrimSpace(string(line))) > 0 {
			var msg rpcMsg
			if jerr := json.Unmarshal(line, &msg); jerr != nil {
				fail(nil, -32700, "parse error")
			} else {
				switch msg.Method {
				case "initialize":
					var p struct {
						ProtocolVersion string `json:"protocolVersion"`
					}
					_ = json.Unmarshal(msg.Params, &p)
					if p.ProtocolVersion == "" {
						p.ProtocolVersion = "2025-06-18"
					}
					reply(msg.ID, M{
						"protocolVersion": p.ProtocolVersion,
						"capabilities":    M{"tools": M{}, "logging": M{}},
						"serverInfo":      M{"name": "idpdbg", "version": version},
						"instructions":    mcpInstructions,
					})
				case "ping":
					reply(msg.ID, M{})
				case "tools/list":
					reply(msg.ID, M{"tools": toolList()})
				case "logging/setLevel":
					reply(msg.ID, M{})
				case "notifications/cancelled":
					var p struct {
						RequestID json.RawMessage `json:"requestId"`
					}
					_ = json.Unmarshal(msg.Params, &p)
					cmu.Lock()
					if cancel := cancels[string(p.RequestID)]; cancel != nil {
						cancel()
					}
					cmu.Unlock()
				case "tools/call":
					var p struct {
						Name      string `json:"name"`
						Arguments M      `json:"arguments"`
					}
					if jerr := json.Unmarshal(msg.Params, &p); jerr != nil {
						fail(msg.ID, -32602, "invalid params")
						break
					}
					op := findOp(p.Name)
					if op == nil {
						fail(msg.ID, -32602, "unknown tool "+p.Name)
						break
					}
					ctx, cancel := context.WithCancel(context.Background())
					key := string(msg.ID)
					cmu.Lock()
					cancels[key] = cancel
					cmu.Unlock()
					wg.Add(1)
					go func(id json.RawMessage) {
						defer wg.Done()
						defer func() {
							cmu.Lock()
							delete(cancels, key)
							cmu.Unlock()
							cancel()
						}()
						log := func(format string, a ...any) {
							send(M{"jsonrpc": "2.0", "method": "notifications/message",
								"params": M{"level": "info", "logger": "idpdbg", "data": fmt.Sprintf(format, a...)}})
						}
						if p.Arguments == nil {
							p.Arguments = M{}
						}
						res, err := runOp(ctx, op, p.Arguments, false, log)
						if err != nil {
							text := "Error: " + err.Error()
							if res != nil {
								b, _ := json.MarshalIndent(res, "", "  ")
								text += "\n\nPartial result:\n" + string(b)
							}
							reply(id, M{"content": []M{{"type": "text", "text": text}}, "isError": true})
							return
						}
						b, _ := json.MarshalIndent(res, "", "  ")
						reply(id, M{"content": []M{{"type": "text", "text": string(b)}}, "structuredContent": res, "isError": false})
					}(msg.ID)
				default:
					if len(msg.ID) > 0 {
						fail(msg.ID, -32601, "method not found: "+msg.Method)
					}
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
