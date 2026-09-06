# Shadow6 Control Center

See [privacy across interfaces](../docs/privacy-interfaces.md) for the shared
`privacy.report` and `system.guide` methods and JSONL's read-only default.

`shadow6-control` is the versioned one-stop CLI/API and tool server for feature configuration,
init rendering, Core/topology/policy/plugin validation, signed plugin inventory,
Crosed feature inspection, typed Slots, security/infrastructure assistants, and signed fixed
runbooks. It never accepts an arbitrary command.

Discover the complete machine-readable surface:

```sh
shadow6-control schema
shadow6-control status --root /path/to/Shadow6
shadow6-control call init.render --params '{"system":"procd","name":"shadow6","binary":"/usr/bin/shadow6-go","config":"/etc/shadow6/core.json"}'
```

GUI clients can use newline-delimited JSON over stdin/stdout:

```json
{"id":1,"method":"system.schema","params":{}}
```

Web UI backends can use the authenticated loopback API. The token file must be
owner-controlled mode `0600` and contain at least 32 bytes:

```sh
shadow6-control serve --token-file /etc/shadow6/control.token
```

Endpoints are `GET /v1/schema`, `GET /v1/status`, and `POST /v1/rpc`. HTTP is
loopback-only. Send RPC bodies as uncompressed UTF-8 JSON with
`Content-Type: application/json`. The server rejects ambiguous authentication,
unexpected Host values and cross-origin browser requests. Request bodies,
connections and concurrency are bounded. State-changing methods are rejected
unless `--allow-mutations` is explicitly set. A reverse proxy or remote listener
is outside this tool's trust boundary.

```sh
curl --fail --header "Authorization: Bearer $(< /etc/shadow6/control.token)" \
  --header 'Content-Type: application/json' \
  --data '{"method":"system.status","params":{}}' \
  http://127.0.0.1:9466/v1/rpc
```

中文说明见 [README.zh-CN.md](README.zh-CN.md)。

## MCP for Claude and Cursor

The MCP server uses bounded JSON-RPC over stdio and exposes every finite Control
Center method, stateless component operation, and bounded orchestrator command:

```json
{
  "mcpServers": {
    "shadow6": {
      "command": "/usr/local/bin/shadow6-control",
      "args": ["mcp"]
    }
  }
}
```

The same command/arguments shape can be used in Claude Desktop and Cursor MCP
configuration. Read-only tools are enabled by default. File creation, packet
sending, topology application, Slot invocation and signed runbook actions are
returned as denied tool results unless the operator deliberately adds
`--allow-mutations` to the server arguments.

Interactive or perpetual orchestrator UI commands are represented by bounded
equivalents: `dashboard` becomes a snapshot, `mtd-daemon` becomes one rotation
that an external service manager may schedule, and `rpc-server` becomes one ACL
decision because nesting an unbounded TUI/daemon/listener inside a tool call
would break protocol framing and resource bounds. `orchestrator.commands`
reports the complete mapping.

## LSP and OpenAI function tools

`shadow6-control lsp` is an LSP 3.17 stdio server. It advertises all tools as
`workspace/executeCommand` commands and also answers the custom read-only
`shadow6/tools` request. An execute-command call accepts zero arguments or one
JSON object. Mutations have the same explicit `--allow-mutations` gate as MCP.

`shadow6-control openai-tools` prints Responses API function definitions. Feed
the model's `function_call` items, one JSON object per line, to
`shadow6-control openai-rpc`; each line produces a matching
`function_call_output`. The adapter parses the `arguments` JSON string, rejects
unknown tool parameters in the shared dispatcher, bounds input/output, and does
not make a network request to OpenAI itself.

Protocol references: [MCP tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools),
[LSP 3.17](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/),
and [OpenAI function calling](https://developers.openai.com/api/docs/guides/function-calling).
