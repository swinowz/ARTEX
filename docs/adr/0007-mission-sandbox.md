# ADR-0007: Task execution containers

Status: accepted as an opt-in task execution increment (2026-11-26), issue #33. Full agent isolation remains open.

## Context
Workers currently obtain Bash from Norma v0.4.11 (`agent/worker.go`), while
Read/Write/Edit use server-side confined file tools (`agent/filetools.go`).
Replacing only Bash would leave inconsistent paths and file access. The existing
privilege-drop shim is process-wide and cannot select a task container safely.
The recording proxy listens on loopback; its address cannot be reused unchanged
inside a bridge-network container.

## Direction
Keep orchestration and interception in ARTEX. Add an operator-configured execution
backend, disabled by default, with a container per task and a shared work volume.
Do not change the process-wide Bash shim for container routing.

The opt-in `sandbox` package provides Docker CLI lifecycle primitives with an
injectable runner. Configuration requires an image pinned by digest, an explicit
network, and non-root identity. Containers do not receive the daemon socket or
inherited server environment; they drop capabilities and enable no-new-privileges,
a read-only root filesystem and resource limits. A task directory is mounted
at the same absolute path in the container so the existing confined file tools
can access its evidence. The server-resolved skill directory is mounted at its
absolute path in read-only mode so skill scripts remain callable. Removing a
container kills its processes and preserves
the task directory. Rootless mode requires a verified rootless daemon and uses
container UID 0, which maps to the unprivileged host user in this environment. Bridge selection is not a scope
firewall. The existing interception and scope review must remain above execution.

Images must provide `/bin/sh`, `/bin/bash`, `python3`, and `sleep infinity`.
The task directory must be writable by the mapped container UID. Container
commands run synchronously; timeout and cancellation kill their process group.
Other registered tools remain visible. An optional interactive shell tool
retains its existing executor path and is covered by the server's global
isolation status, not by this task-container boundary.

## Remaining work before full #33 completion
- Provide reproducible, digest-pinned tool images for network, AD, Wi-Fi and reverse profiles. The integration proof used a local Python image pinned by image ID.
- Reconcile containers left by a server crash. Current lifecycle creates once per task and removes on terminal outcome, deletion or clean shutdown using a separate cleanup context.
- Preserve richer Bash behavior if needed: background Bash is unavailable in this mode. Other tool names are not removed. The existing permission check is delegated to the original Bash tool. Confirm intercept behavior for every tool surface.
- Review any remaining host-side process surfaces and keep the degraded banner on a non-root development server.
- Audit server-side HTTP MCP, custom HTTP, platform and traffic tools as explicit mediated capabilities. They do not execute user code locally, but can act on server-side data and the network. Test all evidence ingestion paths.
- Proxy/CA connectivity from containers without exposing the server's credentials; the proof used direct lab network access and did not exercise recording proxy capture.
- Add concurrent worker and crash recovery tests, plus scope and interception regression in sandbox mode.

Wi-Fi hardware passthrough and privileged network operations need explicit profiles;
they are not provided by this initial non-root backend.

## Validation of increment 1
Unit and race tests cover configuration rejection, lifecycle arguments, shell
argument boundaries, invalid task IDs, Docker error propagation, and worker Bash
routing. A real Docker test covers workspace sharing, host key/socket absence,
timeout, cancellation without orphan process, and evidence retention. `go test ./...`
passed against the dedicated PostgreSQL test database. An ARTEX task against the
isolated local web lab completed with one goal met, two workers producing saved
HTTP proofs and facts, and the task container removed while proofs remained. This
validates the tested scenario only; it does not establish general isolation.

## GOAD Light validation (2026-11-26)
A local AD discovery image adds `ldapsearch` to a pinned Python base. A direct
read-only RootDSE request to the authorized lab DC returned `dnsHostName` and
`defaultNamingContext`. ARTEX task #2 used that image with Docker network `none`
and a temporary Unix-socket relay whose sole destination was the DC LDAP port.
The worker saved `ldap-rootdse.txt` in its mounted task directory and wrote one
fact and four assets. The task persisted `done` in PostgreSQL, the task container was absent after completion, and the LDAP proof files remained. The worker logs showed two finished intents writing one fact each; no finding was claimed.
This validates LDAP discovery, not AD attack paths, privilege escalation, or
general network scope enforcement.

## Worker tool boundary refinement
Sandbox mode preserves configured MCP, skill, WebFetch, web search and host
tools, including deferred MCP unlocking. Planner and worker Bash, task custom
`command` and Python `script` tools, and task MCP stdio servers now execute in
the task container. Main-agent and chat turns use separate disposable session
containers for those process paths, with a unique key per invocation. The skill
directory is available read-only. HTTP MCP,
custom HTTP, WebFetch, web search, platform and traffic tools retain their
existing server-side transports. Skill loading is a server-side read, while
scripts invoked through Bash execute in the container. The global isolation
warning must remain visible unless the independent executor-identity self-test
passes for the server process.

The same Bash boundary applies to the planner while the task is active. Its
configured MCP tools, WebFetch and web search remain available. Main-agent
turns remain usable after task completion because each turn owns a separate
session container. Chat turns use the same lifecycle. Cleanup follows MCP
client close and retains the persistent conversation workspace.

## Planner and worker end-to-end check
An unseeded ARTEX task #3 on the isolated local web lab exercised the planner's
normal dispatch path with sandbox mode enabled. The planner dispatched two
worker intents, each producing a fact. The task ended `done` with its only goal
`met`; both planner and worker evidence files remained after the task container
was removed. This check demonstrates the container Bash route supports this
web flow. It does not cover post-completion main-agent chat or custom/MCP tools.

## Capability-preserving task isolation check
A regression test proves the task's MCP stdio client can list and call a tool,
and that its Docker command targets the task container. Command and Python
custom-tool tests prove their processes use that container. A real rootless
Docker integration test uses a local image pinned by image ID: an MCP stdio
tool runs from a skill file mounted read-only, cannot see a secret file outside
the task and skill mounts, and returns a result; Python script and command
custom tools also return results from the same task container. This proves
these paths for this image and configuration, not every configured MCP or skill.
An image must contain the commands and dependencies its enabled MCPs and skills
require. There is no silent tool removal if an image lacks one: connecting that
MCP reports an error.

Unit tests also verify that main-agent and chat Bash calls use a separate
container per turn while preserving MCP augmentation and workspace files. A
real rootless Docker test exercises session MCP stdio and Python custom-tool
calls from a read-only skill mount, then removes the session container.
Background Bash remains unavailable in this mode. Interactive shell tools
are not in the SDK default set; if explicitly supplied, they remain visible
and retain the server's existing executor path.

The editor's ad hoc command and Python tool tests use their own disposable
session container and private workspace when the sandbox is configured. A
container creation error does not fall back to host execution. With sandboxing
disabled, the legacy server executor remains available. The workspace and
container are removed after each test, including after request cancellation.
With sandboxing configured, custom command/Python and MCP stdio calls also
fail closed if the agent run lacks a task or session sandbox identity.

The alternative server-container deployment keeps the server as container root
and drops Bash, custom script and MCP stdio subprocesses to the executor UID.
Rootless Docker tests of those three paths showed that an executor cannot read
a server-owned secret or `/proc/<server>/environ`; the startup isolation
self-test passed. A separate disposable PostgreSQL proof verified that the
server credential worked, a passwordless executor connection was rejected by
SCRAM, and the startup self-test passed against that database. A host development server running
as the same user as its subprocesses remains degraded even when the task
sandbox is enabled. The task sandbox alone must never change the global status
to `isolated`.

Proxied custom HTTP requests retain their proxy capability. The caller can
gate the requested name and redirects but cannot pin the proxy's actual
upstream IP: only the proxy sees that connection. A proxy-side dial gate tied
to task scope is needed for an IP guarantee; a further external upstream
proxy would reduce that guarantee again.

Custom HTTP no longer sends configured headers after an origin-changing
redirect, and rejects a cross-origin 307/308 when it would replay a configured
request body. Same-origin redirects and bodyless cross-origin redirects remain
available. HTTP MCP SSE line size is bounded, and endpoint discovery now honors
context cancellation.

WebFetch and WebSearch remain server-mediated tools. WebFetch gates requested
URLs and redirect hops under task review; with an upstream proxy, only the
requested name is visible to the client gate. WebSearch uses fixed provider
endpoints (except an operator-configured DeepSeek endpoint), but the current
Norma API offers no redirect hook for search. Its default redirect handling
could forward nonstandard provider credential headers or replay a POST body
across origins on a 307/308. The tools remain enabled; adding a same-origin
redirect hook in Norma and wiring it through ARTEX is outstanding. Traffic
agent search/get tools read the shared capture store without a task filter.
