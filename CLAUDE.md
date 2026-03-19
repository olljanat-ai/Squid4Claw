# CLAUDE.md - Firewall4AI

## Project Overview
Firewall4AI is a transparent firewall/proxy that controls AI agent internet access from isolated VM environments. It sits between agent VMs and the internet, intercepting all HTTP/HTTPS traffic transparently via iptables without requiring proxy configuration on agent VMs.

## Architecture
- **Single Go binary**, zero external dependencies (stdlib only)
- **Three listeners**: HTTP proxy (:8080), transparent TLS (:8443), admin UI (:443)
- **iptables REDIRECT**: Port 80 -> :8080, port 443 -> :8443 for transparent interception
- **TLS MITM**: Auto-generated CA signs per-host certificates; agents must trust the CA
- **Default-deny**: All connections blocked until admin approves
- **Three-level approval**: Global (all agents/VMs) -> VM-specific (by source IP) -> Skill-specific (by skill token, for getting more permissions)
- **VM appliance**: Alpine Linux with two NICs (eth0=internet, eth1=agent network 10.255.255.0/24)
- **Permanent DHCP leases**: Agents get stable IPs for reliable VM-specific approvals

## Key Directories
```
cmd/firewall4ai/     - Application entry point (main.go)
internal/
  api/               - REST API handlers for admin UI
  approval/          - Default-deny approval system with three levels (global/VM/skill)
  auth/              - Skill tokens (GUID format) and authentication
  certgen/           - CA and per-host TLS certificate generation
  config/            - JSON configuration loading
  credentials/       - Credential injection (header/bearer/basic_auth/query_param)
  logging/           - In-memory circular buffer request logger
  proxy/             - HTTP/HTTPS proxy with transparent + explicit modes
  store/             - Generic JSON file persistence
web/static/          - Admin UI (vanilla HTML/JS/CSS, embedded at build time)
vm/                  - VM appliance build scripts and rootfs overlay
```

## Building and Testing
```bash
make build           # Build the binary
make test            # Run all tests
make lint            # Run go vet
go test ./...        # Run tests directly
```

## Key Design Decisions
- **Transparent proxy mode**: iptables REDIRECT intercepts agent traffic; no proxy config needed on agent VMs. Agents can optionally still use explicit proxy mode.
- **Three-level approvals**: Approvals are checked broadest-first: (1) Global (`skill_id=""`, `source_ip=""`) applies to all agents on all VMs. (2) VM-specific (`skill_id=""`, `source_ip` set) applies to all agents on that VM. (3) Skill-specific (`skill_id` set) gives additional permissions beyond global/VM. Broader approvals cascade to notify narrower waiters.
- **Anonymous access**: Agents can make requests without skill tokens. These go through the global/VM approval system. Invalid tokens are rejected; missing tokens are anonymous.
- **GUID tokens**: Skill tokens use UUID v4 format (e.g., `a1b2c3d4-e5f6-4789-abcd-ef0123456789`). Skill IDs can be user-provided or auto-generated GUIDs.
- **State persistence**: All state (skills, approvals, credentials) stored in a single `state.json` file, loaded at startup, saved on mutations and shutdown.

## Common Patterns
- **Thread safety**: All managers use `sync.RWMutex`. Read operations use `RLock`, write operations use `Lock`.
- **Approval flow**: `Check(host, skillID, sourceIP)` registers a pending entry, `WaitForDecision()` blocks until admin decides or timeout, `Decide()` notifies all waiters via channels with cascading (global notifies VM/skill waiters).
- **Source IP extraction**: `extractSourceIP()` in proxy.go strips the port from `RemoteAddr` to get the VM's IP for approval lookups.
- **Test helpers**: `setupProxy(t)` creates a test proxy with 50ms approval timeout. `setupProxyWithCA(t)` adds a CA for MITM tests.
- **No external dependencies**: Everything uses Go stdlib. Don't add third-party packages.

## When Making Changes
- Run `go test ./...` after changes; all tests should pass
- The proxy handles three modes: explicit HTTP proxy, explicit CONNECT/MITM, and transparent TLS interception
- The `checkApproval()` function checks: pre-approved hosts -> global approvals -> VM-specific approvals -> skill-specific approvals -> register pending and wait
- All approval methods take three identifiers: `host`, `skillID`, `sourceIP`
- The admin UI is vanilla JS with no build step; changes to `web/static/` are embedded at compile time via `go:embed`
- VM networking config is in `vm/rootfs/` - iptables rules, dnsmasq, network interfaces
