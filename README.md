# Squid4Claw

Transparent HTTP/HTTPS proxy for controlling where AI agents can connect from isolated environments.

Connections are **denied by default** and require admin approval before first use. AI agents authenticate with skill-specific tokens that load per-skill rulesets. The proxy can inject credentials into outgoing requests so agents never need to know secrets directly.

## Features

- **Default-deny proxy** - All outbound connections require explicit admin approval
- **Skill-based authentication** - Each AI agent skill gets its own token and ruleset
- **Pre-approved hosts** - Configure allowed hosts per skill to skip manual approval
- **Credential injection** - Inject API keys, bearer tokens, basic auth, or query parameters into outgoing requests on behalf of agents
- **Admin UI** - Modern web interface for managing approvals, skills, credentials, and viewing logs
- **Real-time logging** - All proxy requests are logged and visible in the admin UI with polling updates

## Architecture

```
AI Agent --[HTTP/HTTPS]--> Proxy (:8080) --[approved]--> Target Service
                             |
                         Admin UI (:8443) <-- Human Admin
```

The proxy runs two servers:
- **Proxy server** (default `:8080`) - Handles agent HTTP/HTTPS requests with CONNECT tunnel support
- **Admin server** (default `:8443`) - Serves the admin UI and REST API

State is persisted to a JSON file in the data directory.

## Quick Start

```bash
# Build
make build

# Run with defaults
./bin/squid4claw

# Run with config file
./bin/squid4claw -config config.json
```

## Configuration

Create a `config.json` file (all fields optional):

```json
{
  "listen_addr": ":8080",
  "admin_addr": ":8443",
  "data_dir": "./data",
  "tls_cert_file": "",
  "tls_key_file": "",
  "max_log_entries": 10000
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `listen_addr` | `:8080` | Proxy server listen address |
| `admin_addr` | `:8443` | Admin UI/API listen address |
| `data_dir` | `./data` | Directory for persistent state |
| `tls_cert_file` | (empty) | TLS certificate for admin server |
| `tls_key_file` | (empty) | TLS key for admin server |
| `max_log_entries` | `10000` | Maximum log entries kept in memory |

## Usage

### 1. Create a Skill

Via the admin UI or API:

```bash
curl -X POST http://localhost:8443/api/skills \
  -H 'Content-Type: application/json' \
  -d '{"id": "web-scraper", "name": "Web Scraper Agent", "allowed_hosts": ["api.example.com"]}'
```

This returns a token that the AI agent must use for authentication.

### 2. Configure the AI Agent

Set the agent's HTTP proxy to `http://localhost:8080` and include the token header in all requests:

```
X-Squid4Claw-Token: <skill-token>
```

### 3. Approve Connections

When an agent tries to connect to a host not in its pre-approved list, the request blocks and appears in the admin UI as pending. An admin can approve or deny it.

### 4. Credential Injection (Optional)

Configure credentials in the admin UI to automatically inject authentication into outgoing requests. Supported injection types:

- **Custom Header** - Set any header (e.g., `X-API-Key`)
- **Bearer Token** - Sets `Authorization: Bearer <token>`
- **Basic Auth** - Sets HTTP basic authentication
- **Query Parameter** - Appends a query parameter

Credentials can be scoped to specific hosts (with wildcard support like `*.example.com`) and specific skills.

## API Reference

### Skills
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/skills` | List all skills |
| `POST` | `/api/skills` | Create a skill |
| `PUT` | `/api/skills` | Update a skill |
| `DELETE` | `/api/skills?id=<id>` | Delete a skill |

### Approvals
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/approvals` | List all approvals |
| `GET` | `/api/approvals/pending` | List pending approvals |
| `POST` | `/api/approvals/decide` | Approve or deny a host |

### Credentials
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/credentials` | List credentials (secrets masked) |
| `POST` | `/api/credentials` | Add a credential |
| `PUT` | `/api/credentials` | Update a credential |
| `DELETE` | `/api/credentials?id=<id>` | Delete a credential |

### Logs
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/logs?limit=100` | Get recent log entries |
| `GET` | `/api/logs?after=<id>` | Get log entries after a given ID |
| `GET` | `/api/logs/stats` | Get log statistics |

### Health
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Health check |

## Development

```bash
# Run tests
make test

# Lint
make lint

# Build
make build

# Build, test, and lint
make all
```

## Release

Releases are automated via GitHub Actions. To create a release:

```bash
git tag v1.0.0
git push origin v1.0.0
```

This builds a Linux amd64 binary and creates a GitHub release with auto-generated release notes.

## License

See [LICENSE](LICENSE) file.
