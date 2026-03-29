# Paperclip Integration Investigation

## Context

Investigation into whether [Paperclip](https://github.com/paperclipai/paperclip) — an open-source AI agent orchestration platform — is a good fit for integration with Firewall4AI.

## Assessment: Complementary, Not Overlapping

| Concern | Firewall4AI | Paperclip |
|---------|-------------|-----------|
| **Layer** | Network (L4/L7 proxy) | Application (orchestration) |
| **Controls** | Which hosts/packages agents can access | What tasks agents work on, budgets, permissions |
| **Enforcement** | iptables + transparent proxy | Agent heartbeats + ticket system |
| **Approval** | Per-host, per-package, per-image | Per-task, per-budget, per-agent-hire |
| **Tech** | Go, single binary, VM appliance | Node.js/TypeScript, PostgreSQL, React UI |

Firewall4AI provides the **network perimeter security** that Paperclip lacks. Paperclip provides the **agent coordination and governance** that Firewall4AI doesn't handle.

## Recommended Integration: Paperclip Plugin

Paperclip has a plugin system (Node.js child processes via JSON-RPC 2.0 over stdin/stdout). A `firewall4ai` plugin would:

1. **Sync skills/permissions**: When Paperclip creates/assigns an agent, the plugin auto-creates a corresponding Firewall4AI skill with a token.
2. **Auto-approve based on task context**: Pre-approve relevant hosts in Firewall4AI for that agent's skill token.
3. **Feed network logs into Paperclip audit trail**: Poll Firewall4AI's `/api/logs` endpoint.
4. **Policy-aware task assignment**: Query `/v1/policy` so agents know their network constraints.
5. **Budget correlation**: Correlate Paperclip's token budget with Firewall4AI's request logs.

### Data Flow

```
Paperclip (orchestration)
  |
  +-- Creates agent + assigns task
  |     |
  |     +-- Plugin: POST /api/skills -> creates Firewall4AI skill token
  |                 POST /api/approvals/decide -> pre-approves needed hosts
  |
  +-- Agent VM runs task
  |     |
  |     +-- HTTP requests -> Firewall4AI proxy (token in X-Firewall4AI-Token)
  |                          -> approved/denied based on skill-level rules
  |
  +-- Monitoring
        |
        +-- Plugin: GET /api/logs -> ingest network activity into audit trail
                    GET /v1/policy -> show network constraints in dashboard
```

### Deployment Topology

```
+-----------------------------+
|  Management Network         |
|  +----------+ +-----------+ |
|  | Paperclip| |Firewall4AI| |
|  | (Node.js)| |(Go, eth0) | |
|  | :3100    | |Admin :443 | |
|  +----------+ +-----------+ |
+-----------------------------+
                | eth1 (10.255.255.0/24)
+---------------+-------------+
|  Agent Network|             |
|  +--------+ +--------+     |
|  |Agent VM| |Agent VM| ... |
|  +--------+ +--------+     |
+-----------------------------+
```

## Challenges

- **Different tech stacks**: Plugin would be Node.js calling Firewall4AI's REST API
- **Deployment complexity**: Two separate systems to deploy and maintain
- **Concept mapping**: Paperclip "agents/permissions" don't map 1:1 to Firewall4AI "skills/approvals"
- **Paperclip maturity**: Relatively new project; API stability uncertain

## Recommendation

**Worth investigating further, but not a priority.**

**Pros:**
- Genuinely complementary
- Clean integration via REST APIs
- Paperclip's plugin system makes it non-invasive

**Cons:**
- Paperclip is early-stage; API may change
- Firewall4AI works well standalone
- Moderate integration effort

**Suggested next step:** Start with a lightweight proof-of-concept plugin that creates Firewall4AI skills when Paperclip agents are provisioned, syncs approvals, and shows network logs in Paperclip's dashboard.

## Implementation Steps (if proceeding)

1. Create a Paperclip plugin (`firewall4ai-plugin/`) in Node.js/TypeScript
2. Implement skill sync: Paperclip agent creation -> Firewall4AI skill creation
3. Implement approval bridge: Paperclip permission grants -> Firewall4AI host approvals
4. Implement log ingestion: Firewall4AI logs -> Paperclip audit trail
5. Add Firewall4AI admin API authentication for external access from Paperclip
