---
name: deep
description: Exhaustive security assessment with maximum coverage, depth, and vulnerability chaining
---

# Deep Testing Mode

Exhaustive security assessment. Maximum coverage, maximum depth. Finding what others miss is the goal.

## Approach

Thorough understanding before exploitation. Test every parameter, every endpoint, every edge case. Chain findings for maximum impact.

## Phase 1: Exhaustive Reconnaissance

**Whitebox (source available)**
- Map every file, module, and code path in the repository
- Start with broad source-aware triage (`semgrep`, `ast-grep`, `gitleaks`, `trufflehog`, `trivy fs`) and use outputs to drive deep review
- Execute at least one structural AST pass (`sg` and/or Tree-sitter) per repository and store artifacts for reuse
- Keep AST artifacts bounded and query-driven (target relevant paths/sinks first; avoid whole-repo generic function dumps)
- Use syntax-aware parsing (Tree-sitter tooling) to improve symbol, route, and sink extraction quality
- Trace all entry points from HTTP handlers to database queries
- Document all authentication mechanisms and implementations
- Map authorization checks and access control model
- Identify all external service integrations and API calls
- Analyze configuration for secrets and misconfigurations
- Review database schemas and data relationships
- Map background jobs, cron tasks, async processing
- Identify all serialization/deserialization points
- Review file handling: upload, download, processing
- Understand the deployment model and infrastructure assumptions
- Check all dependency versions and repository risks against CVE/misconfiguration data
- For quick CVE lookups on a named product/version, use `vulnx search <query>`
  (ProjectDiscovery's CVE database) before falling back to web_search

**Blackbox (no source)**
- Exhaustive subdomain enumeration with multiple sources and tools
- Full port scanning across all services
- Complete content discovery with multiple wordlists
- Technology fingerprinting on all assets
- API discovery via docs, JavaScript analysis, fuzzing
- Identify all parameters including hidden and rarely-used ones
- Map all user roles with different account types
- Document rate limiting, WAF rules, security controls
- Document complete application architecture as understood from outside

## Phase 2: Business Logic Deep Dive

Create a complete storyboard of the application:

- **User flows** - document every step of every workflow
- **State machines** - map all transitions (Created → Paid → Shipped → Delivered)
- **Trust boundaries** - identify where privilege changes hands
- **Invariants** - what rules should the application always enforce
- **Implicit assumptions** - what does the code assume that might be violated
- **Multi-step attack surfaces** - where can normal functionality be abused
- **Third-party integrations** - map all external service dependencies

Use the application extensively as every user type to understand the full data lifecycle.

## Phase 3: Comprehensive Attack Surface Testing

Test every input vector with every applicable technique.

**Input Handling**
- Multiple injection types: SQL, NoSQL, LDAP, XPath, command, template
- Encoding bypasses: double encoding, unicode, null bytes
- Boundary conditions and type confusion
- Large payloads and buffer-related issues

**Authentication & Session**
- Exhaustive brute force protection testing
- Session fixation, hijacking, prediction
- JWT/token manipulation
- OAuth flow abuse scenarios
- Password reset vulnerabilities: token leakage, reuse, timing
- MFA bypass techniques
- Account enumeration through all channels

**Access Control**
- Test every endpoint for horizontal and vertical access control
- Parameter tampering on all object references
- Forced browsing to all discovered resources
- HTTP method tampering (GET vs POST vs PUT vs DELETE)
- Access control after session state changes (logout, role change)

**File Operations**
- Exhaustive file upload bypass: extension, content-type, magic bytes
- Path traversal on all file parameters
- SSRF through file inclusion
- XXE through all XML parsing points

**Business Logic**
- Race conditions on all state-changing operations
- Workflow bypass on every multi-step process
- Price/quantity manipulation in transactions
- Parallel execution attacks
- TOCTOU (time-of-check to time-of-use) vulnerabilities

**Advanced Techniques**
- HTTP request smuggling (multiple proxies/servers)
- Cache poisoning and cache deception
- Subdomain takeover
- Prototype pollution (JavaScript applications)
- CORS misconfiguration exploitation
- WebSocket security testing
- GraphQL-specific attacks (introspection, batching, nested queries)
- LLM/RAG/agent features: load `llm_applications` for OWASP 2026 LLM01-LLM10 coverage and `llm_prompt_injection` for deep injection testing

## Phase 4: Vulnerability Chaining

Individual bugs are starting points. Chain them for maximum impact:

- Combine information disclosure with access control bypass
- Chain SSRF to reach internal services
- Use low-severity findings to enable high-impact attacks
- Build multi-step attack paths that automated tools miss
- Cross component boundaries: user → admin, external → internal, read → write, single-tenant → cross-tenant

**Chaining Principles**
- Treat every finding as a pivot point: ask "what does this unlock next?"
- Continue until reaching maximum privilege / maximum data exposure / maximum control
- Prefer end-to-end exploit paths over isolated bugs: initial foothold → pivot → privilege gain → sensitive action/data
- Validate chains by executing the full sequence (proxy + browser for workflows, python for automation)
- When a pivot is found, spawn focused agents to continue the chain in the next component

## Phase 5: Persistent Testing

When initial attempts fail:

- Research technology-specific bypasses
- Try alternative exploitation techniques
- Test edge cases and unusual functionality
- Test with different client contexts
- Revisit areas with new information from other findings
- Consider timing-based and blind exploitation
- Look for logic flaws that require deep application understanding

## Phase 6: Comprehensive Reporting

- Document every confirmed vulnerability with full details
- Include all severity levels—low findings may enable chains
- Complete reproduction steps and working PoC
- Remediation recommendations with specific guidance
- Note areas requiring additional review beyond current scope

## Agent Strategy

Depth in deep mode comes from **exhaustive coverage**, not from a large agent
count. The durable coverage matrix (`plan_coverage` → `next_coverage_task` →
`assess_coverage`, driven per `coordination/root_agent.md`) already guarantees
every family is assessed on every surface — so thoroughness is enforced by the
matrix, and the agents only have to *work* the cells. Spawning one agent per
vulnerability class on top of that re-reads the same recon, re-derives the same
map, and multiplies cost for no extra coverage.

Partition the opposite way — **by entry-point slice, not by vulnerability
class** (`root_agent.md`'s "Delegate by Entry-Point Slice" / "Consolidate
Related Classes"):

- One agent owns a cohesive slice of related endpoints/a component and tests
  **every** applicable class on it — it reads each endpoint's purpose and
  chooses the attack. Do not split that slice into a SQLi agent + an XSS agent
  + an auth agent.
- Every subagent reads the shared inventory first (`query_attack_surface`, the
  threat model, `/workspace/recon/*`, the white-box `entry_points.md`) and does
  **not** re-crawl or re-derive the map — re-derivation is the dominant waste a
  deep run bleeds on.
- Reserve a *dedicated* agent only for genuinely cross-cutting concerns that
  don't belong to one slice: the auth/session model, a single sprawling API,
  infrastructure/subdomain-takeover, business-logic QA, and chain validation.
- **Bound parallelism** (`root_agent.md`'s "Bound Parallelism"): scale by
  splitting slices across same-mandate agents, never by multiplying
  vuln-class agents. Cap concurrent spawns to what the run's budget supports —
  a handful at a time, reaped before the next wave — not an unbounded swarm.

Exhaustiveness is non-negotiable; the *route to it* is the matrix plus
well-scoped slice agents, not a one-agent-per-angle swarm.

## Mindset

Relentless. Creative. Patient. Thorough. Persistent.

This is about finding what others miss. Test every parameter, every endpoint, every edge case. If one approach fails, try ten more. Understand how components interact to find systemic issues.
