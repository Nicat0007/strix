---
name: service_enumeration
description: "Testing non-standard-port and non-HTTP services found by naabu/nmap during black-box recon — alternate app instances on :8080/:8443/:8000/:3000, exposed data stores (Redis/Mongo/Elasticsearch/memcached/CouchDB/databases), admin/CI/ops panels (Jenkins/Grafana/Kibana/phpMyAdmin/RabbitMQ/Docker/Kubernetes), and dev/debug servers. This is the highest-yield, lowest-duplication black-box surface because most hunters only test the main site on 443. Loaded from reconnaissance/asset_discovery.md's Service & Port Fan-Out step whenever host_ports.json shows a non-80/443 port."
---

# Service enumeration — odd-port and non-HTTP services

`host_ports.json` (from `naabu`) lists open ports beyond 80/443. Each is a candidate
service to fingerprint and test. **Why this matters for ranking: these are rarely
duplicates.** The crowd tests the main web app on 443; the admin panel on 8443, the
staging build on 8080, the exposed Redis on 6379, the Jenkins on 8080 — those are
where a novel, high-severity, first-to-report finding lives.

## Step 1 — fingerprint every open port
```
nmap -sV -sC -Pn -p <ports> <host>          # version + default NSE scripts
echo "<host>:<port>" | httpx -td -tls-grab -sc -title -server -json   # is it HTTP? both schemes
```
Decide: **HTTP/HTTPS responder** → register as a new origin in `assets.jsonl`, run the
full web brain (`asset_discovery.md` application-layer recon + the executors). **Known
non-HTTP service** → the per-service playbook below. **Unknown** → `nmap` banner +
`nc`/`openssl s_client` manual banner grab, then classify.

## Alternate app instances on odd HTTP ports (do this first — biggest win)
A different port on the same host is often a **different or older build** of the app:
staging, UAT, admin console, a debug server, an internal API exposed by mistake.
- Diff it against the main site: different version banner, different auth, debug
  endpoints enabled, `/actuator`, `/swagger`, `/graphql`, `/.git`, directory listing,
  stack traces. A bug patched on prod (443) is frequently still live on the 8080 build
  — **and it is not a duplicate of the prod report** because it is a distinct origin.
- Staging/UAT builds routinely ship test backdoors, verbose errors, weaker auth,
  seeded/default credentials, and `GenerateFakeToken`-class test endpoints. Treat an
  odd-port instance as its own target with its own hypothesis worklist.

## Data stores (frequently unauthenticated by default — high severity, low dup)
- **Redis (6379, 6380):** `redis-cli -h <host> -p 6379 info` / `ping`. No-auth access =
  critical (read/write keys, often session stores, sometimes RCE via `CONFIG SET dir`
  + module/webshell — do NOT run destructive writes; prove read access to sensitive
  keys and stop). A requirepass prompt = authenticated, note and move on.
- **MongoDB (27017):** `mongosh --host <host> --eval "db.adminCommand('listDatabases')"`.
  No-auth list of databases with real data = critical data exposure.
- **Elasticsearch/OpenSearch (9200, 9300):** `GET /_cat/indices?v`, `GET /_search`.
  Open cluster = mass data exposure; also check Kibana (5601).
- **memcached (11211):** `stats`, `stats items` via `nc` — exposed cache, UDP-amp risk.
- **CouchDB (5984):** `GET /_all_dbs`, `/_utils` (Fauxton). **PostgreSQL (5432) /
  MySQL (3306) / MSSQL (1433) / Oracle (1521):** test default/weak creds ONLY if the
  program allows auth attempts and there is no bruteforce prohibition — otherwise
  report the exposure itself. **Cassandra (9042), RabbitMQ (5672/15672), Kafka (9092)**.
  Every exposed store: prove read of non-public data with ONE record, redact it, stop —
  never bulk-dump (program rules forbid accessing others' data at scale).

## Admin / CI / ops panels
- **Jenkins (8080):** `/script` (Groovy console = RCE if reachable), `/asynchPeople/`,
  unauthenticated job config, `/whoAmI/`. **Grafana (3000):** CVE-2021-43798 path
  traversal, default admin/admin, anonymous org access. **Kibana (5601)**, **phpMyAdmin**
  (default/weak creds, `/setup`), **Adminer**, **Portainer (9000)**, **RabbitMQ mgmt
  (15672)** (guest/guest), **Docker API (2375/2376)** (`GET /version`, `/containers/json`
  — open = host RCE), **Kubernetes API (6443/10250)** (`/api`, kubelet `/pods`),
  **Consul (8500)**, **etcd (2379)**, **Spring Boot Actuator** (`/actuator/env`,
  `/heapdump`), **SonarQube (9000)**.
- For each: default creds → `reconnaissance/asset_discovery.md`'s default-cred note and
  the gov_az priors if applicable; a reachable RCE/admin console is validated per
  `analysis/counterevidence.md` with a minimal non-destructive PoC (prove access, do not
  deploy/modify). Route any web-exposed panel through the normal executors too.

## Mail / DNS / other
- **SMTP (25/465/587):** open relay test (bounded), `VRFY`/`EXPN` user enum.
  **DNS (53):** zone transfer `dig AXFR @<host> <domain>`. **FTP (21):** anonymous login.
  **SNMP (161):** `snmpwalk -c public -v2c` default community. **SMB (445):** null
  session / exposed shares. **RDP/VNC (3389/5900):** exposed remote access (report
  exposure; no bruteforce).

## Discipline (same as every skill)
- A port being OPEN is a lead, not a finding. The finding is a **demonstrated** effect:
  unauthenticated read of real data, reachable admin/RCE, a default-cred login. Prove it
  per `analysis/counterevidence.md`; file via `create_vulnerability_report`.
- Respect program rules absolutely: no DoS, no bulk data extraction, no destructive
  writes, no bruteforce where prohibited, only in-scope hosts. On a bug-bounty program
  that bans automatic scanners, keep `nmap`/`nuclei` narrow and targeted (specific
  ports/templates), never a broad noisy sweep.
- Register every responding odd-port origin into the attack-surface inventory and
  `record_coverage` per service, so the report proves these were tested — and so an
  odd-port finding is filed as its own distinct origin, not folded into (and dup'd
  against) the main-site report.
