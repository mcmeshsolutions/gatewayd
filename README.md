# gatewayd

**`gatewayd`** is the high-performance Rust coordination daemon, content-addressed storage (CAS) engine, lease/failover authority, and outbound TCP/UDP relay for [mcmesh](https://github.com/mcmeshsolutions).

It allows modded Minecraft worlds to stay online 24/7 across peer machines without port forwarding or expensive dedicated game servers. Whoever is online and has the strongest hardware hosts the world from their PC; when they leave or lose power, `gatewayd` elects the next host from a hash-chained revision manifest and seamlessly hands over connected players.

---

## Core Capabilities

- **Content-Addressed Storage (CAS) & Hash-Chained Revisions:** Every world save is deduplicated at the chunk/file level using Zstandard-compressed SHA-256 blobs (`cas/`) and verified with cryptographic Ed25519 host signatures and hash chains.
- **Deterministic Lease & Failover Election:** Tracks active hosts with epoch-fenced leases, hardware scoring, battery/UPS watchdogs, and automatic standby promotion.
- **Outbound TCP/UDP Relay & P2P Offload:** Relays Minecraft traffic (`:25565`) and Simple Voice Chat UDP (`:24454`) through outbound host tunnels when direct STUN/Hole-Punching P2P is unavailable.
- **Zero-Downtime Hot Reload (`SO_REUSEPORT` & Virtual Limbo):** Supports rolling binary upgrades without dropping active players by queuing in-flight Minecraft packets in Virtual Limbo during handoff.
- **Automated S3 / Cloudflare R2 Disaster Replication:** Asynchronous background sync of hot SQLite WAL snapshots (`VACUUM INTO`) and immutable CAS blobs to any S3-compatible object store with 1-command fresh disaster restore.
- **Multi-Tenant World Quotas & Self-Service Tokens:** Per-world storage limits, guest slot caps, retention pruning, and scoped `wk_...` World Owner API tokens.
- **Built-in Web Panel & Live Pulse Telemetry:** Embedded zero-dependency web dashboard (`/panel`, `/setup`, `/view/:id`, `/isomap/:id`, `/timeline/:id`, `/quests/:id`, `/contraption`) and Prometheus metrics (`/metrics`).

---

## Quickstart

### 1. Build from Source

```bash
cargo build --release
```

### 2. Initialize Storage & Create a World

```bash
./target/release/gatewayd init
./target/release/gatewayd create-world survival "Community Survival" 1.21.1 neoforge
```

### 3. Start the Gateway Server

```bash
MCMESH_ADDR=0.0.0.0:8080 \
MCMESH_RELAY=all \
MCMESH_PUBLIC_ADDR=0.0.0.0:25565 \
./target/release/gatewayd serve
```

Open `http://localhost:8080/setup` in your browser for the first-time setup wizard, or `http://localhost:8080/panel` for the operator and world owner dashboard.

---

## CLI Reference

```text
gatewayd serve                                  Start HTTP API, web panel, and relay listeners
gatewayd init                                   Initialize SQLite database and CAS directory
gatewayd create-world <id> <name> <mc> <loader> Create a new shared world
gatewayd add-member <world> <uuid> <name> <dev> <ADMIN|HOST_ELIGIBLE|CLIENT_ONLY> <token>
gatewayd grant <world> <name> <role>            Update a member's role
gatewayd status                                 Print live worlds, leases, and storage summary
gatewayd revisions <world>                      List revision history for a world
gatewayd diff <rev_a> <rev_b> [<limit>]         Compare chunks and files between two revisions
gatewayd revert <world> <revision>              Roll a world head back to a prior revision
gatewayd scrub                                  Verify SHA-256 integrity of all CAS blobs and chains
gatewayd recover <world> [--apply]              Locate newest intact revision and heal damaged head
gatewayd backup <dest_dir>                      Incremental hot backup of DB and CAS blobs
gatewayd s3 sync                                Trigger immediate S3/R2 replication sync
gatewayd s3 status                              Inspect S3 replication state and latest snapshot
gatewayd s3 test                                Test S3 bucket credentials and round-trip latency
gatewayd s3 restore <target_dir> [<snapshot>]   1-command fresh disaster restore from S3/R2
gatewayd reload [<grace_period_s>]              Engage Virtual Limbo for zero-downtime hot reload
gatewayd set-limit <user|world> <id|*> ...      Configure storage, guest, and retention quotas
gatewayd set-admin <name> <admin|user>          Grant or revoke gateway operator status
gatewayd doctor                                 Run diagnostic self-checks on configuration and DB
```

---

## Environment Configuration

| Variable | Default | Description |
|---|---|---|
| `MCMESH_DB` | `mcmesh.db` | Path to SQLite database file |
| `MCMESH_CAS` | `./cas` | Path to Content-Addressed Storage directory |
| `MCMESH_ADDR` | `127.0.0.1:8080` | HTTP API and Web UI bind address |
| `MCMESH_RELAY` | unset (`all` for multi-world) | Set to `all` to relay all worlds on shared ports |
| `MCMESH_RELAY_ADDR` | `127.0.0.1:9000` | Outbound host agent tunnel bind address |
| `MCMESH_PUBLIC_ADDR` | `0.0.0.0:25565` | Public Minecraft guest TCP bind address |
| `MCMESH_VOICE_ADDR` | `0.0.0.0:24454` | Simple Voice Chat UDP bind address |
| `MCMESH_BLOBSTREAM_ADDR` | `0.0.0.0:9100` | Dedicated binary CAS blob streaming port |
| `MCMESH_STRICT_DATA` | `0` | If `1`, refuses to start if DB or CAS directory is missing |
| `MCMESH_TRUST_PROXY` | `0` | If `1`, extracts client IP from `X-Forwarded-For` / `CF-Connecting-IP` |
| `MCMESH_METRICS_TOKEN` | unset | Enables `GET /metrics` (Prometheus) behind bearer token |
| `MCMESH_S3_BUCKET` | unset | Enables automated S3/R2 off-site disaster replication |
| `MCMESH_S3_ENDPOINT` | `https://s3.amazonaws.com` | S3-compatible endpoint URL (Cloudflare R2, MinIO, AWS) |
| `MCMESH_S3_REGION` | `us-east-1` | S3 bucket region (`auto` for Cloudflare R2) |
| `MCMESH_S3_ACCESS_KEY` | unset | S3 access key ID (or `AWS_ACCESS_KEY_ID`) |
| `MCMESH_S3_SECRET_KEY` | unset | S3 secret access key (or `AWS_SECRET_ACCESS_KEY`) |
| `MCMESH_S3_PREFIX` | `""` | Optional object key prefix inside bucket |
| `MCMESH_S3_SYNC_INTERVAL_S` | `300` | Background S3 sync interval in seconds |

---

## Testing

Run the full unit and integration test suite:

```bash
cargo test
```

 All API routes are documented in the OpenAPI 3.0 specification (`openapi.json`) and verified against the router in integration tests.
