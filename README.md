<div align="center">

# gatewayd

**High-performance Rust coordination daemon, content-addressed world store, and P2P relay for mcmesh.**

[![CI](https://github.com/mcmeshsolutions/gatewayd/actions/workflows/ci.yml/badge.svg)](https://github.com/mcmeshsolutions/gatewayd/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg?logo=rust)](https://www.rust-lang.org)
[![SQLite](https://img.shields.io/badge/sqlite-bundled-003B57.svg?logo=sqlite)](https://sqlite.org)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.1.0-6BA539.svg?logo=openapiinitiative)](https://github.com/mcmeshsolutions/docs/blob/main/openapi.json)
[![GitHub last commit](https://img.shields.io/github/last-commit/mcmeshsolutions/gatewayd)](https://github.com/mcmeshsolutions/gatewayd/commits/main)

[Quickstart](#quickstart) | [Architecture](#architecture) | [CLI Reference](#cli-reference) | [Configuration](#environment-configuration) | [Testing](#testing)

</div>

---

## Overview

`gatewayd` is the central authority and relay plane for [mcmesh](https://github.com/mcmeshsolutions). It keeps modded Minecraft worlds online 24/7 across peer machines without port forwarding or dedicated game servers:

- **World state lives on the gateway** as deduplicated, Zstandard-compressed SHA-256 blobs (`cas/`) and hash-chained revision manifests signed with Ed25519 host keys.
- **Whoever is online with the strongest hardware hosts** under an epoch-fenced lease. When they log off or lose power, `gatewayd` promotes the next eligible host from the latest verified revision.
- **Guests connect to one stable address.** When direct P2P hole-punching is unavailable, `gatewayd` relays Minecraft TCP (`:25565`) and Simple Voice Chat UDP (`:24454`) traffic through an outbound host tunnel.

## Architecture

```mermaid
flowchart LR
    Guest["Minecraft Guests (:25565 / :24454 UDP)"] <-->|Relayed TCP/UDP| GW["gatewayd"]
    Host["Active Host (mcmesh mod)"] <-->|Outbound Tunnel (:9000) & CAS (:9100)| GW
    Standby["Standby Peer"] -.->|Heartbeat & Lease Watch| GW
    GW -->|WAL + Blobs| DB[("SQLite + CAS Store")]
    GW -.->|Async Replication| S3[("S3 / R2 / MinIO")]
    Browser["Admin & Players"] -->|HTTPS / SSE| GW
```

## Core Capabilities

- **Content-Addressed Storage (CAS) & Hash Chains:** Chunk and auxiliary mod files are deduplicated via Zstd-compressed SHA-256 blobs, verified by Ed25519 host signatures and tamper-evident parent hash chains.
- **Deterministic Lease & Failover Election:** Epoch-fenced host leases with hardware scoring, battery/UPS watchdogs, sanity gates that reject destructive commits, and automatic standby promotion.
- **Zero-Downtime Hot Reload (`SO_REUSEPORT` & Virtual Limbo):** Supports rolling binary upgrades without dropping active players by holding in-flight Minecraft packets in Virtual Limbo during handoff.
- **S3 / Cloudflare R2 / MinIO Replication:** Background sync of hot SQLite snapshots (`VACUUM INTO`) and immutable CAS blobs with 1-command disaster restore (`gatewayd s3 restore`).
- **Multi-Tenant Quotas & Homelab SSO:** Per-world storage and guest caps, scoped `wk_...` world owner tokens, Forward-Auth headers, and OIDC login support.
- **Embedded Web Panel & Telemetry:** Zero-build dashboard (`/panel`, `/setup`, `/view/:id`, `/isomap/:id`, `/timeline/:id`, `/quests/:id`, `/contraption`), ZFS milestone snapshots, and Prometheus metrics (`/metrics`).

## Quickstart

### 1. Build from Source

Requires Rust 1.75+ (2021 edition). SQLite is bundled (`rusqlite` `bundled` feature).

```bash
cargo build --release
```

### 2. Initialize Storage & Create a World

```bash
./target/release/gatewayd init
./target/release/gatewayd create-world survival "Community Survival" 1.21.1 neoforge
```

### 3. Start the Gateway

```bash
MCMESH_ADDR=0.0.0.0:8080 \
MCMESH_RELAY=all \
MCMESH_PUBLIC_ADDR=0.0.0.0:25565 \
./target/release/gatewayd serve
```

Open `http://localhost:8080/setup` for the first-time setup wizard, or `http://localhost:8080/panel` for the operator dashboard. For production Docker Compose, Caddy TLS, and systemd units, see [mcmeshsolutions/deploy](https://github.com/mcmeshsolutions/deploy).

## CLI Reference

| Command | Description |
|---|---|
| `gatewayd serve` | Start HTTP API, embedded web UI, and TCP/UDP relay listeners |
| `gatewayd init` | Initialize SQLite database and CAS directory |
| `gatewayd create-world <id> <name> <mc> <loader>` | Create a new shared world |
| `gatewayd add-member <world> <uuid> <name> <dev> <role> <token>` | Register a member (`ADMIN`, `HOST_ELIGIBLE`, or `CLIENT_ONLY`) |
| `gatewayd grant <world> <name> <role>` | Update a member's role |
| `gatewayd status` | Print live worlds, active leases, and storage summary |
| `gatewayd revisions <world>` | List revision history for a world |
| `gatewayd diff <rev_a> <rev_b> [<limit>]` | Compare chunks and files between two revisions |
| `gatewayd revert <world> <revision>` | Roll a world head back to a prior revision (non-destructive) |
| `gatewayd scrub` | Verify SHA-256 integrity of all CAS blobs and hash chains |
| `gatewayd recover <world> [--apply]` | Locate newest intact revision and heal damaged head |
| `gatewayd backup <dest_dir>` | Incremental hot backup of database and CAS blobs |
| `gatewayd s3 sync \| status \| test \| restore` | Manage S3/R2 off-site replication and disaster recovery |
| `gatewayd reload [<grace_period_s>]` | Engage Virtual Limbo for zero-downtime hot reload |
| `gatewayd set-limit <user\|world> <id\|*> ...` | Configure storage, guest, and retention quotas |
| `gatewayd set-admin <name> <admin\|user>` | Grant or revoke gateway operator status |
| `gatewayd doctor` | Run diagnostic self-checks on configuration and database |

## Environment Configuration

| Variable | Default | Description |
|---|---|---|
| `MCMESH_DB` | `mcmesh.db` | Path to SQLite database file |
| `MCMESH_CAS` | `./cas` | Path to Content-Addressed Storage directory |
| `MCMESH_ADDR` | `127.0.0.1:8080` | HTTP API and Web UI bind address |
| `MCMESH_RELAY` | unset | Set to `all` to relay all worlds on shared ports |
| `MCMESH_RELAY_ADDR` | `127.0.0.1:9000` | Outbound host agent tunnel bind address |
| `MCMESH_PUBLIC_ADDR` | `0.0.0.0:25565` | Public Minecraft guest TCP bind address |
| `MCMESH_VOICE_ADDR` | `0.0.0.0:24454` | Simple Voice Chat UDP bind address |
| `MCMESH_BLOBSTREAM_ADDR` | `0.0.0.0:9100` | Dedicated binary CAS blob streaming port |
| `MCMESH_STRICT_DATA` | `0` | Refuse startup if DB or CAS directory is missing (`1`) |
| `MCMESH_TRUST_PROXY` | `0` | Extract client IP from `X-Forwarded-For` / `CF-Connecting-IP` (`1`) |
| `MCMESH_METRICS_TOKEN` | unset | Bearer token protecting `GET /metrics` (Prometheus) |
| `MCMESH_S3_BUCKET` | unset | Enables automated S3/R2/MinIO disaster replication |
| `MCMESH_S3_ENDPOINT` | `https://s3.amazonaws.com` | S3-compatible endpoint URL |
| `MCMESH_S3_REGION` | `us-east-1` | S3 bucket region (`auto` for Cloudflare R2) |
| `MCMESH_S3_ACCESS_KEY` | unset | S3 access key ID (or `AWS_ACCESS_KEY_ID`) |
| `MCMESH_S3_SECRET_KEY` | unset | S3 secret access key (or `AWS_SECRET_ACCESS_KEY`) |
| `MCMESH_S3_PREFIX` | `""` | Optional object key prefix inside bucket |
| `MCMESH_S3_SYNC_INTERVAL_S` | `300` | Background S3 sync interval in seconds |

Run `gatewayd` with no arguments to print the full list of supported environment variables.

## Testing

Run the full unit and integration test suite:

```bash
cargo check --all-targets
cargo test --release
```

All HTTP and SSE routes are documented in [`openapi.json`](https://github.com/mcmeshsolutions/docs/blob/main/openapi.json) and verified against the Axum router in integration tests.

## Ecosystem

| Repository | Description |
|---|---|
| [mcmeshsolutions/gatewayd](https://github.com/mcmeshsolutions/gatewayd) | Coordination gateway daemon, CAS store, and relay (this repo) |
| [mcmeshsolutions/mod](https://github.com/mcmeshsolutions/mod) | Minecraft NeoForge 1.21.1 client and host mod |
| [mcmeshsolutions/web](https://github.com/mcmeshsolutions/web) | WebUI panel, 3D voxel viewer, and spatial inspectors |
| [mcmeshsolutions/deploy](https://github.com/mcmeshsolutions/deploy) | Docker Compose, systemd, Caddy TLS, and homelab templates |
| [mcmeshsolutions/docs](https://github.com/mcmeshsolutions/docs) | OpenAPI 3.1.0 spec, JSON schemas, and mod API docs |

---

<div align="center">
<sub>Not affiliated with Mojang or Microsoft.</sub>
</div>
