use gatewayd::lease::{Gateway, Role};
use gatewayd::server::{router, AppState};
use rusqlite::Connection;
use gatewayd::relay::{serve_agents, serve_guests, serve_voice, Relay};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};

fn usage() -> ! {
    eprintln!(
        "usage: gatewayd serve\n       gatewayd create-world <id> <name> <mc_version> <loader>\n       \
         gatewayd add-member <world> <mc_uuid> <name> <device> <ADMIN|HOST_ELIGIBLE|CLIENT_ONLY> <token>\n         gatewayd grant <world> <name> <ADMIN|HOST_ELIGIBLE|CLIENT_ONLY>\n         gatewayd drop-token <token>\n         gatewayd revisions <world>\n         gatewayd init\n         gatewayd leaves <revision>\n         gatewayd diff <revision> <revision>\n         gatewayd recover <world> [--apply]\n         gatewayd status\n         gatewayd scrub\n         gatewayd backup <dir>\n         gatewayd set-pack <world> <pack_id>\n         gatewayd set-admin <name> <admin|user>\n         gatewayd set-limit <user|world> <id|*> <storage_bytes> <world_count> <keep_revisions> <keep_days> [<max_guests> <relay_bytes_month>]   (- = unlimited, replaces the row)\n         gatewayd set-anchor <device> <on|off>\n         gatewayd revert <world> <revision>\n\
         env: MCMESH_DB (default mcmesh.db), MCMESH_CAS (default ./cas),\n         relay (needs MCMESH_WORLD, or MCMESH_RELAY=all to serve every world; MCMESH_WORLD then only picks the UDP and ticketless default): MCMESH_RELAY_ADDR (127.0.0.1:9000), MCMESH_PUBLIC_ADDR (0.0.0.0:25565), MCMESH_VOICE_ADDR (0.0.0.0:24454)\n          MCMESH_ADDR (default 127.0.0.1:8080)\n          MCMESH_CREATE=open lets any logged-in player create worlds\n          MCMESH_ADVERTISE=host:port tells clients where guests connect (with MCMESH_WORLD)\n          MCMESH_METRICS_TOKEN=secret enables GET /metrics (Prometheus) behind that bearer token\n          MCMESH_ADMINS=uuid,uuid are gateway admins on top of `set-admin`; MCMESH_BAN_GRACE_S (120) is how long a banned host may wind down\n          MCMESH_WEBHOOKS=url,url posts gateway events as JSON; MCMESH_WEBHOOK_SECRET signs them\n          MCMESH_MIN_CLIENT=N refuses mods below client protocol level N with 426 CLIENT_TOO_OLD (current mods send level 1, older ones send nothing); MCMESH_REQUIRE_SIGNED=1 refuses commits without a valid host signature (403 SIGNATURE_REQUIRED); MCMESH_STRICT_DATA=1 makes `serve` refuse to start when the database or cas directory is missing (create them with `gatewayd init`); MCMESH_BACKUP_DIR=dir turns on a scheduled scrub plus incremental backup every MCMESH_MAINT_INTERVAL_S (86400, minimum 60), and MCMESH_AUTO_RECOVER=1 lets it move a damaged world head to the newest intact revision; MCMESH_RATE=off disables rate limits; MCMESH_RATE_SCALE=2 doubles every limit; MCMESH_RELAY_RATE_SCALE=10 loosens only the relay limits; MCMESH_PROXY_PROTOCOL=1 expects a PROXY protocol v1 or v2 header on every relay TCP connection (only when the listeners are reachable through the forwarder alone); MCMESH_TRUST_PROXY=1 reads the client address from the last X-Forwarded-For entry (only behind a proxy you control)"
    );
    std::process::exit(2)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let db = std::env::var("MCMESH_DB").unwrap_or_else(|_| "mcmesh.db".into());
    // an empty volume mounted by mistake must not silently become a fresh, empty gateway
    if std::env::var("MCMESH_STRICT_DATA").is_ok_and(|v| v == "1") && args.first().map(String::as_str) == Some("serve") {
        let cas_dir = std::env::var("MCMESH_CAS").unwrap_or_else(|_| "cas".into());
        if !std::path::Path::new(&db).is_file() || !std::path::Path::new(&cas_dir).is_dir() {
            eprintln!("MCMESH_STRICT_DATA=1: no database at {db} or no cas directory at {cas_dir}; refusing to start on an empty volume. Run `gatewayd init` once to create them on purpose.");
            std::process::exit(2);
        }
    }
    let mut gw = Gateway::open(
        Connection::open(&db).expect("open db"),
        gatewayd::cas::Cas::open(std::env::var("MCMESH_CAS").unwrap_or_else(|_| "cas".into())).expect("open cas"),
        0,
    ).expect("init db");
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["init"] => println!("database and cas ready"),
        ["create-world", id, name, mc, loader] => gw.create_world(id, name, mc, loader).expect("create world"),
        ["add-member", world, uuid, name, device, role, token] => {
            let role = match *role {
                "ADMIN" => Role::Admin,
                "HOST_ELIGIBLE" => Role::HostEligible,
                "CLIENT_ONLY" => Role::ClientOnly,
                _ => usage(),
            };
            gw.add_member(world, uuid, name, device, role).expect("add member");
            gw.add_token(device, token).expect("add token");
        }
        ["scrub"] => {
            let cas = std::env::var("MCMESH_CAS").unwrap_or_else(|_| "cas".into());
            let r = gw.scrub(std::path::Path::new(&cas)).expect("scrub");
            println!("blobs {} revisions {} corrupt {} broken revisions {} missing blobs {} chain breaks {} unknown signers {}", r.blobs, r.revisions, r.corrupt.len(), r.broken_revisions.len(), r.missing.len(), r.chain_breaks.len(), r.unknown_signers.len());
            for l in r.corrupt.iter().chain(&r.broken_revisions).chain(&r.missing).chain(&r.chain_breaks).chain(&r.unknown_signers) {
                println!("  {l}");
            }
            if !r.ok() {
                std::process::exit(1);
            }
        }
        ["backup", dest] => {
            let cas = std::env::var("MCMESH_CAS").unwrap_or_else(|_| "cas".into());
            let (copied, skipped) = gw.backup(std::path::Path::new(&cas), std::path::Path::new(dest)).expect("backup");
            println!("backup ok: {copied} blobs copied, {skipped} already present");
        }
        ["set-pack", world, pack] => gw.set_pack(world, pack).expect("set pack"),
        ["set-admin", name, role] => {
            gw.ops_init().expect("init ops tables");
            let Some((uuid, _)) = gw.player_by_name(name).expect("lookup") else {
                eprintln!("no player named {name}; they must log in once first");
                std::process::exit(1);
            };
            gw.set_gateway_admin(&uuid, match *role { "admin" => true, "user" => false, _ => usage() }, "cli").expect("set admin");
        }
        ["set-limit", scope, id, storage, worlds, keep_revs, keep_days, extra @ ..] => {
            let scope = match *scope { "user" => gatewayd::quota::Scope::User, "world" => gatewayd::quota::Scope::World, _ => usage() };
            let n = |v: &str| if v == "-" { None } else { Some(v.parse::<u64>().unwrap_or_else(|_| usage())) };
            let (guests, relay) = match extra { [] => ("-", "-"), [g, r] => (*g, *r), _ => usage() };
            let l = gatewayd::quota::Limits { storage_bytes: n(storage), world_count: n(worlds), keep_revisions: n(keep_revs), keep_days: n(keep_days), max_guests: n(guests), relay_bytes_month: n(relay) };
            gw.set_limits(scope, id, &l).expect("set limits");
        }
        ["set-anchor", device, state] => gw.set_anchor(device, match *state { "on" => true, "off" => false, _ => usage() }).expect("set anchor"),
        ["revisions", world] => {
            for r in gw.revisions(world, 50).expect("revisions") {
                println!("{r}");
            }
        }
        ["status"] => {
            gw.ops_init().expect("init ops tables");
            for l in gw.status().expect("status").into_iter().chain(gw.ops_status().expect("status")) {
                println!("{l}");
            }
        }
        ["revert", world, rev] => {
            let admin: String = gw.first_admin_device(world).expect("no admin");
            match gw.revert(&admin, world, rev).expect("revert") {
                Ok(id) => println!("{id}"),
                Err(c) => {
                    eprintln!("{c}");
                    std::process::exit(1);
                }
            }
        }
        ["diff", a, b] => {
            for l in gw.diff_report(a, b, 20).expect("diff") {
                println!("{l}");
            }
        }
        ["leaves", rev] => {
            use gatewayd::manifest::{self, Item};
            let root = gw.revision_root(rev).expect("revision");
            let mut chunks: std::collections::BTreeMap<(String, String), u64> = Default::default();
            let (mut aux, mut aux_bytes) = (0u64, 0u64);
            manifest::for_each_leaf(gw.cas(), root, &mut |item, hash| {
                match item {
                    Item::Chunk(k) => *chunks.entry((k.dim, format!("{:?}", k.kind))).or_default() += 1,
                    Item::Aux(_) => {
                        aux += 1;
                        aux_bytes += gw.cas().stored_len(&hash).unwrap_or(0);
                    }
                }
                Ok(())
            })
            .expect("walk");
            println!("{rev}: {} chunk entries, {aux} extra files ({aux_bytes} stored bytes)", chunks.values().sum::<u64>());
            for ((dim, kind), n) in chunks {
                println!("  {dim} {kind}: {n}");
            }
        }
        ["recover", world, rest @ ..] => {
            let apply = match rest { [] => false, ["--apply"] => true, _ => usage() };
            let r = gw.recover_head(world, apply).expect("recover");
            if r.head_ok {
                println!("{world}: head {} is intact, nothing to do", r.head);
            } else {
                println!("{world}: head {} is damaged ({} damaged revisions checked)", r.head, r.damaged.len());
                match (&r.good, &r.applied, r.blocked) {
                    (None, ..) => { eprintln!("no intact revision within the last 20; restore from a backup"); std::process::exit(1); }
                    (Some(g), Some(new), _) => println!("head moved to a new ROLLBACK revision {new} with the content of {g}"),
                    (Some(g), None, Some(why)) => { eprintln!("newest intact revision is {g}, not applied: {why}"); std::process::exit(1); }
                    (Some(g), None, None) => println!("newest intact revision is {g}; run again with --apply to make it the head"),
                }
            }
        }
        ["drop-token", token] => {
            if !gw.drop_token(token).expect("drop token") {
                eprintln!("no such token");
                std::process::exit(1);
            }
        }
        ["grant", world, name, role] => {
            let role = match *role {
                "ADMIN" => Role::Admin,
                "HOST_ELIGIBLE" => Role::HostEligible,
                "CLIENT_ONLY" => Role::ClientOnly,
                _ => usage(),
            };
            if !gw.grant_role(world, name, role).expect("grant") {
                eprintln!("no player named {name}; they must log in once first");
                std::process::exit(1);
            }
        }
        ["serve"] => {
            let addr = std::env::var("MCMESH_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
            let modes = std::env::var("MCMESH_AUTH").unwrap_or_else(|_| "mojang,key".into());
            let auth = gatewayd::auth::AuthCfg {
                session_url: std::env::var("MCMESH_SESSION_URL").unwrap_or_else(|_| "https://sessionserver.mojang.com".into()),
                mojang: modes.split(',').any(|m| m.trim() == "mojang"),
                key: modes.split(',').any(|m| m.trim() == "key"),
                require_ticket: std::env::var("MCMESH_GUESTS").map_or(true, |v| v != "open"),
                allow_create: std::env::var("MCMESH_CREATE").is_ok_and(|v| v == "open"),
                advertise: std::env::var("MCMESH_ADVERTISE").unwrap_or_default(),
                metrics_token: std::env::var("MCMESH_METRICS_TOKEN").ok().filter(|t| !t.is_empty()),
                webhooks: std::env::var("MCMESH_WEBHOOKS").unwrap_or_default().split(',').map(str::trim).filter(|u| !u.is_empty()).map(String::from).collect(),
                webhook_secret: std::env::var("MCMESH_WEBHOOK_SECRET").ok().filter(|t| !t.is_empty()),
                admins: std::env::var("MCMESH_ADMINS").unwrap_or_default().split(',').map(str::trim).filter(|u| !u.is_empty()).map(String::from).collect(),
                ban_grace_s: std::env::var("MCMESH_BAN_GRACE_S").ok().and_then(|v| v.parse().ok()).unwrap_or(120),
                require_signed: std::env::var("MCMESH_REQUIRE_SIGNED").is_ok_and(|v| v == "1"),
                min_client: std::env::var("MCMESH_MIN_CLIENT").ok().and_then(|v| v.parse().ok()).unwrap_or(0),
            };
            let state = AppState::with_auth(gw, auth);
            let default_world = std::env::var("MCMESH_WORLD").ok();
            if default_world.is_some() || std::env::var("MCMESH_RELAY").is_ok_and(|v| v == "all") {
                let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.into());
                let udp = Arc::new(UdpSocket::bind(env("MCMESH_VOICE_ADDR", "0.0.0.0:24454")).await.expect("bind voice"));
                let relay = Relay::new(state.clone(), default_world.as_deref(), Some(udp.clone()));
                let agents = TcpListener::bind(env("MCMESH_RELAY_ADDR", "127.0.0.1:9000")).await.expect("bind relay");
                let guests = TcpListener::bind(env("MCMESH_PUBLIC_ADDR", "0.0.0.0:25565")).await.expect("bind public");
                tokio::spawn(serve_agents(relay.clone(), agents));
                tokio::spawn(serve_guests(relay.clone(), guests));
                // MCMESH_CHANNELS="udp:24455,tcp:25580": public ports of extra channels, numbered in order from 1.
                // The mod's `channels` config must list the same protocols in the same order.
                for (i, spec) in std::env::var("MCMESH_CHANNELS").unwrap_or_default().split(',').filter(|s| !s.trim().is_empty()).enumerate() {
                    let (proto, port) = spec.trim().split_once(':').expect("MCMESH_CHANNELS entries look like udp:24455");
                    let bind = format!("0.0.0.0:{port}");
                    let chan = (i + 1) as u8;
                    match proto {
                        "udp" => { tokio::spawn(gatewayd::relay::serve_channel_udp(relay.clone(), chan, Arc::new(UdpSocket::bind(&bind).await.expect("bind channel")))); }
                        "tcp" => { tokio::spawn(gatewayd::relay::serve_channel_tcp(relay.clone(), chan, TcpListener::bind(&bind).await.expect("bind channel"))); }
                        _ => panic!("unknown channel protocol {proto}"),
                    }
                }
                tokio::spawn(serve_voice(relay, udp));
            }
            let t = state.clone();
            tokio::spawn(async move {
                let mut iv = tokio::time::interval(Duration::from_secs(1));
                loop {
                    iv.tick().await;
                    t.tick();
                }
            });
            if let Ok(backup_dir) = std::env::var("MCMESH_BACKUP_DIR") {
                let secs = std::env::var("MCMESH_MAINT_INTERVAL_S").ok().and_then(|v| v.parse::<u64>().ok()).filter(|n| *n >= 60).unwrap_or(86_400);
                let cas_dir = std::env::var("MCMESH_CAS").unwrap_or_else(|_| "cas".into());
                eprintln!("scheduled scrub and backup to {backup_dir} every {secs} s");
                tokio::spawn(gatewayd::schedule::serve(db.clone(), cas_dir, backup_dir, std::env::var("MCMESH_AUTO_RECOVER").is_ok_and(|v| v == "1"), Duration::from_secs(600), Duration::from_secs(secs)));
            }
            let l = tokio::net::TcpListener::bind(&addr).await.expect("bind");
            eprintln!("gatewayd listening on {addr}");
            axum::serve(l, router(state).into_make_service_with_connect_info::<std::net::SocketAddr>())
                .with_graceful_shutdown(async { let _ = tokio::signal::ctrl_c().await; })
                .await
                .expect("serve");
        }
        _ => usage(),
    }
}
