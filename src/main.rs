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
         gatewayd add-member <world> <mc_uuid> <name> <device> <ADMIN|HOST_ELIGIBLE|CLIENT_ONLY> <token>\n         gatewayd grant <world> <name> <ADMIN|HOST_ELIGIBLE|CLIENT_ONLY>\n         gatewayd drop-token <token>\n         gatewayd revisions <world>\n         gatewayd status\n         gatewayd revert <world> <revision>\n\
         env: MCMESH_DB (default mcmesh.db), MCMESH_CAS (default ./cas),\n         relay (needs MCMESH_WORLD, or MCMESH_RELAY=all to serve every world; MCMESH_WORLD then only picks the UDP and ticketless default): MCMESH_RELAY_ADDR (127.0.0.1:9000), MCMESH_PUBLIC_ADDR (0.0.0.0:25565), MCMESH_VOICE_ADDR (0.0.0.0:24454)\n          MCMESH_ADDR (default 127.0.0.1:8080)\n          MCMESH_CREATE=open lets any logged-in player create worlds\n          MCMESH_ADVERTISE=host:port tells clients where guests connect (with MCMESH_WORLD)"
    );
    std::process::exit(2)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let db = std::env::var("MCMESH_DB").unwrap_or_else(|_| "mcmesh.db".into());
    let mut gw = Gateway::open(
        Connection::open(&db).expect("open db"),
        gatewayd::cas::Cas::open(std::env::var("MCMESH_CAS").unwrap_or_else(|_| "cas".into())).expect("open cas"),
        0,
    ).expect("init db");
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
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
        ["revisions", world] => {
            for r in gw.revisions(world, 50).expect("revisions") {
                println!("{r}");
            }
        }
        ["status"] => {
            for l in gw.status().expect("status") {
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
            let l = tokio::net::TcpListener::bind(&addr).await.expect("bind");
            eprintln!("gatewayd listening on {addr}");
            axum::serve(l, router(state))
                .with_graceful_shutdown(async { let _ = tokio::signal::ctrl_c().await; })
                .await
                .expect("serve");
        }
        _ => usage(),
    }
}
