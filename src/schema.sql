CREATE TABLE IF NOT EXISTS players(
  uuid TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS devices(
  id TEXT PRIMARY KEY, player_uuid TEXT NOT NULL REFERENCES players(uuid),
  pubkey BLOB UNIQUE, label TEXT, tailnet_ip TEXT, tier INTEGER, hw_json TEXT,
  last_seen INTEGER, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS worlds(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, mc_version TEXT NOT NULL, loader TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'IDLE' CHECK(state IN('IDLE','LOCKED','MIGRATING')),
  phase TEXT,
  epoch INTEGER NOT NULL DEFAULT 0, head_ref TEXT NOT NULL DEFAULT 'main',
  created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS members(
  world_id TEXT NOT NULL REFERENCES worlds(id), player_uuid TEXT NOT NULL REFERENCES players(uuid),
  role TEXT NOT NULL CHECK(role IN('ADMIN','HOST_ELIGIBLE','CLIENT_ONLY')),
  PRIMARY KEY(world_id, player_uuid));
CREATE TABLE IF NOT EXISTS revisions(
  id TEXT PRIMARY KEY, world_id TEXT NOT NULL, parent_id TEXT, root_hash BLOB NOT NULL,
  seq INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN('AUTOSAVE','MIGRATE','SHUTDOWN','RECOVERED','MANUAL','ROLLBACK','IMPORT')),
  lease_id TEXT, created_at INTEGER NOT NULL, pinned INTEGER NOT NULL DEFAULT 0,
  UNIQUE(world_id, seq));
CREATE TABLE IF NOT EXISTS refs(
  world_id TEXT NOT NULL, name TEXT NOT NULL, rev_id TEXT NOT NULL REFERENCES revisions(id),
  PRIMARY KEY(world_id, name));
CREATE TABLE IF NOT EXISTS leases(
  id TEXT PRIMARY KEY, world_id TEXT NOT NULL REFERENCES worlds(id),
  device_id TEXT NOT NULL REFERENCES devices(id), epoch INTEGER NOT NULL, ref_name TEXT NOT NULL,
  base_rev TEXT NOT NULL, tier INTEGER NOT NULL, hmac_key BLOB NOT NULL,
  status TEXT NOT NULL CHECK(status IN('ACTIVE','HANDOFF','RELEASED','EXPIRED','FENCED')),
  granted_at INTEGER NOT NULL, end_reason TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS one_live_lease ON leases(world_id) WHERE status IN('ACTIVE','HANDOFF');
CREATE TABLE IF NOT EXISTS sessions(
  token_hash BLOB PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id));
CREATE TABLE IF NOT EXISTS chunk_wal(
  lease_id TEXT NOT NULL, seq INTEGER NOT NULL, op TEXT NOT NULL, dim TEXT NOT NULL,
  cx INTEGER NOT NULL, cz INTEGER NOT NULL, hash BLOB NOT NULL,
  PRIMARY KEY(lease_id, seq)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS wal_chain(
  lease_id TEXT PRIMARY KEY, next_seq INTEGER NOT NULL, prev_mac BLOB NOT NULL) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS identities(
  player_uuid TEXT PRIMARY KEY REFERENCES players(uuid), kind TEXT NOT NULL CHECK(kind IN('MOJANG','KEY')),
  pubkey BLOB);
CREATE UNIQUE INDEX IF NOT EXISTS players_name_ci ON players(name COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS blob_world(
  hash BLOB NOT NULL, world_id TEXT NOT NULL REFERENCES worlds(id), PRIMARY KEY(hash, world_id));
CREATE TABLE IF NOT EXISTS invites(
  code TEXT PRIMARY KEY, world_id TEXT NOT NULL REFERENCES worlds(id), role TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS mod_requests(
  world_id TEXT NOT NULL REFERENCES worlds(id), mod_id TEXT NOT NULL, hash TEXT NOT NULL,
  player_uuid TEXT NOT NULL REFERENCES players(uuid), created_at INTEGER NOT NULL,
  PRIMARY KEY(world_id, mod_id, hash, player_uuid));
CREATE TABLE IF NOT EXISTS quotas(
  scope TEXT NOT NULL CHECK(scope IN('user','world')), id TEXT NOT NULL,
  storage_bytes INTEGER, world_count INTEGER, keep_revisions INTEGER, keep_days INTEGER,
  PRIMARY KEY(scope, id)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS blob_world_by_world ON blob_world(world_id);

CREATE TABLE IF NOT EXISTS shard_leases(
  id TEXT PRIMARY KEY, world_id TEXT NOT NULL REFERENCES worlds(id), device_id TEXT NOT NULL REFERENCES devices(id),
  epoch INTEGER NOT NULL, hmac_key BLOB NOT NULL, regions TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN('ACTIVE','ENDED')), granted_at INTEGER NOT NULL, last_hb INTEGER NOT NULL, end_reason TEXT,
  merged INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS shard_standby(
  world_id TEXT NOT NULL, device_id TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(world_id, device_id)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS shard_offers(
  id INTEGER PRIMARY KEY AUTOINCREMENT, world_id TEXT NOT NULL REFERENCES worlds(id), regions TEXT NOT NULL, created_at INTEGER NOT NULL,
  players TEXT NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS shard_homes(
  world_id TEXT NOT NULL, uuid TEXT NOT NULL, lease_id TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(world_id, uuid)) WITHOUT ROWID;
