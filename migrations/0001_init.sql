CREATE TABLE IF NOT EXISTS configs (
  id TEXT PRIMARY KEY,
  config_text TEXT NOT NULL,
  private_key TEXT NOT NULL,
  public_key TEXT NOT NULL,
  ipv4 TEXT DEFAULT '',
  ipv6 TEXT DEFAULT '',
  warp_account_id TEXT DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_configs_created_at ON configs(created_at);
