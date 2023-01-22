-- migrate:up
CREATE TABLE clients (
  id UUID PRIMARY KEY,

  name TEXT NOT NULL,
  homepage_url TEXT,
  logo BYTEA NOT NULL,
  logo_uri TEXT NOT NULL,

  secret TEXT NOT NULL UNIQUE,
  redirect_uris TEXT[] NOT NULL,
  grant_types TEXT[] NOT NULL,

  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX clients_secret ON clients (secret);

CREATE TABLE oauth_token_requests (
  code TEXT PRIMARY KEY,
  redirect_uri TEXT NOT NULL,

  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,

  user_id UUID REFERENCES users (id) ON UPDATE CASCADE ON DELETE CASCADE,
  client_id UUID REFERENCES clients (id) ON UPDATE CASCADE ON DELETE CASCADE,

  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE oauth_tokens (
  access_key TEXT PRIMARY KEY,
  access_key_expires_at TIMESTAMPTZ NOT NULL,

  refresh_key TEXT UNIQUE,
  refresh_key_expires_at TIMESTAMPTZ,

  user_id UUID REFERENCES users (id) ON UPDATE CASCADE ON DELETE CASCADE,
  client_id UUID REFERENCES clients (id) ON UPDATE CASCADE ON DELETE CASCADE,

  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX tokens_refresh_key ON oauth_tokens (refresh_key);

-- migrate:down
DROP INDEX IF EXISTS tokens_refresh_key;
DROP TABLE IF EXISTS oauth_token_requests;
DROP TABLE IF EXISTS oauth_tokens;
DROP INDEX IF EXISTS clients_secret;
DROP TABLE IF EXISTS clients;
