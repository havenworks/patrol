-- migrate:up
CREATE TABLE users (
  id UUID PRIMARY KEY,

  username TEXT NOT NULL UNIQUE,

  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,

  profile_picture TEXT,

  password_hash TEXT NOT NULL,
  password_hash_previous TEXT,
  password_changed_at TIMESTAMPTZ NOT NULL,

  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX users_username ON users (username);

CREATE TABLE roles (
  name TEXT PRIMARY KEY
);

INSERT INTO roles (name) VALUES ('admin');

CREATE TABLE users_roles (
  user_id UUID REFERENCES users (id) ON UPDATE CASCADE ON DELETE CASCADE,

  role_name TEXT REFERENCES roles (name) ON UPDATE CASCADE ON DELETE CASCADE,

  CONSTRAINT users_roles_pkey PRIMARY KEY (user_id, role_name)
);

-- migrate:down
DROP TABLE IF EXISTS users;
DROP INDEX IF EXISTS users_username;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users_roles;
